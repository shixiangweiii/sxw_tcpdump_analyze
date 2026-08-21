import { describe, expect, it } from 'vitest';
import { analyze } from './analyzer.js';
import { scenarios } from '../testing/scenarios.js';
import type { Connection, HttpTransaction } from '../types.js';

function only(connections: Connection[]): Connection {
  expect(connections).toHaveLength(1);
  return connections[0]!;
}

function firstTransaction(connection: Connection): HttpTransaction {
  expect(connection.http).not.toBeNull();
  const transaction = connection.http!.transactions[0];
  expect(transaction).toBeDefined();
  return transaction!;
}

describe('协议识别', () => {
  it('明文 HTTP 被认出来，请求与响应都解出', () => {
    const connection = only(analyze(scenarios.httpSimpleTransaction()).connections);

    expect(connection.appProtocol).toBe('http1');
    const { request, response } = firstTransaction(connection);

    expect(request?.method).toBe('GET');
    expect(request?.target).toBe('/api/order');
    expect(request?.httpVersion).toBe('HTTP/1.1');
    expect(response?.statusCode).toBe(200);
    expect(response?.reasonPhrase).toBe('OK');
    expect(response?.body?.text).toBe('{"ok":true}');
  });

  it('TLS 不能被误判成 HTTP', () => {
    // 加密流量的载荷同样会被嗅探到，必须一眼否掉，否则会拿密文当报文解
    const result = analyze(scenarios.dnsAndSni());
    const tls = result.connections.find((connection) => connection.serverPort === 443);

    expect(tls?.appProtocol).toBe('tls');
    expect(tls?.http).toBeNull();
    expect(tls?.httpSummary).toBeNull();
  });

  it('抓包从正文中间开始时不硬认成 HTTP', () => {
    const connection = only(analyze(scenarios.httpMidStreamCapture()).connections);

    expect(connection.appProtocol).toBe('unknown');
    expect(connection.http).toBeNull();
  });

  it('没有应用层数据的连接不产生 HTTP 结论', () => {
    const connection = only(analyze(scenarios.synNoResponse()).connections);

    expect(connection.appProtocol).toBe('unknown');
    expect(connection.http).toBeNull();
  });
});

describe('流重组', () => {
  it('响应乱序到达时仍能还原出完整正文', () => {
    // 抓包顺序是「第 4 段 → 第 2 段 → 第 1 段 → 第 3 段」，响应头在第 3 个到达的包里。
    // 按抓包顺序拼接得到的是乱码，这条用例守的就是「必须按序号排序」。
    const connection = only(analyze(scenarios.httpOutOfOrderResponse()).connections);
    const { response } = firstTransaction(connection);

    expect(response?.statusCode).toBe(200);
    expect(response?.complete).toBe(true);
    expect(response?.body?.byteCount).toBe(3_000);
    expect(response?.body?.text).toBe('X'.repeat(3_000));
    expect(connection.http?.quality.serverStreamComplete).toBe(true);
  });

  it('承载响应头的包按流序认定，不是抓包序里的第一个', () => {
    const connection = only(analyze(scenarios.httpOutOfOrderResponse()).connections);
    const { response } = firstTransaction(connection);

    const serverPackets = connection.packets.filter(
      (packet) => packet.direction === 's2c' && packet.payloadLength > 0,
    );
    // 抓包顺序里服务端第一个数据包承载的是流的末段，不是响应头
    expect(response?.firstPacketIndex).not.toBe(serverPackets[0]!.packetIndex);

    const headerPacket = connection.packets.find(
      (packet) => packet.packetIndex === response?.firstPacketIndex,
    );
    expect(headerPacket?.appSpan?.part).toBe('mixed');
    expect(headerPacket?.appNote).toContain('响应头在这个包里');
  });

  it('重传的响应头被丢弃，不会被拼进正文', () => {
    const connection = only(analyze(scenarios.httpRetransmittedHeader()).connections);
    const { response } = firstTransaction(connection);

    expect(connection.http?.quality.duplicateSegmentsDropped).toBe(1);
    expect(response?.body?.byteCount).toBe(2_000);
    expect(response?.body?.text).toBe('Y'.repeat(2_000));
    // 正文里绝不能出现第二份响应头
    expect(response?.body?.text).not.toContain('HTTP/1.1');
  });

  it('重传包被标出来，且注明它不参与拼接', () => {
    const connection = only(analyze(scenarios.httpRetransmittedHeader()).connections);
    const duplicate = connection.packets.find((packet) => packet.appSpan?.duplicate);

    expect(duplicate).toBeDefined();
    expect(duplicate?.appNote).toContain('不参与响应拼接');
  });

  it('流里有洞时不谎报正文完整', () => {
    const connection = only(analyze(scenarios.httpGapInStream()).connections);
    const { response } = firstTransaction(connection);

    expect(connection.http?.quality.serverStreamComplete).toBe(false);
    expect(connection.http?.quality.gaps).toHaveLength(1);
    expect(response?.complete).toBe(false);
    expect(response?.incompleteReason).toContain('没抓到');
  });
});

describe('正文', () => {
  it('chunked 被解块，长度行不会混进正文', () => {
    const connection = only(analyze(scenarios.httpChunkedResponse()).connections);
    const { response } = firstTransaction(connection);

    expect(response?.body?.framing).toBe('chunked');
    expect(response?.body?.text).toBe('<!DOCTYPE html><p>第一块内容</p><p>第二块内容</p>');
    expect(response?.complete).toBe(true);
  });

  it('Content-Type 不带 charset 时从 HTML 的 meta 里认字符集', () => {
    // 真实抓包就是这样：响应头只有 text/html，charset 只写在 <meta> 里
    const connection = only(analyze(scenarios.httpNoCharsetHeader()).connections);
    const { response } = firstTransaction(connection);

    expect(response?.headers.find((header) => header.name === 'Content-Type')?.value).toBe('text/html');
    expect(response?.body?.charset).toBe('utf-8');
    expect(response?.body?.text).toContain('中国孩子网');
    expect(response?.body?.text).toContain('正文内容');
  });
});

describe('事务与耗时', () => {
  it('耗时分解把网络往返和服务端处理拆开', () => {
    const connection = only(analyze(scenarios.httpSimpleTransaction()).connections);
    const { timing, note } = firstTransaction(connection);

    expect(timing.ttfbMicros).toBe(30_000);
    expect(timing.requestAckedMicros).not.toBeNull();
    expect(timing.totalMicros).toBe(30_000);
    expect(note).toContain('GET /api/order → 200 OK');
  });

  it('请求发出但没有响应时说清楚，而不是留空', () => {
    const connection = only(analyze(scenarios.httpRequestNoResponse()).connections);
    const transaction = firstTransaction(connection);

    expect(transaction.request?.method).toBe('GET');
    expect(transaction.response).toBeNull();
    expect(transaction.note).toContain('没有看到任何响应');
    expect(connection.outcome).toBe('established-reset');
  });

  it('连接列表用的摘要不带头部与正文', () => {
    const connection = only(analyze(scenarios.httpSimpleTransaction()).connections);

    expect(connection.httpSummary).toEqual({
      transactionCount: 1,
      firstLine: 'GET /api/order',
      statusCode: 200,
    });
  });
});

describe('包锚点', () => {
  it('每个承载正文的包都能定位到正文的字符区间', () => {
    const connection = only(analyze(scenarios.httpOutOfOrderResponse()).connections);
    const bodyPackets = connection.packets.filter((packet) => packet.appSpan?.part === 'body');

    expect(bodyPackets.length).toBeGreaterThan(0);
    for (const packet of bodyPackets) {
      expect(packet.appSpan?.textFrom).not.toBeNull();
      expect(packet.appSpan!.textTo!).toBeGreaterThan(packet.appSpan!.textFrom!);
      expect(packet.appNote).toMatch(/响应正文第 \d+~\d+ 个字符/);
    }
  });

  it('区间按流序首尾相接，覆盖整个正文', () => {
    const connection = only(analyze(scenarios.httpOutOfOrderResponse()).connections);
    const { response } = firstTransaction(connection);

    const spans = connection.packets
      .filter((packet) => packet.appSpan && !packet.appSpan.duplicate && packet.direction === 's2c')
      .map((packet) => packet.appSpan!)
      .sort((a, b) => a.streamFrom - b.streamFrom);

    for (let i = 1; i < spans.length; i += 1) {
      expect(spans[i]!.streamFrom).toBe(spans[i - 1]!.streamTo);
    }
    expect(spans[spans.length - 1]!.streamTo).toBe(response!.streamEnd);
  });

  it('握手与纯 ACK 包上不挂应用层注解', () => {
    const connection = only(analyze(scenarios.httpSimpleTransaction()).connections);
    const syn = connection.packets[0]!;

    expect(syn.flags).toContain('SYN');
    expect(syn.appSpan).toBeNull();
    expect(syn.appNote).toBeNull();
  });
});
