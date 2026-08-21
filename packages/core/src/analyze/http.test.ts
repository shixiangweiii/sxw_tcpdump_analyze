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

  it('Redis 内联命令不会被编造成 HTTP 报文', () => {
    // `GET mykey\r\n` 命中「大写方法 + 空格」，但起始行没有 HTTP 版本 token。
    // 这条守的是「宁可不给结论，也不能编造结论」
    const connection = only(analyze(scenarios.redisInlineCommand()).connections);

    expect(connection.appProtocol).toBe('unknown');
    expect(connection.http).toBeNull();
    expect(connection.httpSummary).toBeNull();
    for (const packet of connection.packets) {
      expect(packet.appSpan).toBeNull();
      expect(packet.appNote).toBeNull();
    }
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

  it('抓包从中途开始时不报「流完整」，即使中间一个洞都没有', () => {
    // 「中间没洞」不等于「完整」——开头缺失同样是不完整，两者要分开表达
    const connection = only(analyze(scenarios.httpMidStreamRequest()).connections);

    expect(connection.quality.handshakeCaptured).toBe(false);
    expect(connection.http?.quality.gaps).toEqual([]);
    expect(connection.http?.quality.clientStartsAtBeginning).toBe(false);
    expect(connection.http?.quality.serverStartsAtBeginning).toBe(false);
    expect(connection.http?.quality.clientStreamComplete).toBe(false);
    expect(connection.http?.quality.serverStreamComplete).toBe(false);
  });

  it('握手抓全时，即使某个方向一个字节都没传也算起点完整', () => {
    const connection = only(analyze(scenarios.httpRequestNoResponse()).connections);

    // 服务端一个字节都没回，但我们确实是从连接起点开始看的，不该报成「开头缺失」
    expect(connection.http?.quality.serverStartsAtBeginning).toBe(true);
    expect(connection.http?.quality.clientStreamComplete).toBe(true);
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

  it('字符集声明无效时，charset 报的是实际用的那个', () => {
    // 退回 UTF-8 之后还挂着无效声明的话，界面会告诉用户「这段是 xxx 解出来的」，那是假的。
    // 声明值本身在 Content-Type 头里仍然看得到，信息不丢
    const connection = only(analyze(scenarios.httpUnknownCharset()).connections);
    const { response } = firstTransaction(connection);

    expect(response?.headers.find((h) => h.name === 'Content-Type')?.value).toContain(
      'x-not-a-real-charset',
    );
    expect(response?.body?.charset).toBe('utf-8');
    expect(response?.body?.text).toBe('中文内容');
  });
});

describe('事务与耗时', () => {
  it('服务端单独回 ACK 时，网络往返和服务端处理能拆开', () => {
    const connection = only(analyze(scenarios.httpSeparateAck()).connections);
    const { timing, note } = firstTransaction(connection);

    expect(timing.requestAckedMicros).toBe(10_000);
    expect(timing.ttfbMicros).toBe(30_000);
    expect(timing.serverThinkMicros).toBe(20_000);
    expect(note).toContain('服务端处理 20.00ms');
  });

  it('ACK 被捎在响应首包上时，如实说明处理时间测不出来', () => {
    // 内网快链路 + 延迟 ACK 下这是常态：确认与响应同包，两个时间点重合。
    // 既不能报「服务端处理 0μs」（把测不出来说成不耗时），也不能干脆不提耗时
    const connection = only(analyze(scenarios.httpSimpleTransaction()).connections);
    const { timing, note } = firstTransaction(connection);

    expect(timing.requestAckedMicros).toBe(timing.ttfbMicros);
    expect(timing.serverThinkMicros).toBeNull();
    expect(note).toContain('等首字节 30.00ms（含网络往返）');
    expect(note).not.toContain('服务端处理');
  });

  it('乱序时传输耗时不会算成负数', () => {
    // 流序最末的那段可能最先到达，拿它当「收齐时间」会得到负的传输耗时
    const connection = only(analyze(scenarios.httpOutOfOrderResponse()).connections);
    const { timing } = firstTransaction(connection);

    expect(timing.responseTransferMicros).toBeGreaterThanOrEqual(0);
    expect(timing.totalMicros).toBeGreaterThanOrEqual(timing.ttfbMicros!);
  });

  it('100 Continue 不占用事务位，真正的响应不会错位', () => {
    const connection = only(analyze(scenarios.httpExpectContinue()).connections);

    expect(connection.http?.transactions).toHaveLength(1);
    const transaction = firstTransaction(connection);

    expect(transaction.request?.method).toBe('POST');
    expect(transaction.response?.statusCode).toBe(200);
    expect(transaction.informationalResponses.map((m) => m.statusCode)).toEqual([100]);
    expect(transaction.note).toContain('POST /upload → 200 OK');
    // 摘要必须给正式响应的状态码，而不是 100
    expect(connection.httpSummary?.statusCode).toBe(200);
  });

  it('承载 100 Continue 的包归到同一个事务上', () => {
    const connection = only(analyze(scenarios.httpExpectContinue()).connections);
    const spans = connection.packets.filter((packet) => packet.appSpan).map((p) => p.appSpan!);

    expect(spans.length).toBeGreaterThan(0);
    for (const span of spans) {
      expect(span.transactionIndex).toBe(1);
    }
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
      responded: true,
      statusCode: 200,
    });
  });

  it('摘要区分「没有响应」与「响应解不出来」', () => {
    const connection = only(analyze(scenarios.httpRequestNoResponse()).connections);

    expect(connection.httpSummary?.responded).toBe(false);
    expect(connection.httpSummary?.statusCode).toBeNull();
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

  it('注解里的字符区间是 1 基闭区间，不是内部的 0 基偏移', () => {
    // 内部偏移是 [from, to) 半开 0 基，对外必须写成 from+1 ~ to，
    // 否则「第 0 个字符」既不是人话，读起来还整体差一位
    const connection = only(analyze(scenarios.httpOutOfOrderResponse()).connections);
    const bodyPackets = connection.packets.filter((packet) => packet.appSpan?.part === 'body');

    expect(bodyPackets.length).toBeGreaterThan(0);
    for (const packet of bodyPackets) {
      const { textFrom, textTo } = packet.appSpan!;
      expect(packet.appNote).toBe(`响应正文第 ${textFrom! + 1}~${textTo} 个字符`);
    }
    expect(bodyPackets.some((packet) => packet.appNote?.includes('第 0~'))).toBe(false);
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
