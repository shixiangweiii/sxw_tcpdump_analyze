import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { analyze } from './analyzer.js';
import type { Connection } from '../types.js';

/**
 * 真实抓包回归测试：明文 HTTP。
 *
 * 来自一次真实的 `sudo tcpdump -i any host www.chinakids.net -w packet.pcap`（macOS，en0），
 * 两次 `curl http://www.chinakids.net`。它一次性覆盖了合成夹具单独造才能凑齐的组合，
 * 而且每一条都是现实里真会发生的：
 *
 *  - **服务端方向严重乱序**：到达顺序是流偏移 4194 → 1398 → 0 → 2796，
 *    HTTP 响应头在第 3 个到达的数据包里。按抓包顺序拼接得到的是乱码
 *  - **响应头整包重传**：#28 重发了 #14 的那 1398 字节
 *  - **Transfer-Encoding: chunked**，不解块正文里会混进十六进制长度行
 *  - **Content-Type: text/html 不带 charset**，字符集只写在 HTML 的 <meta> 里
 *  - 抓包开始前就存在的两条连接（:50264 / :50265）只剩挥手尾巴，没有任何应用层数据
 *
 * 下面的数字全部来自对该文件的逐字节核对。
 */
const FIXTURE = fileURLToPath(
  new URL('../../testdata/macos-tcpdump-http-chinakids.pcap', import.meta.url),
);

const result = analyze(new Uint8Array(readFileSync(FIXTURE)));

function connectionOn(port: number): Connection {
  const connection = result.connections.find((item) => item.clientPort === port);
  expect(connection).toBeDefined();
  return connection!;
}

describe('真实抓包：明文 HTTP（www.chinakids.net）', () => {
  it('容器与链路层都被正确读出', () => {
    expect(result.capture.format).toBe('pcapng');
    expect(result.capture.linkTypes).toEqual([1]);
    expect(result.capture.interfaceNames).toEqual(['en0']);
    expect(result.capture.truncated).toBe(false);
  });

  it('63 个包全部解码成功，没有产生解码告警', () => {
    expect(result.capture.packetCount).toBe(63);
    expect(result.capture.decodedPackets).toBe(63);
    expect(result.capture.warnings).toEqual([]);
  });

  it('四条连接：两次 curl，外加抓包前就存在的两条尾巴', () => {
    expect(result.connections.map((connection) => connection.clientPort)).toEqual([
      50_264, 50_265, 50_398, 50_399,
    ]);
  });

  it('只剩挥手尾巴的连接不产生 HTTP 结论', () => {
    for (const port of [50_264, 50_265]) {
      const connection = connectionOn(port);
      expect(connection.outcome).toBe('handshake-missing');
      expect(connection.stats.byteCount).toBe(0);
      expect(connection.appProtocol).toBe('unknown');
      expect(connection.http).toBeNull();
      expect(connection.httpSummary).toBeNull();
    }
  });

  it('域名靠明文 HTTP 的 Host 头认出来（抓包命令没带 port 53）', () => {
    const server = result.hosts.find((host) => host.address === '168.76.253.241');

    expect(server?.names.map((name) => name.name)).toEqual(['www.chinakids.net']);
    expect(server?.names[0]?.source).toBe('http-host');
  });
});

describe('真实抓包：乱序与重传的重组', () => {
  const connection = connectionOn(50_398);

  it('服务端字节数 = 重组后的流长度 + 被丢弃的那次重传', () => {
    // 14144 = 12746（去重后的真实流）+ 1398（#28 重发的响应头）
    expect(connection.stats.serverBytes).toBe(14_144);
    expect(connection.http?.transactions[0]?.response?.streamEnd).toBe(12_746);
    expect(connection.http?.quality.duplicateSegmentsDropped).toBe(1);
  });

  it('乱序不是丢包：重组后两个方向都没有空洞', () => {
    expect(connection.http?.quality.clientStreamComplete).toBe(true);
    expect(connection.http?.quality.serverStreamComplete).toBe(true);
    expect(connection.http?.quality.gaps).toEqual([]);
    expect(connection.http?.quality.payloadCapped).toBe(false);
  });

  it('承载响应头的是 #14，而不是抓包顺序里服务端的第一个数据包', () => {
    const serverData = connection.packets.filter(
      (packet) => packet.direction === 's2c' && packet.payloadLength > 0,
    );

    // 抓包顺序里服务端第一个数据包是 #11，它承载的是流的第 4194 字节
    expect(serverData[0]?.packetIndex).toBe(11);
    expect(serverData[0]?.appSpan?.streamFrom).toBe(4_194);
    expect(serverData[0]?.appSpan?.part).toBe('body');

    // 响应真正的起点在 #14
    expect(connection.http?.transactions[0]?.response?.firstPacketIndex).toBe(14);
  });

  it('#28 被判成重传，且明确标出不参与拼接', () => {
    const retransmit = connection.packets.find((packet) => packet.packetIndex === 28);

    expect(retransmit?.anomalies.map((anomaly) => anomaly.kind)).toContain('retransmission');
    expect(retransmit?.appSpan?.duplicate).toBe(true);
    expect(retransmit?.appNote).toContain('不参与响应拼接');
  });
});

describe('真实抓包：报文还原', () => {
  const connection = connectionOn(50_398);
  const transaction = connection.http!.transactions[0]!;

  it('请求与 curl -v 的输出一致', () => {
    const request = transaction.request!;

    expect(request.startLine).toBe('GET / HTTP/1.1');
    expect(request.method).toBe('GET');
    expect(request.target).toBe('/');
    expect(request.headerByteCount).toBe(80);
    expect(request.headers).toEqual([
      { name: 'Host', value: 'www.chinakids.net' },
      { name: 'User-Agent', value: 'curl/8.7.1' },
      { name: 'Accept', value: '*/*' },
    ]);
    expect(request.complete).toBe(true);
  });

  it('响应头 9 个字段全部解出', () => {
    const response = transaction.response!;

    expect(response.statusCode).toBe(200);
    expect(response.reasonPhrase).toBe('OK');
    expect(response.headerByteCount).toBe(329);
    expect(response.headers).toHaveLength(9);
    expect(response.headers.map((header) => header.name)).toEqual([
      'Server',
      'Date',
      'Content-Type',
      'Transfer-Encoding',
      'Connection',
      'Vary',
      'Trace-Id',
      'Set-Cookie',
      'X-Cache',
    ]);
    expect(response.headers.find((header) => header.name === 'Server')?.value).toBe('nginx');
    expect(response.headers.find((header) => header.name === 'Content-Type')?.value).toBe('text/html');
  });

  it('chunked 正文被解块并按 UTF-8 还原，与 curl 收到的 HTML 一致', () => {
    const body = transaction.response!.body!;

    expect(body.framing).toBe('chunked');
    expect(body.byteCount).toBe(12_397);
    expect(body.truncated).toBe(false);
    expect(body.unavailableReason).toBeNull();

    // Content-Type 里没有 charset，只能从 <meta charset="utf-8" /> 认出来
    expect(body.charset).toBe('utf-8');
    expect(body.text).not.toBeNull();
    expect(body.text!.startsWith('<!DOCTYPE html>')).toBe(true);
    expect(body.text!.trimEnd().endsWith('</html>')).toBe(true);
    expect(body.text).toContain('中国孩子网');
    expect(transaction.response!.complete).toBe(true);
  });

  it('第二次 curl 拿到的是另一份动态正文，同样解得完整', () => {
    const second = connectionOn(50_399);
    const body = second.http!.transactions[0]!.response!.body!;

    expect(second.http?.quality.duplicateSegmentsDropped).toBe(0);
    expect(body.byteCount).toBe(12_652);
    expect(body.text).toContain('中国孩子网');
  });
});

describe('真实抓包：耗时分解', () => {
  const connection = connectionOn(50_398);
  const transaction = connection.http!.transactions[0]!;

  it('把网络往返和服务端处理拆开', () => {
    // 请求送达确认 41.79ms ≈ 一个 RTT（握手 RTT 42.685ms），说明链路正常；
    // 等首字节 50.21ms，差出来的约 8.4ms 才是服务端真正的处理时间
    expect(connection.handshakeRttMicros).toBe(42_685);
    expect(transaction.timing.requestAckedMicros).toBe(41_793);
    expect(transaction.timing.ttfbMicros).toBe(50_211);
    expect(transaction.timing.responseTransferMicros).toBe(48_810);
    expect(transaction.timing.totalMicros).toBe(99_021);
  });

  it('TTFB 按流序取，不受乱序影响', () => {
    // 服务端第一个到达的包 #11 比承载响应首字节的 #14 早 4.346ms，
    // 拿抓包顺序算会把 TTFB 少算成 45.87ms
    const eleven = connection.packets.find((packet) => packet.packetIndex === 11)!;
    const fourteen = connection.packets.find((packet) => packet.packetIndex === 14)!;

    expect(fourteen.tsMicros - eleven.tsMicros).toBe(4_346);
    expect(transaction.timing.ttfbMicros).toBeGreaterThan(
      eleven.tsMicros - transaction.request!.lastTsMicros,
    );
  });

  it('给出一句能直接下结论的人话', () => {
    expect(transaction.note).toBe('GET / → 200 OK，服务端处理 8.42ms，返回 12.1 KB 正文');
    expect(connection.httpSummary).toEqual({
      transactionCount: 1,
      firstLine: 'GET /',
      statusCode: 200,
    });
  });
});
