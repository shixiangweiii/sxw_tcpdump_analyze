import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { analyze } from './analyzer.js';
import { buildHostView } from './hostview.js';
import type { Connection } from '../types.js';

/**
 * 真实抓包回归测试。
 *
 * 其余夹具全是合成的——好处是确定、可进 CI，坏处是只能验证「我们以为现实长什么样」。
 * 这个文件来自一次真实的 `sudo tcpdump -i any host www.yuhang.gov.cn -w packet.pcap`
 * （macOS，流量经 utun4 隧道），一次性覆盖了合成夹具当时全都没覆盖到的组合：
 *
 *  - Apple 的 tcpdump 写出 pcapng 而非经典 pcap，且扩展名仍是 .pcap
 *    （文件名故意保留 .pcap，用来验证格式识别只看魔数、不看扩展名）
 *  - 单 IDB、链路类型 DLT_NULL、带 if_name="utun4"
 *  - 两个 Apple 私有 block（0x80000001），必须按长度跳过而不是报错
 *  - IDB 里没有 if_tsresol，要按 pcapng 规范默认微秒
 *  - 客户端 SYN 带 ECE+CWR 与 WS=6，服务端 SYN-ACK 不回 WS
 *
 * 下面的数字全部来自对该文件的逐字节核对，不是跑一遍抄回来的。
 */
const FIXTURE = fileURLToPath(
  new URL('../../testdata/macos-tcpdump-any-utun.pcap', import.meta.url),
);

const result = analyze(new Uint8Array(readFileSync(FIXTURE)));

function anomalyCount(connection: Connection): number {
  return connection.packets.reduce((sum, packet) => sum + packet.anomalies.length, 0);
}

describe('真实抓包：macOS tcpdump -i any 经 utun 隧道', () => {
  it('容器格式按魔数识别，不受 .pcap 扩展名误导', () => {
    expect(result.capture.format).toBe('pcapng');
    expect(result.capture.truncated).toBe(false);
  });

  it('链路类型与抓包接口都被正确读出', () => {
    expect(result.capture.linkTypes).toEqual([0]);
    expect(result.capture.interfaceNames).toEqual(['utun4']);
    // 实际是 VPN 隧道，文案不能说成本机回环
    expect(result.capture.linkTypeNames[0]).not.toContain('本机回环');
  });

  it('38 个包全部解码成功，没有产生解码告警', () => {
    expect(result.capture.packetCount).toBe(38);
    expect(result.capture.decodedPackets).toBe(38);
    expect(result.capture.warnings).toEqual([]);
  });

  it('两次 curl 归拢成两条独立连接', () => {
    expect(result.connections).toHaveLength(2);

    const ports = result.connections.map((connection) => connection.clientPort);
    expect(ports).toEqual([55_708, 55_732]);

    for (const connection of result.connections) {
      expect(connection.clientAddr).toBe('198.18.0.1');
      expect(connection.serverAddr).toBe('198.18.0.141');
      expect(connection.serverPort).toBe(443);
      expect(connection.ipVersion).toBe(4);
      // 端口不同，各自都是第一代，不该被判成端口复用
      expect(connection.generation).toBe(1);
      expect(connection.stats.packetCount).toBe(19);
    }
  });

  it('两条连接都是握手完整、正常挥手关闭', () => {
    for (const connection of result.connections) {
      expect(connection.outcome).toBe('established-closed');
      expect(connection.closureReason).toBe('fin');
      expect(connection.quality.handshakeCaptured).toBe(true);
      expect(connection.quality.seqBaseEstimated).toBe(false);
      expect(connection.quality.rolesInferred).toBe(false);
      // 客户端声明了 WS、服务端没回：确知双方都不缩放
      expect(connection.quality.windowScaleKnown).toBe(true);
    }
  });

  it('字节数与握手 RTT 与逐字节核对结果一致', () => {
    const [first] = result.connections;

    expect(first?.stats.clientBytes).toBe(560);
    expect(first?.stats.serverBytes).toBe(5755);
    expect(first?.stats.byteCount).toBe(6315);
    expect(first?.handshakeRttMicros).toBe(124);
    expect(first?.durationMicros).toBe(113_798);
  });

  it('这是一次干净的抓包，一个异常都不能报', () => {
    // 本测试是整个套件里最重要的一条防线：
    // 工具敢替新手下结论的前提是不误报，否则比让他自己看 Wireshark 更糟。
    for (const connection of result.connections) {
      expect(anomalyCount(connection)).toBe(0);
      expect(connection.stats.retransmissions).toBe(0);
      expect(connection.stats.fastRetransmissions).toBe(0);
      expect(connection.stats.suspectedOutOfOrder).toBe(0);
      expect(connection.stats.zeroWindowEvents).toBe(0);
      expect(connection.stats.duplicateAcks).toBe(0);
      expect(connection.stats.lostSegments).toBe(0);
    }
  });

  it('抓包命令没带 port 53，域名只能靠 TLS SNI 认出来', () => {
    const server = result.hosts.find((host) => host.address === '198.18.0.141');

    expect(server?.names.map((name) => name.name)).toEqual(['www.yuhang.gov.cn']);
    expect(server?.names[0]?.source).toBe('sni');
    expect(server?.connectionCount).toBe(2);
    // 全程 TCP，没有 QUIC，不该触发「只分析 TCP」的兜底提示
    expect(server?.quicPackets).toBe(0);
    expect(server?.udpPackets).toBe(0);
  });

  it('按域名查询能命中 IP，并判定出「我们在访问它」', () => {
    const view = buildHostView(result, 'www.yuhang.gov.cn');

    expect(view.matchedAddresses).toEqual(['198.18.0.141']);
    expect(view.matchedNames).toEqual(['www.yuhang.gov.cn']);
    expect(view.perspective).toBe('host-as-server');
    expect(view.connections).toHaveLength(2);
  });

  it('每个包的相对序号都从 0 起算且连续推进', () => {
    const [first] = result.connections;
    const packets = first?.packets ?? [];

    // 握手三包：SYN(0) / SYN-ACK(0, ack=1) / ACK(1, ack=1)
    expect(packets[0]?.relSeq).toBe(0);
    expect(packets[0]?.flags).toEqual(['SYN', 'ECE', 'CWR']);
    expect(packets[1]?.relSeq).toBe(0);
    expect(packets[1]?.relAck).toBe(1);
    expect(packets[2]?.relSeq).toBe(1);

    // 服务端第一段应答是整 4004 字节（等于它通告的 MSS）
    expect(packets[4]?.relSeq).toBe(1);
    expect(packets[4]?.payloadLength).toBe(4004);
    expect(packets[5]?.relSeq).toBe(4005);
  });
});
