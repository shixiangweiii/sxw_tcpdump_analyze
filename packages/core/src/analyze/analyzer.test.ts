import { describe, expect, it } from 'vitest';
import { analyze } from '../analyze/analyzer.js';
import { buildHostView } from '../analyze/hostview.js';
import { scenarios } from '../testing/scenarios.js';
import type { AnomalyKind, Connection } from '../types.js';

function only(connections: Connection[]): Connection {
  expect(connections).toHaveLength(1);
  return connections[0]!;
}

function anomalyKinds(connection: Connection): AnomalyKind[] {
  return connection.packets.flatMap((packet) => packet.anomalies.map((a) => a.kind));
}

describe('容器格式', () => {
  it('经典 pcap 与 pcapng 解出完全一致的结果', () => {
    const classic = analyze(scenarios.normalConnection({ format: 'pcap' }));
    const ng = analyze(scenarios.normalConnection({ format: 'pcapng' }));

    expect(classic.capture.format).toBe('pcap');
    expect(ng.capture.format).toBe('pcapng');
    expect(ng.capture.packetCount).toBe(classic.capture.packetCount);
    expect(ng.connections).toEqual(classic.connections);
  });

  it('拒绝无法识别的文件', () => {
    expect(() => analyze(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]))).toThrow(/无法识别的文件格式/);
  });

  it('文件被截断时标记出来而不是报错', () => {
    const full = scenarios.normalConnection();
    const truncated = full.subarray(0, full.length - 20);
    const result = analyze(truncated);

    expect(result.capture.truncated).toBe(true);
    expect(result.connections.length).toBeGreaterThan(0);
  });
});

describe('链路层', () => {
  it('LINUX_SLL（k8s pod 里的 tcpdump -i any）', () => {
    const result = analyze(scenarios.linuxCookedCapture());
    const connection = only(result.connections);

    expect(result.capture.linkTypeNames[0]).toContain('LINUX_SLL');
    expect(connection.outcome).toBe('established-closed');
  });

  it('剥掉 VLAN 标签后仍能识别出连接', () => {
    const result = analyze(scenarios.vlanTagged());
    const connection = only(result.connections);

    expect(connection.serverPort).toBe(443);
    expect(connection.quality.handshakeCaptured).toBe(true);
  });

  it('DLT_NULL（macOS tcpdump -i any 走 utun 隧道）', () => {
    const result = analyze(scenarios.macosTunnelCapture());
    const connection = only(result.connections);

    expect(result.capture.format).toBe('pcapng');
    expect(result.capture.linkTypes).toEqual([0]);
    // DLT_NULL 不等于本机回环，文案不能这么写
    expect(result.capture.linkTypeNames[0]).not.toContain('本机回环');
    // 接口名是唯一能区分「回环还是隧道」的线索，必须透传出来
    expect(result.capture.interfaceNames).toEqual(['utun4']);

    expect(connection.outcome).toBe('established-closed');
    expect(connection.clientAddr).toBe('198.18.0.1');
    expect(connection.serverAddr).toBe('198.18.0.141');
    expect(connection.quality.handshakeCaptured).toBe(true);
    expect(connection.quality.rolesInferred).toBe(false);
  });

  it('经典 pcap 没有接口名，返回空数组而不是编造', () => {
    const result = analyze(scenarios.normalConnection({ format: 'pcap' }));
    expect(result.capture.interfaceNames).toEqual([]);
  });
});

describe('连接终态判定', () => {
  it('正常建连与四次挥手', () => {
    const connection = only(analyze(scenarios.normalConnection()).connections);

    expect(connection.outcome).toBe('established-closed');
    expect(connection.closureReason).toBe('fin');
    expect(connection.quality.handshakeCaptured).toBe(true);
    expect(connection.quality.rolesInferred).toBe(false);
    expect(connection.handshakeRttMicros).toBe(12_000);
  });

  it('三包挥手（FIN 与 ACK 合并）同样算正常关闭', () => {
    const connection = only(analyze(scenarios.threeWayTeardown()).connections);

    expect(connection.outcome).toBe('established-closed');
    expect(connection.closureReason).toBe('fin');
  });

  it('建连后被 RST 中断', () => {
    const connection = only(analyze(scenarios.resetConnection()).connections);

    expect(connection.outcome).toBe('established-reset');
    expect(connection.closureReason).toBe('rst');
  });

  it('SYN 无响应', () => {
    const connection = only(analyze(scenarios.synNoResponse()).connections);

    expect(connection.outcome).toBe('failed-no-response');
    expect(connection.stats.packetCount).toBe(3);
  });

  it('端口没监听，被 RST 拒绝', () => {
    const connection = only(analyze(scenarios.connectionRefused()).connections);

    expect(connection.outcome).toBe('failed-refused');
    expect(connection.packets[1]?.note).toContain('没有程序在监听');
  });

  it('抓包开始时连接已存在', () => {
    const connection = only(analyze(scenarios.midStreamConnection()).connections);

    expect(connection.outcome).toBe('handshake-missing');
    expect(connection.quality.handshakeCaptured).toBe(false);
    expect(connection.quality.seqBaseEstimated).toBe(true);
    // 缩放因子未知时不能编造窗口大小
    expect(connection.quality.windowScaleKnown).toBe(false);
    expect(connection.packets[0]?.scaledWindow).toBeNull();
  });

  it('抓包结束时连接仍开着', () => {
    const connection = only(analyze(scenarios.zeroWindow()).connections);
    expect(connection.outcome).toBe('established-open');
  });
});

describe('端口复用与 SYN 重传', () => {
  it('同一四元组的两条连接被拆开，generation 递增', () => {
    const result = analyze(scenarios.portReuse());

    expect(result.connections).toHaveLength(2);
    expect(result.connections[0]?.generation).toBe(1);
    expect(result.connections[1]?.generation).toBe(2);
    expect(result.connections[0]?.outcome).toBe('established-reset');
    expect(result.connections[1]?.outcome).toBe('established-open');
  });

  it('相同 ISN 的 SYN 是重传，不能拆成两条连接', () => {
    const result = analyze(scenarios.synRetransmission());
    const connection = only(result.connections);

    expect(connection.generation).toBe(1);
    expect(connection.outcome).toBe('established-open');
    expect(connection.stats.packetCount).toBe(4);
  });
});

describe('序号', () => {
  it('握手完整时相对序号从 0 开始，且保留原始序号', () => {
    const connection = only(analyze(scenarios.normalConnection()).connections);
    const [syn, synAck, ack] = connection.packets;

    expect(syn?.relSeq).toBe(0);
    expect(syn?.rawSeq).toBe(1000);
    expect(synAck?.relSeq).toBe(0);
    expect(synAck?.relAck).toBe(1); // SYN 占用一个序号
    expect(synAck?.rawSeq).toBe(5_000_000);
    expect(ack?.relSeq).toBe(1);
    expect(ack?.relAck).toBe(1);
    expect(connection.quality.seqBaseEstimated).toBe(false);
  });

  it('未捕获握手时以首包为基准并标记为估算', () => {
    const connection = only(analyze(scenarios.midStreamConnection()).connections);

    expect(connection.packets[0]?.relSeq).toBe(0);
    expect(connection.packets[0]?.rawSeq).toBe(4_000_000);
    expect(connection.quality.seqBaseEstimated).toBe(true);
  });
});

describe('异常检测', () => {
  it('超时重传', () => {
    const connection = only(analyze(scenarios.retransmission()).connections);

    expect(connection.stats.retransmissions).toBe(1);
    expect(connection.stats.suspectedOutOfOrder).toBe(0);
  });

  it('短间隔重复只标疑似乱序，不下重传的结论', () => {
    const connection = only(analyze(scenarios.outOfOrder()).connections);

    expect(connection.stats.suspectedOutOfOrder).toBe(1);
    expect(connection.stats.retransmissions).toBe(0);
    const kinds = anomalyKinds(connection);
    expect(kinds).toContain('suspected-out-of-order');
  });

  it('三次重复 ACK 后的重发算快速重传', () => {
    const connection = only(analyze(scenarios.fastRetransmission()).connections);

    expect(connection.stats.duplicateAcks).toBe(3);
    expect(connection.stats.fastRetransmissions).toBe(1);
  });

  it('零窗口与窗口恢复', () => {
    const connection = only(analyze(scenarios.zeroWindow()).connections);
    const kinds = anomalyKinds(connection);

    expect(connection.stats.zeroWindowEvents).toBe(1);
    expect(kinds).toContain('window-update');
  });

  it('窗口缩放已协商时换算出真实窗口', () => {
    const connection = only(analyze(scenarios.normalConnection()).connections);
    const handshakeAck = connection.packets[2];

    expect(connection.quality.windowScaleKnown).toBe(true);
    // 客户端通告缩放 7，窗口字段 512 → 真实窗口 65536
    expect(handshakeAck?.window).toBe(512);
    expect(handshakeAck?.scaledWindow).toBe(65_536);
  });

  it('只有一方声明窗口缩放时按不缩放处理，且不算未知', () => {
    const connection = only(analyze(scenarios.macosTunnelCapture()).connections);

    // 客户端 SYN 带 WS=6、服务端 SYN-ACK 不带：RFC 7323 规定此时双方都不缩放。
    // 这是「确知不缩放」而非「无从判断」，所以不该给用户挂可信度告警。
    expect(connection.quality.windowScaleKnown).toBe(true);
    for (const packet of connection.packets) {
      expect(packet.scaledWindow).toBe(packet.window);
    }
  });

  it('干净抓包不得报出任何异常', () => {
    const connection = only(analyze(scenarios.macosTunnelCapture()).connections);

    // 带 ECE/CWR 的 SYN、超 MSS 的整段数据、FIN 占序号，都不该被误判
    expect(anomalyKinds(connection)).toEqual([]);
  });
});

describe('host 解析', () => {
  it('DNS 应答建立域名到 IP 的映射，CNAME 链上的名字同样可查', () => {
    const result = analyze(scenarios.dnsAndSni());
    const target = result.hosts.find((host) => host.address === '93.184.216.34');

    const names = target?.names.map((n) => n.name) ?? [];
    expect(names).toContain('www.example.com');
    expect(names).toContain('cdn.example.net');
    expect(target?.names.some((n) => n.source === 'dns')).toBe(true);
  });

  it('TLS ClientHello 的 SNI 也能作为证据', () => {
    const result = analyze(scenarios.dnsAndSni());
    const target = result.hosts.find((host) => host.address === '93.184.216.34');

    expect(target?.names.some((n) => n.source === 'sni' && n.name === 'www.example.com')).toBe(
      true,
    );
  });

  it('按域名过滤能命中对应连接，并推断出 host 是服务端', () => {
    const result = analyze(scenarios.dnsAndSni());
    const view = buildHostView(result, 'www.example.com');

    expect(view.matchedAddresses).toContain('93.184.216.34');
    expect(view.connections).toHaveLength(1);
    expect(view.perspective).toBe('host-as-server');
  });

  it('按 IP 过滤等价于按域名过滤', () => {
    const result = analyze(scenarios.dnsAndSni());
    const byName = buildHostView(result, 'www.example.com');
    const byIp = buildHostView(result, '93.184.216.34');

    expect(byIp.connections.map((c) => c.id)).toEqual(byName.connections.map((c) => c.id));
  });

  it('统计 QUIC 流量用于兜底提示', () => {
    const result = analyze(scenarios.dnsAndSni());
    const view = buildHostView(result, '93.184.216.34');

    expect(view.nonTcp.quicPackets).toBe(5);
  });

  it('客户端视角下 host 落在服务端侧', () => {
    const result = analyze(scenarios.normalConnection());
    const view = buildHostView(result, '93.184.216.34');
    expect(view.perspective).toBe('host-as-server');
  });

  it('查询客户端 IP 时视角反转为 host-as-client', () => {
    const result = analyze(scenarios.normalConnection());
    const view = buildHostView(result, '192.168.1.10');
    expect(view.perspective).toBe('host-as-client');
  });
});

describe('人话注解', () => {
  it('握手三个包各自有对应的解释', () => {
    const connection = only(analyze(scenarios.normalConnection()).connections);
    const notes = connection.packets.map((p) => p.note);

    expect(notes[0]).toContain('客户端发起建连（SYN）');
    expect(notes[1]).toContain('服务端同意建连（SYN-ACK）');
    expect(notes[2]).toContain('三次握手完成');
  });

  it('挥手与数据包也有解释', () => {
    const connection = only(analyze(scenarios.normalConnection()).connections);
    const notes = connection.packets.map((p) => p.note);

    expect(notes.some((note) => note.includes('发送 37 字节数据'))).toBe(true);
    expect(notes.some((note) => note.includes('请求关闭连接（FIN）'))).toBe(true);
  });
});
