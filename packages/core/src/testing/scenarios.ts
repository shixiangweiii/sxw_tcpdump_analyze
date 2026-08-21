import { LinkType } from '../decode/link.js';
import { PcapBuilder } from './pcap-builder.js';

const CLIENT = '192.168.1.10';
const SERVER = '93.184.216.34';
const CLIENT_PORT = 51514;
const SERVER_PORT = 443;
const CLIENT_ISN = 1000;
const SERVER_ISN = 5_000_000;
const BASE_TS = 1_775_000_000_000_000; // 2026 年的某个时刻

/** 请求与应答的字节长度必须从实际编码算，手写常量会把序号算错 */
const HTTP_REQUEST = 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n';
const HTTP_RESPONSE = 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi';
const REQUEST_LENGTH = new TextEncoder().encode(HTTP_REQUEST).length;
const RESPONSE_LENGTH = new TextEncoder().encode(HTTP_RESPONSE).length;

interface ScenarioOptions {
  linkType?: number;
  format?: 'pcap' | 'pcapng';
}

/** 最健康的形态：三次握手 → 一来一回 → 四次挥手 */
export function normalConnection(options: ScenarioOptions = {}): Uint8Array {
  const b = new PcapBuilder(options);
  const t = (offset: number) => BASE_TS + offset;

  b.tcp({
    tsMicros: t(0),
    src: CLIENT,
    srcPort: CLIENT_PORT,
    dst: SERVER,
    dstPort: SERVER_PORT,
    seq: CLIENT_ISN,
    flags: ['SYN'],
    window: 65535,
    options: { mss: 1460, sackPermitted: true, windowScale: 7 },
  });
  b.tcp({
    tsMicros: t(12_000),
    src: SERVER,
    srcPort: SERVER_PORT,
    dst: CLIENT,
    dstPort: CLIENT_PORT,
    seq: SERVER_ISN,
    ack: CLIENT_ISN + 1,
    flags: ['SYN', 'ACK'],
    window: 65535,
    options: { mss: 1460, sackPermitted: true, windowScale: 8 },
  });
  b.tcp({
    tsMicros: t(12_200),
    src: CLIENT,
    srcPort: CLIENT_PORT,
    dst: SERVER,
    dstPort: SERVER_PORT,
    seq: CLIENT_ISN + 1,
    ack: SERVER_ISN + 1,
    flags: ['ACK'],
    window: 512,
  });

  b.tcp({
    tsMicros: t(13_000),
    src: CLIENT,
    srcPort: CLIENT_PORT,
    dst: SERVER,
    dstPort: SERVER_PORT,
    seq: CLIENT_ISN + 1,
    ack: SERVER_ISN + 1,
    flags: ['PSH', 'ACK'],
    window: 512,
    payload: HTTP_REQUEST,
  });
  const requestLength = REQUEST_LENGTH;

  b.tcp({
    tsMicros: t(45_000),
    src: SERVER,
    srcPort: SERVER_PORT,
    dst: CLIENT,
    dstPort: CLIENT_PORT,
    seq: SERVER_ISN + 1,
    ack: CLIENT_ISN + 1 + requestLength,
    flags: ['PSH', 'ACK'],
    window: 501,
    payload: HTTP_RESPONSE,
  });
  const responseLength = RESPONSE_LENGTH;

  // 四次挥手：客户端先关
  b.tcp({
    tsMicros: t(46_000),
    src: CLIENT,
    srcPort: CLIENT_PORT,
    dst: SERVER,
    dstPort: SERVER_PORT,
    seq: CLIENT_ISN + 1 + requestLength,
    ack: SERVER_ISN + 1 + responseLength,
    flags: ['FIN', 'ACK'],
    window: 512,
  });
  b.tcp({
    tsMicros: t(46_500),
    src: SERVER,
    srcPort: SERVER_PORT,
    dst: CLIENT,
    dstPort: CLIENT_PORT,
    seq: SERVER_ISN + 1 + responseLength,
    ack: CLIENT_ISN + 2 + requestLength,
    flags: ['ACK'],
    window: 501,
  });
  b.tcp({
    tsMicros: t(47_000),
    src: SERVER,
    srcPort: SERVER_PORT,
    dst: CLIENT,
    dstPort: CLIENT_PORT,
    seq: SERVER_ISN + 1 + responseLength,
    ack: CLIENT_ISN + 2 + requestLength,
    flags: ['FIN', 'ACK'],
    window: 501,
  });
  b.tcp({
    tsMicros: t(47_500),
    src: CLIENT,
    srcPort: CLIENT_PORT,
    dst: SERVER,
    dstPort: SERVER_PORT,
    seq: CLIENT_ISN + 2 + requestLength,
    ack: SERVER_ISN + 2 + responseLength,
    flags: ['ACK'],
    window: 512,
  });

  return b.build();
}

/**
 * 三包挥手：服务端把 FIN 和对客户端 FIN 的 ACK 合并成一个包。
 * 现实中比标准的四次挥手更常见，硬匹配「四次」的实现会在这里失败。
 */
export function threeWayTeardown(options: ScenarioOptions = {}): Uint8Array {
  const b = new PcapBuilder(options);
  const t = (offset: number) => BASE_TS + offset;
  handshake(b, t);

  b.tcp({
    tsMicros: t(20_000),
    src: CLIENT,
    srcPort: CLIENT_PORT,
    dst: SERVER,
    dstPort: SERVER_PORT,
    seq: CLIENT_ISN + 1,
    ack: SERVER_ISN + 1,
    flags: ['FIN', 'ACK'],
  });
  b.tcp({
    tsMicros: t(20_500),
    src: SERVER,
    srcPort: SERVER_PORT,
    dst: CLIENT,
    dstPort: CLIENT_PORT,
    seq: SERVER_ISN + 1,
    ack: CLIENT_ISN + 2,
    flags: ['FIN', 'ACK'],
  });
  b.tcp({
    tsMicros: t(21_000),
    src: CLIENT,
    srcPort: CLIENT_PORT,
    dst: SERVER,
    dstPort: SERVER_PORT,
    seq: CLIENT_ISN + 2,
    ack: SERVER_ISN + 2,
    flags: ['ACK'],
  });

  return b.build();
}

/** 连接建立后被服务端 RST 掐断 */
export function resetConnection(options: ScenarioOptions = {}): Uint8Array {
  const b = new PcapBuilder(options);
  const t = (offset: number) => BASE_TS + offset;
  handshake(b, t);

  b.tcp({
    tsMicros: t(15_000),
    src: CLIENT,
    srcPort: CLIENT_PORT,
    dst: SERVER,
    dstPort: SERVER_PORT,
    seq: CLIENT_ISN + 1,
    ack: SERVER_ISN + 1,
    flags: ['PSH', 'ACK'],
    payload: 'hello',
  });
  b.tcp({
    tsMicros: t(16_000),
    src: SERVER,
    srcPort: SERVER_PORT,
    dst: CLIENT,
    dstPort: CLIENT_PORT,
    seq: SERVER_ISN + 1,
    ack: CLIENT_ISN + 6,
    flags: ['RST', 'ACK'],
  });

  return b.build();
}

/** SYN 发出去石沉大海，只有重传，没有任何回应 */
export function synNoResponse(options: ScenarioOptions = {}): Uint8Array {
  const b = new PcapBuilder(options);
  const t = (offset: number) => BASE_TS + offset;

  for (const [index, delay] of [0, 1_000_000, 3_000_000].entries()) {
    b.tcp({
      tsMicros: t(delay),
      src: CLIENT,
      srcPort: CLIENT_PORT,
      dst: SERVER,
      dstPort: SERVER_PORT,
      seq: CLIENT_ISN,
      flags: ['SYN'],
      window: 65535,
      options: { mss: 1460, windowScale: 7 },
    });
    void index;
  }

  return b.build();
}

/** 端口没程序监听，服务端直接回 RST */
export function connectionRefused(options: ScenarioOptions = {}): Uint8Array {
  const b = new PcapBuilder(options);
  const t = (offset: number) => BASE_TS + offset;

  b.tcp({
    tsMicros: t(0),
    src: CLIENT,
    srcPort: CLIENT_PORT,
    dst: SERVER,
    dstPort: 8080,
    seq: CLIENT_ISN,
    flags: ['SYN'],
    options: { mss: 1460, windowScale: 7 },
  });
  b.tcp({
    tsMicros: t(800),
    src: SERVER,
    srcPort: 8080,
    dst: CLIENT,
    dstPort: CLIENT_PORT,
    seq: 0,
    ack: CLIENT_ISN + 1,
    flags: ['RST', 'ACK'],
    window: 0,
  });

  return b.build();
}

/** 超时重传：同一段数据隔了 300ms 又发一遍 */
export function retransmission(options: ScenarioOptions = {}): Uint8Array {
  const b = new PcapBuilder(options);
  const t = (offset: number) => BASE_TS + offset;
  handshake(b, t);

  const send = (tsMicros: number) =>
    b.tcp({
      tsMicros,
      src: CLIENT,
      srcPort: CLIENT_PORT,
      dst: SERVER,
      dstPort: SERVER_PORT,
      seq: CLIENT_ISN + 1,
      ack: SERVER_ISN + 1,
      flags: ['PSH', 'ACK'],
      payload: 'A'.repeat(100),
    });

  send(t(20_000));
  send(t(320_000)); // 300ms 后重发，远超乱序阈值
  b.tcp({
    tsMicros: t(330_000),
    src: SERVER,
    srcPort: SERVER_PORT,
    dst: CLIENT,
    dstPort: CLIENT_PORT,
    seq: SERVER_ISN + 1,
    ack: CLIENT_ISN + 101,
    flags: ['ACK'],
  });

  return b.build();
}

/**
 * 快速重传：第二段丢了，后续段继续到达，服务端每收一个就重复确认一次。
 *
 * 注意数量：RFC 5681 说的「3 个重复 ACK」是指 3 个**重复**，加上最初那个正常推进的 ACK，
 * 线上一共会看到 4 个确认号相同的包。只发 3 个不足以触发快速重传。
 */
export function fastRetransmission(options: ScenarioOptions = {}): Uint8Array {
  const b = new PcapBuilder(options);
  const t = (offset: number) => BASE_TS + offset;
  handshake(b, t);

  // 客户端连发五段，其中第二段（seq=101）在路上丢失。
  // 在发送端抓包仍然能看到它，只是服务端没收到。
  for (let i = 0; i < 5; i += 1) {
    b.tcp({
      tsMicros: t(20_000 + i * 1000),
      src: CLIENT,
      srcPort: CLIENT_PORT,
      dst: SERVER,
      dstPort: SERVER_PORT,
      seq: CLIENT_ISN + 1 + i * 100,
      ack: SERVER_ISN + 1,
      flags: ['PSH', 'ACK'],
      payload: 'B'.repeat(100),
    });
  }

  // 第一个 ACK 确认第一段，是正常推进；后面三个才是重复确认
  for (let i = 0; i < 4; i += 1) {
    b.tcp({
      tsMicros: t(25_000 + i * 500),
      src: SERVER,
      srcPort: SERVER_PORT,
      dst: CLIENT,
      dstPort: CLIENT_PORT,
      seq: SERVER_ISN + 1,
      ack: CLIENT_ISN + 101,
      flags: ['ACK'],
      window: 501,
    });
  }

  // 客户端不等超时，立刻重发丢掉的那一段
  b.tcp({
    tsMicros: t(30_000),
    src: CLIENT,
    srcPort: CLIENT_PORT,
    dst: SERVER,
    dstPort: SERVER_PORT,
    seq: CLIENT_ISN + 101,
    ack: SERVER_ISN + 1,
    flags: ['PSH', 'ACK'],
    payload: 'B'.repeat(100),
  });

  return b.build();
}

/** 乱序：同一段数据在 1ms 内重复出现，时间间隔远小于重传阈值 */
export function outOfOrder(options: ScenarioOptions = {}): Uint8Array {
  const b = new PcapBuilder(options);
  const t = (offset: number) => BASE_TS + offset;
  handshake(b, t);

  b.tcp({
    tsMicros: t(20_000),
    src: CLIENT,
    srcPort: CLIENT_PORT,
    dst: SERVER,
    dstPort: SERVER_PORT,
    seq: CLIENT_ISN + 1,
    ack: SERVER_ISN + 1,
    flags: ['PSH', 'ACK'],
    payload: 'C'.repeat(50),
  });
  b.tcp({
    tsMicros: t(20_800), // 仅隔 0.8ms
    src: CLIENT,
    srcPort: CLIENT_PORT,
    dst: SERVER,
    dstPort: SERVER_PORT,
    seq: CLIENT_ISN + 1,
    ack: SERVER_ISN + 1,
    flags: ['PSH', 'ACK'],
    payload: 'C'.repeat(50),
  });

  return b.build();
}

/** 零窗口：服务端缓冲区满，通告窗口 0，随后恢复 */
export function zeroWindow(options: ScenarioOptions = {}): Uint8Array {
  const b = new PcapBuilder(options);
  const t = (offset: number) => BASE_TS + offset;
  handshake(b, t);

  b.tcp({
    tsMicros: t(20_000),
    src: SERVER,
    srcPort: SERVER_PORT,
    dst: CLIENT,
    dstPort: CLIENT_PORT,
    seq: SERVER_ISN + 1,
    ack: CLIENT_ISN + 1,
    flags: ['ACK'],
    window: 0,
  });
  b.tcp({
    tsMicros: t(500_000),
    src: SERVER,
    srcPort: SERVER_PORT,
    dst: CLIENT,
    dstPort: CLIENT_PORT,
    seq: SERVER_ISN + 1,
    ack: CLIENT_ISN + 1,
    flags: ['ACK'],
    window: 512,
  });

  return b.build();
}

/**
 * 抓包开始时连接已存在：没有 SYN，因此没有 ISN，也不知道窗口缩放因子。
 * nginx 服务端和连接池场景下极其常见。
 */
export function midStreamConnection(options: ScenarioOptions = {}): Uint8Array {
  const b = new PcapBuilder(options);
  const t = (offset: number) => BASE_TS + offset;

  b.tcp({
    tsMicros: t(0),
    src: CLIENT,
    srcPort: CLIENT_PORT,
    dst: SERVER,
    dstPort: SERVER_PORT,
    seq: 4_000_000,
    ack: 9_000_000,
    flags: ['PSH', 'ACK'],
    window: 502,
    payload: 'GET /api HTTP/1.1\r\nHost: api.internal\r\n\r\n',
  });
  b.tcp({
    tsMicros: t(30_000),
    src: SERVER,
    srcPort: SERVER_PORT,
    dst: CLIENT,
    dstPort: CLIENT_PORT,
    seq: 9_000_000,
    ack: 4_000_040,
    flags: ['PSH', 'ACK'],
    window: 501,
    payload: 'HTTP/1.1 200 OK\r\n\r\n',
  });

  return b.build();
}

/** 端口复用：同一个四元组先后承载两条独立连接 */
export function portReuse(options: ScenarioOptions = {}): Uint8Array {
  const b = new PcapBuilder(options);
  const t = (offset: number) => BASE_TS + offset;

  // 第一条：建连后被 RST
  b.tcp({
    tsMicros: t(0),
    src: CLIENT,
    srcPort: CLIENT_PORT,
    dst: SERVER,
    dstPort: SERVER_PORT,
    seq: CLIENT_ISN,
    flags: ['SYN'],
    options: { mss: 1460, windowScale: 7 },
  });
  b.tcp({
    tsMicros: t(10_000),
    src: SERVER,
    srcPort: SERVER_PORT,
    dst: CLIENT,
    dstPort: CLIENT_PORT,
    seq: SERVER_ISN,
    ack: CLIENT_ISN + 1,
    flags: ['SYN', 'ACK'],
    options: { mss: 1460, windowScale: 8 },
  });
  b.tcp({
    tsMicros: t(11_000),
    src: SERVER,
    srcPort: SERVER_PORT,
    dst: CLIENT,
    dstPort: CLIENT_PORT,
    seq: SERVER_ISN + 1,
    ack: CLIENT_ISN + 1,
    flags: ['RST', 'ACK'],
  });

  // 第二条：完全不同的 ISN，同样的端口
  b.tcp({
    tsMicros: t(2_000_000),
    src: CLIENT,
    srcPort: CLIENT_PORT,
    dst: SERVER,
    dstPort: SERVER_PORT,
    seq: 777_000,
    flags: ['SYN'],
    options: { mss: 1460, windowScale: 7 },
  });
  b.tcp({
    tsMicros: t(2_010_000),
    src: SERVER,
    srcPort: SERVER_PORT,
    dst: CLIENT,
    dstPort: CLIENT_PORT,
    seq: 888_000,
    ack: 777_001,
    flags: ['SYN', 'ACK'],
    options: { mss: 1460, windowScale: 8 },
  });
  b.tcp({
    tsMicros: t(2_011_000),
    src: CLIENT,
    srcPort: CLIENT_PORT,
    dst: SERVER,
    dstPort: SERVER_PORT,
    seq: 777_001,
    ack: 888_001,
    flags: ['ACK'],
  });

  return b.build();
}

/** SYN 重传：同一个 ISN 重发，不能被当成新连接 */
export function synRetransmission(options: ScenarioOptions = {}): Uint8Array {
  const b = new PcapBuilder(options);
  const t = (offset: number) => BASE_TS + offset;

  b.tcp({
    tsMicros: t(0),
    src: CLIENT,
    srcPort: CLIENT_PORT,
    dst: SERVER,
    dstPort: SERVER_PORT,
    seq: CLIENT_ISN,
    flags: ['SYN'],
    options: { mss: 1460, windowScale: 7 },
  });
  b.tcp({
    tsMicros: t(1_000_000),
    src: CLIENT,
    srcPort: CLIENT_PORT,
    dst: SERVER,
    dstPort: SERVER_PORT,
    seq: CLIENT_ISN,
    flags: ['SYN'],
    options: { mss: 1460, windowScale: 7 },
  });
  b.tcp({
    tsMicros: t(1_010_000),
    src: SERVER,
    srcPort: SERVER_PORT,
    dst: CLIENT,
    dstPort: CLIENT_PORT,
    seq: SERVER_ISN,
    ack: CLIENT_ISN + 1,
    flags: ['SYN', 'ACK'],
    options: { mss: 1460, windowScale: 8 },
  });
  b.tcp({
    tsMicros: t(1_011_000),
    src: CLIENT,
    srcPort: CLIENT_PORT,
    dst: SERVER,
    dstPort: SERVER_PORT,
    seq: CLIENT_ISN + 1,
    ack: SERVER_ISN + 1,
    flags: ['ACK'],
  });

  return b.build();
}

/** DNS 应答 + 带 SNI 的 TLS ClientHello，用来验证域名到 IP 的映射 */
export function dnsAndSni(options: ScenarioOptions = {}): Uint8Array {
  const b = new PcapBuilder(options);
  const t = (offset: number) => BASE_TS + offset;

  b.udp({
    tsMicros: t(0),
    src: '10.0.0.1',
    srcPort: 53,
    dst: CLIENT,
    dstPort: 40000,
    payload: buildDnsResponse('www.example.com', ['cdn.example.net'], [SERVER]),
  });

  b.tcp({
    tsMicros: t(5_000),
    src: CLIENT,
    srcPort: CLIENT_PORT,
    dst: SERVER,
    dstPort: SERVER_PORT,
    seq: CLIENT_ISN,
    flags: ['SYN'],
    options: { mss: 1460, windowScale: 7 },
  });
  b.tcp({
    tsMicros: t(15_000),
    src: SERVER,
    srcPort: SERVER_PORT,
    dst: CLIENT,
    dstPort: CLIENT_PORT,
    seq: SERVER_ISN,
    ack: CLIENT_ISN + 1,
    flags: ['SYN', 'ACK'],
    options: { mss: 1460, windowScale: 8 },
  });
  b.tcp({
    tsMicros: t(15_500),
    src: CLIENT,
    srcPort: CLIENT_PORT,
    dst: SERVER,
    dstPort: SERVER_PORT,
    seq: CLIENT_ISN + 1,
    ack: SERVER_ISN + 1,
    flags: ['ACK'],
  });

  const clientHello = buildClientHello('www.example.com');
  b.tcp({
    tsMicros: t(16_000),
    src: CLIENT,
    srcPort: CLIENT_PORT,
    dst: SERVER,
    dstPort: SERVER_PORT,
    seq: CLIENT_ISN + 1,
    ack: SERVER_ISN + 1,
    flags: ['PSH', 'ACK'],
    payload: clientHello,
  });

  // 同一个 host 上的 QUIC 流量，用来触发「只分析 TCP」的兜底提示
  for (let i = 0; i < 5; i += 1) {
    b.udp({
      tsMicros: t(20_000 + i * 1000),
      src: CLIENT,
      srcPort: 55000,
      dst: SERVER,
      dstPort: 443,
      payload: new Uint8Array([0xc0, 0x00, 0x00, 0x00, 0x01]),
    });
  }

  return b.build();
}

/** k8s pod 里 tcpdump -i any 的封装形式 */
export function linuxCookedCapture(): Uint8Array {
  return normalConnection({ linkType: LinkType.LINUX_SLL });
}

/** 带 VLAN 标签的以太网帧 */
export function vlanTagged(): Uint8Array {
  const b = new PcapBuilder();
  const t = (offset: number) => BASE_TS + offset;

  b.tcp({
    tsMicros: t(0),
    src: CLIENT,
    srcPort: CLIENT_PORT,
    dst: SERVER,
    dstPort: SERVER_PORT,
    seq: CLIENT_ISN,
    flags: ['SYN'],
    vlanId: 100,
    options: { mss: 1460, windowScale: 7 },
  });
  b.tcp({
    tsMicros: t(10_000),
    src: SERVER,
    srcPort: SERVER_PORT,
    dst: CLIENT,
    dstPort: CLIENT_PORT,
    seq: SERVER_ISN,
    ack: CLIENT_ISN + 1,
    flags: ['SYN', 'ACK'],
    vlanId: 100,
    options: { mss: 1460, windowScale: 8 },
  });

  return b.build();
}

function handshake(b: PcapBuilder, t: (offset: number) => number): void {
  b.tcp({
    tsMicros: t(0),
    src: CLIENT,
    srcPort: CLIENT_PORT,
    dst: SERVER,
    dstPort: SERVER_PORT,
    seq: CLIENT_ISN,
    flags: ['SYN'],
    window: 65535,
    options: { mss: 1460, sackPermitted: true, windowScale: 7 },
  });
  b.tcp({
    tsMicros: t(10_000),
    src: SERVER,
    srcPort: SERVER_PORT,
    dst: CLIENT,
    dstPort: CLIENT_PORT,
    seq: SERVER_ISN,
    ack: CLIENT_ISN + 1,
    flags: ['SYN', 'ACK'],
    window: 65535,
    options: { mss: 1460, sackPermitted: true, windowScale: 8 },
  });
  b.tcp({
    tsMicros: t(10_500),
    src: CLIENT,
    srcPort: CLIENT_PORT,
    dst: SERVER,
    dstPort: SERVER_PORT,
    seq: CLIENT_ISN + 1,
    ack: SERVER_ISN + 1,
    flags: ['ACK'],
    window: 512,
  });
}

/**
 * macOS `tcpdump -i any host <域名>` 的真实形态。
 *
 * Apple 的 tcpdump 写出的是 pcapng，并按真实抓包接口建 IDB——流量走 VPN / 代理时
 * 接口是 utun，链路类型为 DLT_NULL。这与「本机回环」无关，因此必须靠 if_name 区分。
 *
 * 另两个现实细节一并复刻：
 *  - macOS 的 SYN 会带 ECE + CWR（ECN 商议），不能影响握手识别
 *  - 服务端 SYN-ACK 不回 Window Scale，此时双方都不缩放（而不是「未知」）
 */
export function macosTunnelCapture(): Uint8Array {
  const b = new PcapBuilder({
    format: 'pcapng',
    linkType: LinkType.NULL,
    interfaceName: 'utun4',
  });
  const t = (offset: number) => BASE_TS + offset;

  const client = '198.18.0.1';
  const server = '198.18.0.141';
  const clientPort = 55_708;
  const clientIsn = 3_000_000;
  const serverIsn = 7_000_000;

  // 长度一律从实际编码算，避免手写常量把序号对不上
  const clientHello = buildClientHello('www.yuhang.gov.cn');
  const serverFlight = new Uint8Array(1200).fill(0x17);
  const clientAppData = new Uint8Array(31).fill(0x17);

  b.tcp({
    tsMicros: t(0),
    src: client,
    srcPort: clientPort,
    dst: server,
    dstPort: SERVER_PORT,
    seq: clientIsn,
    flags: ['SYN', 'ECE', 'CWR'],
    window: 65535,
    options: { mss: 4024, sackPermitted: true, windowScale: 6 },
  });
  b.tcp({
    tsMicros: t(124),
    src: server,
    srcPort: SERVER_PORT,
    dst: client,
    dstPort: clientPort,
    seq: serverIsn,
    ack: clientIsn + 1,
    flags: ['SYN', 'ACK'],
    window: 65535,
    // 注意：没有 windowScale
    options: { mss: 4004 },
  });
  b.tcp({
    tsMicros: t(189),
    src: client,
    srcPort: clientPort,
    dst: server,
    dstPort: SERVER_PORT,
    seq: clientIsn + 1,
    ack: serverIsn + 1,
    flags: ['ACK'],
    window: 65535,
  });
  b.tcp({
    tsMicros: t(12_328),
    src: client,
    srcPort: clientPort,
    dst: server,
    dstPort: SERVER_PORT,
    seq: clientIsn + 1,
    ack: serverIsn + 1,
    flags: ['PSH', 'ACK'],
    window: 65535,
    payload: clientHello,
  });
  b.tcp({
    tsMicros: t(44_888),
    src: server,
    srcPort: SERVER_PORT,
    dst: client,
    dstPort: clientPort,
    seq: serverIsn + 1,
    ack: clientIsn + 1 + clientHello.length,
    flags: ['ACK'],
    window: 65208,
    payload: serverFlight,
  });
  b.tcp({
    tsMicros: t(45_020),
    src: client,
    srcPort: clientPort,
    dst: server,
    dstPort: SERVER_PORT,
    seq: clientIsn + 1 + clientHello.length,
    ack: serverIsn + 1 + serverFlight.length,
    flags: ['ACK'],
    window: 65535,
  });
  b.tcp({
    tsMicros: t(107_970),
    src: client,
    srcPort: clientPort,
    dst: server,
    dstPort: SERVER_PORT,
    seq: clientIsn + 1 + clientHello.length,
    ack: serverIsn + 1 + serverFlight.length,
    flags: ['PSH', 'ACK'],
    window: 65535,
    payload: clientAppData,
  });

  const clientFinSeq = clientIsn + 1 + clientHello.length + clientAppData.length;
  const serverFinSeq = serverIsn + 1 + serverFlight.length;

  b.tcp({
    tsMicros: t(113_473),
    src: client,
    srcPort: clientPort,
    dst: server,
    dstPort: SERVER_PORT,
    seq: clientFinSeq,
    ack: serverFinSeq,
    flags: ['FIN', 'ACK'],
    window: 65535,
  });
  b.tcp({
    tsMicros: t(113_667),
    src: server,
    srcPort: SERVER_PORT,
    dst: client,
    dstPort: clientPort,
    seq: serverFinSeq,
    ack: clientFinSeq + 1,
    flags: ['FIN', 'ACK'],
    window: 64974,
  });
  b.tcp({
    tsMicros: t(113_798),
    src: client,
    srcPort: clientPort,
    dst: server,
    dstPort: SERVER_PORT,
    seq: clientFinSeq + 1,
    ack: serverFinSeq + 1,
    flags: ['ACK'],
    window: 65535,
  });

  return b.build();
}

/** 构造一个含 CNAME 链的 DNS 应答 */
function buildDnsResponse(question: string, cnames: string[], addresses: string[]): Uint8Array {
  const parts: number[] = [];

  parts.push(0x12, 0x34); // transaction id
  parts.push(0x81, 0x80); // 标准查询应答，无错误
  parts.push(0x00, 0x01); // qdcount
  const answerCount = cnames.length + addresses.length;
  parts.push((answerCount >> 8) & 0xff, answerCount & 0xff);
  parts.push(0x00, 0x00, 0x00, 0x00); // nscount / arcount

  parts.push(...encodeName(question));
  parts.push(0x00, 0x01, 0x00, 0x01); // type A, class IN

  let owner = question;
  for (const cname of cnames) {
    parts.push(...encodeName(owner));
    parts.push(0x00, 0x05, 0x00, 0x01); // type CNAME
    parts.push(0x00, 0x00, 0x01, 0x2c); // ttl 300
    const encoded = encodeName(cname);
    parts.push((encoded.length >> 8) & 0xff, encoded.length & 0xff);
    parts.push(...encoded);
    owner = cname;
  }

  for (const address of addresses) {
    parts.push(...encodeName(owner));
    parts.push(0x00, 0x01, 0x00, 0x01); // type A
    parts.push(0x00, 0x00, 0x01, 0x2c);
    parts.push(0x00, 0x04);
    parts.push(...address.split('.').map((part) => Number(part) & 0xff));
  }

  return new Uint8Array(parts);
}

function encodeName(name: string): number[] {
  const out: number[] = [];
  for (const label of name.split('.')) {
    out.push(label.length);
    for (const char of label) out.push(char.charCodeAt(0));
  }
  out.push(0);
  return out;
}

/** 构造一个只带 SNI 扩展的最小 TLS ClientHello */
function buildClientHello(serverName: string): Uint8Array {
  const nameBytes = [...serverName].map((char) => char.charCodeAt(0));

  const sniExtension: number[] = [];
  sniExtension.push(0x00, 0x00); // extension type: server_name
  const listLength = nameBytes.length + 3;
  const extensionLength = listLength + 2;
  sniExtension.push((extensionLength >> 8) & 0xff, extensionLength & 0xff);
  sniExtension.push((listLength >> 8) & 0xff, listLength & 0xff);
  sniExtension.push(0x00); // name type: host_name
  sniExtension.push((nameBytes.length >> 8) & 0xff, nameBytes.length & 0xff);
  sniExtension.push(...nameBytes);

  const body: number[] = [];
  body.push(0x03, 0x03); // client version TLS 1.2
  body.push(...new Array(32).fill(0x11)); // random
  body.push(0x00); // session id length
  body.push(0x00, 0x02, 0x13, 0x01); // cipher suites
  body.push(0x01, 0x00); // compression methods
  body.push((sniExtension.length >> 8) & 0xff, sniExtension.length & 0xff);
  body.push(...sniExtension);

  const handshakeMessage: number[] = [];
  handshakeMessage.push(0x01); // ClientHello
  handshakeMessage.push((body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff);
  handshakeMessage.push(...body);

  const record: number[] = [];
  record.push(0x16, 0x03, 0x01);
  record.push((handshakeMessage.length >> 8) & 0xff, handshakeMessage.length & 0xff);
  record.push(...handshakeMessage);

  return new Uint8Array(record);
}

export const scenarios = {
  normalConnection,
  threeWayTeardown,
  resetConnection,
  synNoResponse,
  connectionRefused,
  retransmission,
  fastRetransmission,
  outOfOrder,
  zeroWindow,
  midStreamConnection,
  portReuse,
  synRetransmission,
  dnsAndSni,
  linuxCookedCapture,
  vlanTagged,
  macosTunnelCapture,
};
