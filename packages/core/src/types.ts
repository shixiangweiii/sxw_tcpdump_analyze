/**
 * 全局数据模型。core 的所有产物都以这里的类型描述，server 直接序列化为 JSON，
 * web 以 type-only import 复用，保证报告结构只有一个事实来源。
 */

// ---------------------------------------------------------------- 容器与解码

export type CaptureFormat = 'pcap' | 'pcapng';

/** 从 pcap/pcapng 容器里读出来的一个原始帧，尚未解码链路层。 */
export interface RawPacket {
  /** 抓包顺序，从 0 开始 */
  index: number;
  /** 绝对时间戳，单位微秒。2026 年的 epoch 微秒约 1.8e15，仍在 Number 安全整数范围内 */
  tsMicros: number;
  /** 实际写入文件的字节数（可能被 snaplen 截断） */
  capturedLength: number;
  /** 线路上的原始长度 */
  originalLength: number;
  linkType: number;
  data: Uint8Array;
}

export interface Ipv4Info {
  version: 4;
  src: string;
  dst: string;
  protocol: number;
  ttl: number;
  /** 是否为分片（MF 置位或偏移非 0）。本工具只标记不重组 */
  fragmented: boolean;
  fragmentOffset: number;
}

export interface Ipv6Info {
  version: 6;
  src: string;
  dst: string;
  protocol: number;
  ttl: number;
  fragmented: boolean;
  fragmentOffset: number;
}

export type NetworkInfo = Ipv4Info | Ipv6Info;

export interface TcpFlags {
  fin: boolean;
  syn: boolean;
  rst: boolean;
  psh: boolean;
  ack: boolean;
  urg: boolean;
  ece: boolean;
  cwr: boolean;
}

export interface TcpOptions {
  mss?: number;
  /** 窗口缩放指数。真实窗口 = window << windowScale，仅在握手中协商 */
  windowScale?: number;
  sackPermitted?: boolean;
  timestamps?: { tsval: number; tsecr: number };
}

export interface TcpInfo {
  kind: 'tcp';
  srcPort: number;
  dstPort: number;
  seq: number;
  ack: number;
  flags: TcpFlags;
  window: number;
  headerLength: number;
  payloadLength: number;
  options: TcpOptions;
}

export interface UdpInfo {
  kind: 'udp';
  srcPort: number;
  dstPort: number;
  payloadLength: number;
}

export type TransportInfo = TcpInfo | UdpInfo;

/** 一个完整解码后的包。payload 只在流式处理期间短暂持有，不会进入最终报告。 */
export interface DecodedPacket {
  index: number;
  tsMicros: number;
  capturedLength: number;
  originalLength: number;
  network?: NetworkInfo;
  transport?: TransportInfo;
  /** 传输层载荷，仅供 DNS / TLS / HTTP 嗅探使用，用完即弃 */
  payload?: Uint8Array;
}

// ---------------------------------------------------------------- host 解析

export type HostNameSource = 'dns' | 'sni' | 'http-host';

/** 一条「域名 → IP」的证据。界面据此解释「为什么这个 IP 属于这个域名」 */
export interface HostNameEvidence {
  name: string;
  source: HostNameSource;
  /** 首次观察到这条证据的包序号 */
  firstSeenPacket: number;
  /** 该证据被观察到的次数 */
  observations: number;
}

export interface HostEntry {
  address: string;
  ipVersion: 4 | 6;
  names: HostNameEvidence[];
  tcpPackets: number;
  udpPackets: number;
  /** UDP/443，几乎可以确定是 QUIC/HTTP3 */
  quicPackets: number;
  otherPackets: number;
  connectionCount: number;
}

// ---------------------------------------------------------------- 连接与包

export type Direction = 'c2s' | 's2c';

export type AnomalyKind =
  | 'retransmission'
  | 'fast-retransmission'
  | 'suspected-out-of-order'
  | 'zero-window'
  | 'window-update'
  | 'duplicate-ack'
  | 'lost-segment'
  | 'keep-alive';

export interface Anomaly {
  kind: AnomalyKind;
  /** 面向新手的中文说明 */
  detail: string;
}

export interface ConnectionPacket {
  /** 对应全局抓包序号，方便与 Wireshark 对照 */
  packetIndex: number;
  tsMicros: number;
  /** 相对连接第一个包的偏移（微秒） */
  offsetMicros: number;
  /** 与本连接上一个包的间隔（微秒） */
  deltaMicros: number;
  direction: Direction;
  flags: string[];
  rawSeq: number;
  rawAck: number;
  /** 相对序号。基准未知时为 null */
  relSeq: number | null;
  relAck: number | null;
  payloadLength: number;
  /** TCP 头里的原始窗口字段 */
  window: number;
  /** 应用缩放因子后的真实窗口。缩放因子未知时为 null */
  scaledWindow: number | null;
  anomalies: Anomaly[];
  /** 人话注解，例如「客户端发起建连，起始编号 0」 */
  note: string;
}

export type ConnectionOutcome =
  | 'established-closed'
  | 'established-reset'
  | 'established-open'
  | 'failed-no-response'
  | 'failed-refused'
  | 'handshake-missing';

export type ClosureReason = 'fin' | 'rst' | 'none';

export interface ConnectionStats {
  packetCount: number;
  byteCount: number;
  clientBytes: number;
  serverBytes: number;
  retransmissions: number;
  fastRetransmissions: number;
  suspectedOutOfOrder: number;
  zeroWindowEvents: number;
  duplicateAcks: number;
  lostSegments: number;
}

export interface ConnectionQuality {
  /** 握手是否被完整捕获。false 时序号基准与窗口大小均不可靠 */
  handshakeCaptured: boolean;
  /** 相对序号基准是否为估算值（未捕获 SYN 时以首包 seq 兜底） */
  seqBaseEstimated: boolean;
  /** 是否知道窗口缩放因子。未知时窗口大小无法换算（但零窗口仍可判定） */
  windowScaleKnown: boolean;
  /** 客户端/服务端角色是否为推断而非由 SYN 确定 */
  rolesInferred: boolean;
}

export interface Connection {
  id: string;
  clientAddr: string;
  clientPort: number;
  serverAddr: string;
  serverPort: number;
  ipVersion: 4 | 6;
  /** 同一四元组被复用时递增，从 1 开始 */
  generation: number;
  firstTsMicros: number;
  lastTsMicros: number;
  durationMicros: number;
  outcome: ConnectionOutcome;
  closureReason: ClosureReason;
  /** 握手往返时间估算（SYN → SYN-ACK），未捕获握手时为 null */
  handshakeRttMicros: number | null;
  quality: ConnectionQuality;
  stats: ConnectionStats;
  packets: ConnectionPacket[];
}

// ---------------------------------------------------------------- 分析产物

export interface DecodeWarning {
  reason: string;
  count: number;
  /** 首个触发该告警的包序号 */
  firstPacket: number;
}

export interface CaptureInfo {
  format: CaptureFormat;
  linkTypes: number[];
  linkTypeNames: string[];
  packetCount: number;
  /** 成功解码到 IP 层的包数 */
  decodedPackets: number;
  firstTsMicros: number | null;
  lastTsMicros: number | null;
  durationMicros: number;
  warnings: DecodeWarning[];
  /** 文件被截断（最后一个包不完整）时为 true */
  truncated: boolean;
}

export interface AnalysisResult {
  capture: CaptureInfo;
  hosts: HostEntry[];
  connections: Connection[];
}

/** 针对某个 host 过滤后的视图 */
export interface HostView {
  /** 用户输入的原始查询串 */
  query: string;
  /** 查询命中的 IP 集合 */
  matchedAddresses: string[];
  /** 命中该 host 的域名（若查询本身是域名） */
  matchedNames: string[];
  /** host 在这批连接里主要扮演的角色，决定界面文案是「发往」还是「来自」 */
  perspective: 'host-as-server' | 'host-as-client' | 'mixed';
  connections: Connection[];
  /** 与该 host 相关但不是 TCP 的流量，用于兜底提示 */
  nonTcp: { udpPackets: number; quicPackets: number; otherPackets: number };
}
