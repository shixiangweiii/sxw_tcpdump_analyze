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

// ---------------------------------------------------------------- 应用层（HTTP）

/**
 * 连接上跑的是什么应用层协议。
 * 只做能确定判断的三类：明文 HTTP/1.x、TLS（识别出来就跳过，不解密）、其余一律 unknown。
 */
export type AppProtocol = 'http1' | 'tls' | 'unknown';

export interface HttpHeader {
  name: string;
  value: string;
}

/** 正文的框定方式。决定「读多少字节算这条消息的正文」 */
export type HttpBodyFraming = 'content-length' | 'chunked' | 'until-close' | 'none';

export interface HttpBody {
  framing: HttpBodyFraming;
  /** 解块之后的真实字节数 */
  byteCount: number;
  /** 解码后的正文。二进制或被压缩时为 null */
  text: string | null;
  /** text 触及上限被截断 */
  truncated: boolean;
  /** 实际用于解码的字符集 */
  charset: string | null;
  /** 拿不到正文文本的原因，例如「Content-Encoding: gzip，本工具暂不解压」 */
  unavailableReason: string | null;
}

export interface HttpMessage {
  kind: 'request' | 'response';
  /** 这条消息在本方向流里的字节区间 [start, end) */
  streamStart: number;
  streamEnd: number;
  /** 起始行原文，例如 `GET / HTTP/1.1` */
  startLine: string;
  method?: string;
  target?: string;
  statusCode?: number;
  reasonPhrase?: string;
  httpVersion: string;
  headers: HttpHeader[];
  /** 起始行 + 头部 + 空行的总字节数 */
  headerByteCount: number;
  body: HttpBody | null;
  /** 承载这条消息第一个 / 最后一个字节的包序号（按流序，不是抓包序） */
  firstPacketIndex: number;
  lastPacketIndex: number;
  firstTsMicros: number;
  lastTsMicros: number;
  /** 消息是否完整。流里有洞、抓包提前结束、载荷保留触顶都会置 false */
  complete: boolean;
  incompleteReason: string | null;
}

/**
 * 一次请求-响应的耗时分解。这是内网排查最需要的东西——
 * 回答「慢在网络还是慢在服务端」，而不是只给一个总耗时。
 */
export interface HttpTiming {
  /** 请求最后一字节 → 服务端确认收到。约等于一个 RTT，反映链路 */
  requestAckedMicros: number | null;
  /** 请求最后一字节 → 响应第一字节。减去 RTT 就是服务端处理时间 */
  ttfbMicros: number | null;
  /** 响应第一字节 → 最后一字节。反映响应体传输 */
  responseTransferMicros: number | null;
  /** 请求最后一字节 → 响应最后一字节 */
  totalMicros: number | null;
}

export interface HttpTransaction {
  /** 连接内的第几个事务，从 1 开始 */
  index: number;
  request: HttpMessage | null;
  response: HttpMessage | null;
  timing: HttpTiming;
  /** 人话结论，例如「GET / → 200 OK，服务端处理 7.5ms」 */
  note: string;
}

export interface HttpQuality {
  /** 客户端 / 服务端方向的流是否完整（无洞、从流起点开始） */
  clientStreamComplete: boolean;
  serverStreamComplete: boolean;
  /** 流里没被抓到的区间 */
  gaps: { direction: Direction; from: number; to: number }[];
  /** 被判定为重复而丢弃的段数 */
  duplicateSegmentsDropped: number;
  /** 载荷保留触及上限，正文只有前一部分 */
  payloadCapped: boolean;
}

export interface HttpAnalysis {
  transactions: HttpTransaction[];
  quality: HttpQuality;
}

/** 连接列表用的轻量摘要，不含头部与正文，避免把列表响应撑爆 */
export interface HttpSummary {
  transactionCount: number;
  /** 第一个事务的请求行，例如 `GET /` */
  firstLine: string | null;
  /** 第一个事务的响应状态码 */
  statusCode: number | null;
}

/**
 * 一个包承载的应用层数据落在哪里。
 * 这是「点梯形图某一行 → 高亮它在报文里对应的那段」的依据。
 */
export interface AppSpan {
  transactionIndex: number;
  messageKind: 'request' | 'response';
  /** 这个包的数据落在消息的哪个部分 */
  part: 'start-line' | 'headers' | 'body' | 'mixed';
  /** 在本方向流里的字节区间 [from, to) */
  streamFrom: number;
  streamTo: number;
  /** 落在正文里时，对应解码后文本的字符区间；否则为 null */
  textFrom: number | null;
  textTo: number | null;
  /** 重传或重复数据，不参与流拼接 */
  duplicate: boolean;
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
  /** 应用层视角的补充注解，例如「响应正文第 1399~2797 字节」。非 HTTP 连接为 null */
  appNote: string | null;
  /** 这个包承载的应用层数据落在报文的哪一段。非 HTTP 或纯 ACK 时为 null */
  appSpan: AppSpan | null;
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
  /** 识别出的应用层协议 */
  appProtocol: AppProtocol;
  /** HTTP 解析结果。appProtocol 不是 http1 时为 null */
  http: HttpAnalysis | null;
  /** 供连接列表用的轻量摘要 */
  httpSummary: HttpSummary | null;
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
  /** 抓包接口名（如 en0 / utun4）。仅 pcapng 携带，经典 pcap 为空数组 */
  interfaceNames: string[];
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
