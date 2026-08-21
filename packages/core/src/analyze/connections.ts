import type {
  AppProtocol,
  Connection,
  ConnectionOutcome,
  ConnectionPacket,
  ClosureReason,
  Direction,
  HttpAnalysis,
  HttpSummary,
  NetworkInfo,
  TcpInfo,
} from '../types.js';
import { flagNames } from '../decode/transport.js';
import { sniffAppProtocol } from '../decode/http.js';
import { createDirectionState, detectAnomalies, type DirectionState } from './anomaly.js';
import { analyzeHttp } from './http-analysis.js';
import type { StreamSegment } from './reassemble.js';
import { describePacket } from './notes.js';

/**
 * 还没认出协议之前，每个方向最多先缓存这么多字节。
 *
 * 不能只看每个方向第一个到达的数据包：真实抓包里服务端先到的是流的第 4195 字节，
 * HTTP 响应头在第 3 个到达的包里。这个预算就是给乱序留的兜底。
 */
const SNIFF_BUDGET = 32 * 1024;

/** 认定是 HTTP 之后，每条连接最多保留这么多载荷 */
const HTTP_RETAIN_CAP = 1024 * 1024;

/** 连接上的载荷缓存。只对可能是 HTTP 的连接保留，其余即用即弃 */
interface AppCapture {
  protocol: AppProtocol;
  /** 已经下过结论，不用再嗅探 */
  decided: boolean;
  client: StreamSegment[];
  server: StreamSegment[];
  clientSniffBudget: number;
  serverSniffBudget: number;
  retainedBytes: number;
  capped: boolean;
}

interface MutableConnection {
  key: string;
  generation: number;
  clientAddr: string;
  clientPort: number;
  serverAddr: string;
  serverPort: number;
  ipVersion: 4 | 6;
  rolesInferred: boolean;

  client: DirectionState;
  server: DirectionState;

  sawClientSyn: boolean;
  sawServerSynAck: boolean;
  sawHandshakeAck: boolean;
  clientFin: boolean;
  serverFin: boolean;
  sawRst: boolean;

  synTsMicros: number | null;
  synAckTsMicros: number | null;

  firstTsMicros: number;
  lastTsMicros: number;
  packets: ConnectionPacket[];
  /** 双方都完成挥手或出现 RST 后置位，用于识别端口复用 */
  closed: boolean;
  appCapture: AppCapture;
}

/**
 * 按四元组把包归拢成连接，并推进 TCP 状态机。
 * 必须按抓包顺序逐包喂入。
 */
export class ConnectionTracker {
  private readonly active = new Map<string, MutableConnection>();
  private readonly finished: MutableConnection[] = [];
  private readonly generations = new Map<string, number>();

  add(
    packetIndex: number,
    tsMicros: number,
    network: NetworkInfo,
    tcp: TcpInfo,
    payload?: Uint8Array,
  ): void {
    const key = canonicalKey(network.src, tcp.srcPort, network.dst, tcp.dstPort);
    const isPureSyn = tcp.flags.syn && !tcp.flags.ack;

    let connection = this.active.get(key);

    if (connection && isPureSyn) {
      const senderIsClient =
        network.src === connection.clientAddr && tcp.srcPort === connection.clientPort;
      // 同一个 ISN 的 SYN 是重传，不同 ISN 或连接已关闭则是端口被复用
      const isSynRetransmit =
        senderIsClient && connection.sawClientSyn && connection.client.isn === tcp.seq;

      if (!isSynRetransmit) {
        this.retire(key, connection);
        connection = undefined;
      }
    }

    if (!connection) {
      connection = this.create(key, tsMicros, network, tcp);
      this.active.set(key, connection);
    }

    this.append(connection, packetIndex, tsMicros, network, tcp, payload);
  }

  finish(): Connection[] {
    for (const [key, connection] of this.active) {
      this.finished.push(connection);
      this.active.delete(key);
    }
    return this.finished
      .sort((a, b) => a.firstTsMicros - b.firstTsMicros)
      .map((connection) => materialize(connection));
  }

  private retire(key: string, connection: MutableConnection): void {
    this.finished.push(connection);
    this.active.delete(key);
  }

  private create(
    key: string,
    tsMicros: number,
    network: NetworkInfo,
    tcp: TcpInfo,
  ): MutableConnection {
    const generation = (this.generations.get(key) ?? 0) + 1;
    this.generations.set(key, generation);

    const roles = determineRoles(network, tcp);

    return {
      key,
      generation,
      ...roles,
      ipVersion: network.version,
      client: createDirectionState(),
      server: createDirectionState(),
      sawClientSyn: false,
      sawServerSynAck: false,
      sawHandshakeAck: false,
      clientFin: false,
      serverFin: false,
      sawRst: false,
      synTsMicros: null,
      synAckTsMicros: null,
      firstTsMicros: tsMicros,
      lastTsMicros: tsMicros,
      packets: [],
      closed: false,
      appCapture: {
        protocol: 'unknown',
        decided: false,
        client: [],
        server: [],
        clientSniffBudget: SNIFF_BUDGET,
        serverSniffBudget: SNIFF_BUDGET,
        retainedBytes: 0,
        capped: false,
      },
    };
  }

  private append(
    connection: MutableConnection,
    packetIndex: number,
    tsMicros: number,
    network: NetworkInfo,
    tcp: TcpInfo,
    payload?: Uint8Array,
  ): void {
    const direction: Direction =
      network.src === connection.clientAddr && tcp.srcPort === connection.clientPort
        ? 'c2s'
        : 's2c';
    const self = direction === 'c2s' ? connection.client : connection.server;
    const peer = direction === 'c2s' ? connection.server : connection.client;

    // ---- 序号基准 ----
    // SYN 的序号就是 ISN，是唯一可靠的基准。抓不到 SYN 时退而用该方向首包序号，
    // 此时相对序号只是「相对抓包起点」，必须标记为估算值。
    if (self.isn === null) {
      const isOwnSyn = tcp.flags.syn && (direction === 'c2s' ? !tcp.flags.ack : true);
      self.isn = tcp.seq;
      self.isnEstimated = !isOwnSyn;
    }
    // 缩放因子只在握手中协商。-1 表示「看到了 SYN 但没带该选项」，null 表示「压根没抓到 SYN」，
    // 两者含义不同：前者说明不缩放，后者说明窗口大小无从换算。
    if (tcp.flags.syn && self.windowScale === null) {
      self.windowScale = tcp.options.windowScale ?? -1;
    }

    const relSeq = wrapSub(tcp.seq, self.isn);
    const relAck = tcp.flags.ack && peer.isn !== null ? wrapSub(tcp.ack, peer.isn) : null;

    // ---- 状态机 ----
    const wasEstablished = connection.sawServerSynAck;
    let isHandshakeAck = false;

    if (tcp.flags.syn && !tcp.flags.ack && direction === 'c2s') {
      connection.sawClientSyn = true;
      if (connection.synTsMicros === null) connection.synTsMicros = tsMicros;
    } else if (tcp.flags.syn && tcp.flags.ack && direction === 's2c') {
      if (!connection.sawServerSynAck) {
        connection.sawServerSynAck = true;
        connection.synAckTsMicros = tsMicros;
      }
    } else if (
      !connection.sawHandshakeAck &&
      connection.sawServerSynAck &&
      direction === 'c2s' &&
      tcp.flags.ack &&
      !tcp.flags.syn &&
      !tcp.flags.fin &&
      !tcp.flags.rst &&
      tcp.payloadLength === 0
    ) {
      connection.sawHandshakeAck = true;
      isHandshakeAck = true;
    }

    if (tcp.flags.fin) {
      if (direction === 'c2s') connection.clientFin = true;
      else connection.serverFin = true;
    }
    if (tcp.flags.rst) {
      connection.sawRst = true;
      connection.closed = true;
    }
    if (connection.clientFin && connection.serverFin) {
      connection.closed = true;
    }

    // ---- 异常检测 ----
    const anomalies = detectAnomalies({ tcp, tsMicros, relSeq, relAck, self, peer });

    if (payload && payload.length > 0) {
      retainPayload(connection.appCapture, direction, relSeq, payload, packetIndex, tsMicros);
    }

    const previous = connection.packets[connection.packets.length - 1];
    const scale = effectiveWindowScale(self, peer);

    connection.packets.push({
      packetIndex,
      tsMicros,
      offsetMicros: tsMicros - connection.firstTsMicros,
      deltaMicros: previous ? tsMicros - previous.tsMicros : 0,
      direction,
      flags: flagNames(tcp.flags),
      rawSeq: tcp.seq,
      rawAck: tcp.ack,
      relSeq,
      relAck,
      payloadLength: tcp.payloadLength,
      window: tcp.window,
      // SYN 包自身的窗口永远不缩放，缩放要等握手结束才生效
      scaledWindow: tcp.flags.syn ? tcp.window : scale === null ? null : tcp.window * 2 ** scale,
      anomalies,
      note: describePacket({
        direction,
        tcp,
        relSeq,
        relAck,
        isHandshakeAck,
        established: wasEstablished,
      }),
      // 应用层视角要等流重组完才知道，先占位，materialize 时回填
      appNote: null,
      appSpan: null,
    });

    connection.lastTsMicros = tsMicros;
  }
}

/**
 * 决定要不要留下这个包的载荷。
 *
 * 现有设计是「载荷即用即弃，内存与连接数相关而与文件大小无关」，展示报文必须打破它，
 * 所以只对可能是 HTTP 的连接保留，并且两头都设上限：
 * 认出协议前每方向 32KB，认出之后每条连接 1MB。TLS 一眼就能否掉，代价接近零。
 */
function retainPayload(
  capture: AppCapture,
  direction: Direction,
  relSeq: number,
  payload: Uint8Array,
  packetIndex: number,
  tsMicros: number,
): void {
  if (capture.decided && capture.protocol !== 'http1') return;

  if (capture.protocol !== 'http1') {
    const verdict = sniffAppProtocol(payload, direction);

    if (verdict === 'tls') {
      capture.protocol = 'tls';
      capture.decided = true;
      capture.client = [];
      capture.server = [];
      capture.retainedBytes = 0;
      return;
    }

    if (verdict === 'http1') {
      capture.protocol = 'http1';
      capture.decided = true;
    } else {
      // 还没认出来：花预算先存着，等后面的包再看。预算耗尽仍无结论就放弃这条连接
      const budget = direction === 'c2s' ? capture.clientSniffBudget : capture.serverSniffBudget;
      if (budget <= 0) {
        if (capture.clientSniffBudget <= 0 && capture.serverSniffBudget <= 0) {
          capture.protocol = 'unknown';
          capture.decided = true;
          capture.client = [];
          capture.server = [];
          capture.retainedBytes = 0;
        }
        return;
      }
      if (direction === 'c2s') capture.clientSniffBudget -= payload.length;
      else capture.serverSniffBudget -= payload.length;
    }
  }

  if (capture.retainedBytes + payload.length > HTTP_RETAIN_CAP) {
    capture.capped = true;
    return;
  }

  // 必须复制：payload 是整个抓包文件 buffer 的 subarray，
  // 直接留住会让一个几十字节的片段把整份 pcap 钉在内存里
  const bytes = payload.slice();
  capture.retainedBytes += bytes.length;
  (direction === 'c2s' ? capture.client : capture.server).push({
    relSeq,
    bytes,
    packetIndex,
    tsMicros,
  });
}

/**
 * 窗口缩放必须双方在握手里都声明才生效，只有一方声明等于没有。
 * 返回 null 表示握手没抓全、无从判断，此时窗口数值不可信（但零窗口仍可判定，
 * 因为 0 左移多少位都还是 0）。
 */
function effectiveWindowScale(self: DirectionState, peer: DirectionState): number | null {
  if (self.windowScale === null || peer.windowScale === null) return null;
  if (self.windowScale < 0 || peer.windowScale < 0) return 0;
  return self.windowScale;
}

/**
 * 「发 SYN 的一方是客户端」这条规则在客户端机器、k8s pod、nginx 服务端三种抓包位置下都成立，
 * 所以不需要让用户配置视角。只有连接残缺（抓不到握手）时才需要靠端口号猜。
 */
function determineRoles(
  network: NetworkInfo,
  tcp: TcpInfo,
): Pick<
  MutableConnection,
  'clientAddr' | 'clientPort' | 'serverAddr' | 'serverPort' | 'rolesInferred'
> {
  if (tcp.flags.syn && !tcp.flags.ack) {
    return {
      clientAddr: network.src,
      clientPort: tcp.srcPort,
      serverAddr: network.dst,
      serverPort: tcp.dstPort,
      rolesInferred: false,
    };
  }
  if (tcp.flags.syn && tcp.flags.ack) {
    return {
      clientAddr: network.dst,
      clientPort: tcp.dstPort,
      serverAddr: network.src,
      serverPort: tcp.srcPort,
      rolesInferred: false,
    };
  }

  // 残缺连接：服务端通常监听知名端口或低端口，客户端用临时端口
  const srcIsLikelyServer = looksLikeServerPort(tcp.srcPort, tcp.dstPort);
  if (srcIsLikelyServer) {
    return {
      clientAddr: network.dst,
      clientPort: tcp.dstPort,
      serverAddr: network.src,
      serverPort: tcp.srcPort,
      rolesInferred: true,
    };
  }
  return {
    clientAddr: network.src,
    clientPort: tcp.srcPort,
    serverAddr: network.dst,
    serverPort: tcp.dstPort,
    rolesInferred: true,
  };
}

function looksLikeServerPort(candidate: number, other: number): boolean {
  if (candidate < 1024 && other >= 1024) return true;
  if (other < 1024 && candidate >= 1024) return false;
  if (candidate < 32768 && other >= 32768) return true;
  if (other < 32768 && candidate >= 32768) return false;
  return candidate < other;
}

function materialize(connection: MutableConnection): Connection {
  const outcome = determineOutcome(connection);
  const closureReason: ClosureReason = connection.sawRst
    ? 'rst'
    : connection.clientFin || connection.serverFin
      ? 'fin'
      : 'none';

  let clientBytes = 0;
  let serverBytes = 0;
  let retransmissions = 0;
  let fastRetransmissions = 0;
  let suspectedOutOfOrder = 0;
  let zeroWindowEvents = 0;
  let duplicateAcks = 0;
  let lostSegments = 0;

  for (const packet of connection.packets) {
    if (packet.direction === 'c2s') clientBytes += packet.payloadLength;
    else serverBytes += packet.payloadLength;

    for (const anomaly of packet.anomalies) {
      switch (anomaly.kind) {
        case 'retransmission':
          retransmissions += 1;
          break;
        case 'fast-retransmission':
          fastRetransmissions += 1;
          break;
        case 'suspected-out-of-order':
          suspectedOutOfOrder += 1;
          break;
        case 'zero-window':
          zeroWindowEvents += 1;
          break;
        case 'duplicate-ack':
          duplicateAcks += 1;
          break;
        case 'lost-segment':
          lostSegments += 1;
          break;
        default:
          break;
      }
    }
  }

  const handshakeCaptured = connection.sawClientSyn && connection.sawServerSynAck;

  let appProtocol = connection.appCapture.protocol;
  let http: HttpAnalysis | null = null;
  let httpSummary: HttpSummary | null = null;

  if (appProtocol === 'http1') {
    const result = analyzeHttp({
      clientSegments: connection.appCapture.client,
      serverSegments: connection.appCapture.server,
      handshakeCaptured,
      clientClosed: connection.clientFin,
      serverClosed: connection.serverFin,
      payloadCapped: connection.appCapture.capped,
      packets: connection.packets,
    });

    if (result.analysis.transactions.length === 0) {
      // 签名命中了却一条消息都解不出来，说明判断有误，不硬报成 HTTP
      appProtocol = 'unknown';
    } else {
      http = result.analysis;
      httpSummary = result.summary;
      for (const packet of connection.packets) {
        packet.appSpan = result.spans.get(packet.packetIndex) ?? null;
        packet.appNote = result.notes.get(packet.packetIndex) ?? null;
      }
    }
  }

  return {
    id: `${connection.key}#${connection.generation}`,
    clientAddr: connection.clientAddr,
    clientPort: connection.clientPort,
    serverAddr: connection.serverAddr,
    serverPort: connection.serverPort,
    ipVersion: connection.ipVersion,
    generation: connection.generation,
    firstTsMicros: connection.firstTsMicros,
    lastTsMicros: connection.lastTsMicros,
    durationMicros: connection.lastTsMicros - connection.firstTsMicros,
    outcome,
    closureReason,
    handshakeRttMicros:
      connection.synTsMicros !== null && connection.synAckTsMicros !== null
        ? connection.synAckTsMicros - connection.synTsMicros
        : null,
    quality: {
      handshakeCaptured,
      seqBaseEstimated: connection.client.isnEstimated || connection.server.isnEstimated,
      // 双方的 SYN 都抓到才知道该不该缩放，与 effectiveWindowScale 的判据保持一致
      windowScaleKnown:
        connection.client.windowScale !== null && connection.server.windowScale !== null,
      rolesInferred: connection.rolesInferred,
    },
    stats: {
      packetCount: connection.packets.length,
      byteCount: clientBytes + serverBytes,
      clientBytes,
      serverBytes,
      retransmissions,
      fastRetransmissions,
      suspectedOutOfOrder,
      zeroWindowEvents,
      duplicateAcks,
      lostSegments,
    },
    appProtocol,
    http,
    httpSummary,
    packets: connection.packets,
  };
}

function determineOutcome(connection: MutableConnection): ConnectionOutcome {
  // 抓包开始时连接就已存在：既没有 SYN 也没有 SYN-ACK，无法判断建连过程
  if (!connection.sawClientSyn && !connection.sawServerSynAck) {
    return 'handshake-missing';
  }

  if (!connection.sawServerSynAck) {
    return connection.sawRst ? 'failed-refused' : 'failed-no-response';
  }

  if (connection.sawRst) return 'established-reset';
  // 三包挥手（FIN 与 ACK 合并）同样满足「双方都发过 FIN」，不能按包数硬匹配四次
  if (connection.clientFin && connection.serverFin) return 'established-closed';
  return 'established-open';
}

function canonicalKey(a: string, portA: number, b: string, portB: number): string {
  const left = `${a}:${portA}`;
  const right = `${b}:${portB}`;
  return left < right ? `${left}-${right}` : `${right}-${left}`;
}

/** 序号是 32 位循环计数，相减后必须回到无符号 32 位 */
function wrapSub(value: number, base: number | null): number {
  if (base === null) return 0;
  return (value - base) >>> 0;
}
