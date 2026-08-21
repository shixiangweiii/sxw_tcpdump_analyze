import type { Anomaly, TcpInfo } from '../types.js';

/**
 * 判定乱序还是重传的时间阈值。
 *
 * 两者在包层面几乎无法严格区分：都是「序号往回退」。业界通行的启发式是看间隔——
 * 重排导致的回退发生在极短时间内，而真正的重传要等超时或三次重复 ACK。
 * Wireshark 用的也是同量级的阈值。因为是猜的，结论一律标「疑似」。
 */
const OUT_OF_ORDER_WINDOW_MICROS = 3_000;

/** RFC 5681 规定的快速重传触发条件：收到 3 个重复 ACK */
const FAST_RETRANSMIT_DUPACK_THRESHOLD = 3;

export interface DirectionState {
  /** 初始序号。未捕获 SYN 时以该方向首包序号兜底 */
  isn: number | null;
  isnEstimated: boolean;
  windowScale: number | null;
  /** 已发送数据的最高边界（相对序号） */
  maxNextRelSeq: number;
  /** 见过的 (相对序号:长度) → 最后一次出现时间，用于判重 */
  seen: Map<string, number>;
  lastAck: number | null;
  lastWindow: number | null;
  /** 连续重复 ACK 计数，供对端的快速重传判定使用 */
  dupAckRun: number;
  /** 该方向上一个包的时间 */
  lastTsMicros: number | null;
  /** 上一个包是否报告了零窗口，用于识别窗口恢复 */
  inZeroWindow: boolean;
}

export function createDirectionState(): DirectionState {
  return {
    isn: null,
    isnEstimated: false,
    windowScale: null,
    maxNextRelSeq: 0,
    seen: new Map(),
    lastAck: null,
    lastWindow: null,
    dupAckRun: 0,
    lastTsMicros: null,
    inZeroWindow: false,
  };
}

export interface AnomalyInput {
  tcp: TcpInfo;
  tsMicros: number;
  relSeq: number;
  relAck: number | null;
  /** 发送方向的状态 */
  self: DirectionState;
  /** 对端方向的状态 */
  peer: DirectionState;
}

/**
 * 检测单个包上的异常，并就地推进方向状态。
 * 必须按抓包顺序逐包调用。
 */
export function detectAnomalies(input: AnomalyInput): Anomaly[] {
  const { tcp, tsMicros, relSeq, relAck, self, peer } = input;
  const anomalies: Anomaly[] = [];

  // ---- 零窗口 ----
  // window 字段为 0 时，无论缩放因子是多少，真实窗口都是 0。
  // 所以即使没抓到握手（缩放因子未知），零窗口依然可以确定判定。
  if (tcp.window === 0 && !tcp.flags.rst && !tcp.flags.syn) {
    anomalies.push({
      kind: 'zero-window',
      detail: '接收窗口为 0，发送方已经收不下更多数据了，对端只能暂停发送',
    });
    self.inZeroWindow = true;
  } else if (self.inZeroWindow && tcp.window > 0 && tcp.payloadLength === 0) {
    anomalies.push({
      kind: 'window-update',
      detail: '接收窗口从 0 恢复，对端可以继续发送了',
    });
    self.inZeroWindow = false;
  } else if (tcp.window > 0) {
    self.inZeroWindow = false;
  }

  // ---- 重复 ACK ----
  // 纯 ACK、确认号没往前走、窗口也没变，且对端确实有数据在途，才算重复 ACK。
  // 少了「有数据在途」这个条件，空闲连接上的保活 ACK 会被误判。
  const isPureAck =
    tcp.flags.ack && tcp.payloadLength === 0 && !tcp.flags.syn && !tcp.flags.fin && !tcp.flags.rst;
  if (
    isPureAck &&
    relAck !== null &&
    self.lastAck !== null &&
    relAck === self.lastAck &&
    self.lastWindow === tcp.window &&
    peer.maxNextRelSeq > relAck
  ) {
    self.dupAckRun += 1;
    anomalies.push({
      kind: 'duplicate-ack',
      detail: `第 ${self.dupAckRun} 次重复确认同一位置，通常说明中间有数据没收到`,
    });
  } else if (isPureAck) {
    self.dupAckRun = 0;
  }
  if (relAck !== null) {
    self.lastAck = relAck;
  }
  self.lastWindow = tcp.window;

  // ---- 序号推进类异常 ----
  // SYN 和 FIN 各占用一个序号，计算边界时要算进去
  const consumed = tcp.payloadLength + (tcp.flags.syn ? 1 : 0) + (tcp.flags.fin ? 1 : 0);

  if (consumed > 0 && !tcp.flags.rst) {
    const segmentEnd = relSeq + consumed;
    const key = `${relSeq}:${consumed}`;
    const previousTs = self.seen.get(key);

    // 保活包：序号刻意退一格、载荷 0 或 1 字节，不是重传
    const isKeepAlive =
      tcp.payloadLength <= 1 &&
      !tcp.flags.syn &&
      !tcp.flags.fin &&
      self.maxNextRelSeq > 0 &&
      relSeq === self.maxNextRelSeq - 1;

    if (isKeepAlive) {
      anomalies.push({
        kind: 'keep-alive',
        detail: '保活探测包，用来确认连接还活着，不是异常',
      });
    } else if (relSeq > self.maxNextRelSeq && self.maxNextRelSeq > 0) {
      anomalies.push({
        kind: 'lost-segment',
        detail: `序号从 ${self.maxNextRelSeq} 跳到 ${relSeq}，中间 ${relSeq - self.maxNextRelSeq} 字节没有出现在抓包里`,
      });
    } else if (segmentEnd <= self.maxNextRelSeq) {
      // 整段都落在已经发过的区间里
      if (previousTs !== undefined) {
        const gap = tsMicros - previousTs;
        if (gap < OUT_OF_ORDER_WINDOW_MICROS) {
          anomalies.push({
            kind: 'suspected-out-of-order',
            detail: `与前一次相同内容只隔 ${formatMicros(gap)}，更像是网络重排而不是重传`,
          });
        } else if (peer.dupAckRun >= FAST_RETRANSMIT_DUPACK_THRESHOLD) {
          anomalies.push({
            kind: 'fast-retransmission',
            detail: `对端连续 ${peer.dupAckRun} 次重复确认后立即重发，属于快速重传`,
          });
        } else {
          anomalies.push({
            kind: 'retransmission',
            detail: `这段数据 ${formatMicros(gap)} 前发过一次，对方没确认，重发了`,
          });
        }
      } else {
        // 边界和之前发过的段对不上，比起重传更像重排
        anomalies.push({
          kind: 'suspected-out-of-order',
          detail: '序号比已发送的最高位置靠后退，疑似网络重排',
        });
      }
    }

    self.seen.set(key, tsMicros);
    self.maxNextRelSeq = Math.max(self.maxNextRelSeq, segmentEnd);
  }

  self.lastTsMicros = tsMicros;
  return anomalies;
}

function formatMicros(micros: number): string {
  if (micros < 1000) return `${micros}μs`;
  if (micros < 1_000_000) return `${(micros / 1000).toFixed(1)}ms`;
  return `${(micros / 1_000_000).toFixed(2)}s`;
}
