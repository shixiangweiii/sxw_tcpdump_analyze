import type { AnomalyKind, ConnectionOutcome } from '../types.js';

export interface OutcomeLabel {
  /** 徽章上的短标签 */
  text: string;
  /** 悬浮时的详细解释 */
  hint: string;
  tone: 'good' | 'warn' | 'bad' | 'neutral';
}

const OUTCOME_LABELS: Record<ConnectionOutcome, OutcomeLabel> = {
  'established-closed': {
    text: '建连成功 · 正常关闭',
    hint: '三次握手建立，双方都发过 FIN 完成挥手，这是最健康的形态',
    tone: 'good',
  },
  'established-reset': {
    text: '建连成功 · 被 RST 中断',
    hint: '连接建立后被一方用 RST 直接掐断，没有走正常挥手流程',
    tone: 'bad',
  },
  'established-open': {
    text: '建连成功 · 仍在连接中',
    hint: '抓包结束时连接还开着，可能是长连接或连接池，不一定有问题',
    tone: 'neutral',
  },
  'failed-no-response': {
    text: '建连失败 · SYN 无响应',
    hint: '客户端发了 SYN 但服务端一直没回，通常是对端不可达、被防火墙丢弃或服务端过载',
    tone: 'bad',
  },
  'failed-refused': {
    text: '建连失败 · 被拒绝',
    hint: '服务端直接回了 RST，说明这个端口上没有程序在监听',
    tone: 'bad',
  },
  'handshake-missing': {
    text: '握手未捕获',
    hint: '抓包开始时这条连接就已经存在了，看不到握手过程，序号基准与窗口大小都不可靠',
    tone: 'warn',
  },
};

export function outcomeLabel(outcome: ConnectionOutcome): OutcomeLabel {
  return OUTCOME_LABELS[outcome];
}

export interface AnomalyLabel {
  text: string;
  tone: 'warn' | 'bad' | 'neutral';
}

const ANOMALY_LABELS: Record<AnomalyKind, AnomalyLabel> = {
  retransmission: { text: '重传', tone: 'bad' },
  'fast-retransmission': { text: '快速重传', tone: 'bad' },
  'suspected-out-of-order': { text: '疑似乱序', tone: 'warn' },
  'zero-window': { text: '零窗口', tone: 'bad' },
  'window-update': { text: '窗口恢复', tone: 'neutral' },
  'duplicate-ack': { text: '重复确认', tone: 'warn' },
  'lost-segment': { text: '有包没抓到', tone: 'warn' },
  'keep-alive': { text: '保活探测', tone: 'neutral' },
};

export function anomalyLabel(kind: AnomalyKind): AnomalyLabel {
  return ANOMALY_LABELS[kind];
}

/** 时间的人类可读形式，自动选择单位 */
export function formatDuration(micros: number): string {
  const abs = Math.abs(micros);
  if (abs < 1000) return `${micros}μs`;
  if (abs < 1_000_000) return `${(micros / 1000).toFixed(2)}ms`;
  return `${(micros / 1_000_000).toFixed(3)}s`;
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}
