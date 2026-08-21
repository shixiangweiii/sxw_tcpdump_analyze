import type { ConnectionOutcome } from '@tcpview/core';
import type { ConnectionSummary } from './api';

/**
 * 连接列表的筛选规则。
 *
 * 单独成模块是因为工作台的「上一条 / 下一条」必须跟随筛选后的顺序——
 * 筛掉的连接不该被翻页翻出来。列表和工作台由此共用同一份定义，
 * 而不是各自维护一套会悄悄跑偏的判断。
 */
export type Filter = 'all' | ConnectionOutcome | 'has-anomaly';

export const FILTERS: { key: Filter; text: string }[] = [
  { key: 'all', text: '全部' },
  { key: 'has-anomaly', text: '只看有异常的' },
  { key: 'established-closed', text: '正常关闭' },
  { key: 'established-reset', text: '被 RST 中断' },
  { key: 'established-open', text: '仍在连接中' },
  { key: 'failed-no-response', text: 'SYN 无响应' },
  { key: 'failed-refused', text: '被拒绝' },
  { key: 'handshake-missing', text: '握手未捕获' },
];

export function hasAnomaly(connection: ConnectionSummary): boolean {
  const s = connection.stats;
  return (
    s.retransmissions +
      s.fastRetransmissions +
      s.suspectedOutOfOrder +
      s.zeroWindowEvents +
      s.duplicateAcks +
      s.lostSegments >
    0
  );
}

export function applyFilter(
  connections: ConnectionSummary[],
  filter: Filter,
): ConnectionSummary[] {
  if (filter === 'all') return connections;
  if (filter === 'has-anomaly') return connections.filter(hasAnomaly);
  return connections.filter((connection) => connection.outcome === filter);
}

/** 只列出这批连接里真的存在的筛选项，避免点了就空的按钮 */
export function availableFilters(connections: ConnectionSummary[]) {
  const present = new Set(connections.map((connection) => connection.outcome));
  return FILTERS.filter(
    (item) =>
      item.key === 'all' ||
      (item.key === 'has-anomaly' && connections.some(hasAnomaly)) ||
      present.has(item.key as ConnectionOutcome),
  );
}
