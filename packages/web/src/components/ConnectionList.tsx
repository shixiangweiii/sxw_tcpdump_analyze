import { useMemo } from 'react';
import { formatBytes, formatDuration, outcomeLabel } from '@tcpview/core';
import type { ConnectionsResponse, ConnectionSummary } from '../api';
import { availableFilters, type Filter } from '../connection-filter';

interface Props {
  view: ConnectionsResponse;
  /** 已按 filter 过滤好的连接。过滤在 App 里做，工作台翻页要跟随同一份顺序 */
  connections: ConnectionSummary[];
  filter: Filter;
  onFilterChange: (filter: Filter) => void;
  activeId: string | null;
  loadingId: string | null;
  onOpen: (connectionId: string) => void;
}

export function ConnectionList({
  view,
  connections,
  filter,
  onFilterChange,
  activeId,
  loadingId,
  onOpen,
}: Props) {
  const available = useMemo(() => availableFilters(view.connections), [view.connections]);

  return (
    <div className="connection-list">
      <PerspectiveBanner view={view} />

      {view.connections.length === 0 ? (
        <div className="empty-state">
          <p>这个 host 上没有找到任何 TCP 连接。</p>
          {view.nonTcp.quicPackets > 0 && (
            <p className="muted">
              但它有 {view.nonTcp.quicPackets} 个 QUIC 包——流量走的是 HTTP/3，本工具目前只分析 TCP。
            </p>
          )}
        </div>
      ) : (
        <>
          <div className="filters">
            {available.map((item) => (
              <button
                key={item.key}
                className={`filter ${filter === item.key ? 'active' : ''}`}
                onClick={() => onFilterChange(item.key)}
              >
                {item.text}
              </button>
            ))}
          </div>

          <div className="rows">
            {connections.map((connection) => (
              <div key={connection.id} className="row-wrap">
                <ConnectionRow
                  connection={connection}
                  active={activeId === connection.id}
                  loading={loadingId === connection.id}
                  onOpen={() => onOpen(connection.id)}
                />
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

function PerspectiveBanner({ view }: { view: ConnectionsResponse }) {
  const target = view.matchedNames.length > 0 ? view.matchedNames.join('、') : view.query;
  const addresses = view.matchedAddresses.join('、');

  // 抓包位置决定了同一个查询的含义，所以把推断结果直接写出来，而不是让用户自己想
  const description =
    view.perspective === 'host-as-client'
      ? `来自 ${target} 的 ${view.connections.length} 条连接`
      : view.perspective === 'mixed'
        ? `与 ${target} 相关的 ${view.connections.length} 条连接（它既做过客户端也做过服务端）`
        : `发往 ${target} 的 ${view.connections.length} 条连接`;

  return (
    <div className="perspective">
      <div className="perspective-main">正在查看：{description}</div>
      {addresses && <div className="perspective-sub">命中的 IP：{addresses}</div>}
      {view.nonTcp.quicPackets > 0 && (
        <div className="alert info">
          该 host 还有 {view.nonTcp.quicPackets} 个 UDP/QUIC 包，本工具当前只分析 TCP。
        </div>
      )}
    </div>
  );
}

interface RowProps {
  connection: ConnectionSummary;
  /** 刚从工作台返回时标出上次看的是哪一条 */
  active: boolean;
  loading: boolean;
  onOpen: () => void;
}

function ConnectionRow({ connection, active, loading, onOpen }: RowProps) {
  const label = outcomeLabel(connection.outcome);

  return (
    <button className={`row ${active ? 'active' : ''}`} onClick={onOpen}>
      <span className="row-caret">{loading ? '⏳' : '›'}</span>

      <span className="row-endpoints">
        <span className="endpoint">
          {connection.clientAddr}:{connection.clientPort}
        </span>
        <span className="arrow-glyph">→</span>
        <span className="endpoint">
          {connection.serverAddr}:{connection.serverPort}
        </span>
        {connection.generation > 1 && (
          <span className="chip" title="同一组端口被重复使用，这是第几次">
            第 {connection.generation} 次复用
          </span>
        )}
      </span>

      <span className={`badge ${label.tone}`} title={label.hint}>
        {label.text}
      </span>

      <HttpChip connection={connection} />

      <span className="row-stats">
        <span>{connection.stats.packetCount} 包</span>
        <span>{formatBytes(connection.stats.byteCount)}</span>
        <span>{formatDuration(connection.durationMicros)}</span>
        {connection.handshakeRttMicros !== null && (
          <span title="握手往返时间，反映到对端的网络延迟">
            RTT {formatDuration(connection.handshakeRttMicros)}
          </span>
        )}
      </span>

      <span className="row-anomalies">
        <AnomalyChips connection={connection} />
      </span>
    </button>
  );
}

/**
 * 不展开也能看出这条连接干了什么，这是列表里最有用的一列。
 * 外层 span 必须无条件渲染：.row 是固定列数的 grid，少一个子元素后面的列就会错位。
 */
function HttpChip({ connection }: { connection: ConnectionSummary }) {
  return <span className="row-app">{renderChip(connection)}</span>;
}

function renderChip(connection: ConnectionSummary) {
  if (connection.appProtocol === 'tls') {
    return (
      <span className="chip" title="HTTPS 流量，内容加密，看不到明文报文">
        TLS
      </span>
    );
  }

  const summary = connection.httpSummary;
  if (!summary) return null;

  const status = summary.statusCode;
  // 「没收到响应」和「收到了但状态行解不出来」是两回事，不能都说成无响应
  const outcome = !summary.responded ? '无响应' : status === null ? '响应无法解析' : `→ ${status}`;
  const tone =
    !summary.responded || status === null
      ? 'warn'
      : status >= 500
        ? 'bad'
        : status >= 400
          ? 'warn'
          : 'ok';
  const text = [summary.firstLine, outcome].filter(Boolean).join(' ');

  return (
    <span className={`chip ${tone}`} title="点开可以看到完整的请求与响应报文">
      {text}
      {summary.transactionCount > 1 && ` 等 ${summary.transactionCount} 个请求`}
    </span>
  );
}

function AnomalyChips({ connection }: { connection: ConnectionSummary }) {
  const { stats } = connection;
  const chips: { text: string; tone: string }[] = [];

  if (stats.retransmissions > 0) chips.push({ text: `重传 ${stats.retransmissions}`, tone: 'bad' });
  if (stats.fastRetransmissions > 0)
    chips.push({ text: `快速重传 ${stats.fastRetransmissions}`, tone: 'bad' });
  if (stats.zeroWindowEvents > 0)
    chips.push({ text: `零窗口 ${stats.zeroWindowEvents}`, tone: 'bad' });
  if (stats.suspectedOutOfOrder > 0)
    chips.push({ text: `疑似乱序 ${stats.suspectedOutOfOrder}`, tone: 'warn' });
  if (stats.duplicateAcks > 0)
    chips.push({ text: `重复确认 ${stats.duplicateAcks}`, tone: 'warn' });
  if (stats.lostSegments > 0)
    chips.push({ text: `丢包 ${stats.lostSegments}`, tone: 'warn' });

  if (chips.length === 0) return <span className="chip ok">无异常</span>;

  return (
    <>
      {chips.map((chip) => (
        <span key={chip.text} className={`chip ${chip.tone}`}>
          {chip.text}
        </span>
      ))}
    </>
  );
}
