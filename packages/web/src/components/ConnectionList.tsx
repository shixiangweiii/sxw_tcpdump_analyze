import { useEffect, useMemo, useState } from 'react';
import type { Connection, ConnectionOutcome } from '@tcpview/core';
import { formatBytes, formatDuration, outcomeLabel } from '@tcpview/core';
import type { ConnectionsResponse, ConnectionSummary } from '../api';
import { HttpTransactions } from './HttpTransactions';
import { LadderDiagram } from './LadderDiagram';

interface Props {
  view: ConnectionsResponse;
  expandedId: string | null;
  expanded: Connection | null;
  loadingId: string | null;
  onToggle: (connectionId: string) => void;
}

type Filter = 'all' | ConnectionOutcome | 'has-anomaly';

const FILTERS: { key: Filter; text: string }[] = [
  { key: 'all', text: '全部' },
  { key: 'has-anomaly', text: '只看有异常的' },
  { key: 'established-closed', text: '正常关闭' },
  { key: 'established-reset', text: '被 RST 中断' },
  { key: 'established-open', text: '仍在连接中' },
  { key: 'failed-no-response', text: 'SYN 无响应' },
  { key: 'failed-refused', text: '被拒绝' },
  { key: 'handshake-missing', text: '握手未捕获' },
];

export function ConnectionList({ view, expandedId, expanded, loadingId, onToggle }: Props) {
  const [filter, setFilter] = useState<Filter>('all');

  const connections = useMemo(() => {
    if (filter === 'all') return view.connections;
    if (filter === 'has-anomaly') return view.connections.filter(hasAnomaly);
    return view.connections.filter((connection) => connection.outcome === filter);
  }, [view.connections, filter]);

  const available = useMemo(() => {
    const present = new Set(view.connections.map((connection) => connection.outcome));
    return FILTERS.filter(
      (item) =>
        item.key === 'all' ||
        (item.key === 'has-anomaly' && view.connections.some(hasAnomaly)) ||
        present.has(item.key as ConnectionOutcome),
    );
  }, [view.connections]);

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
                onClick={() => setFilter(item.key)}
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
                  expanded={expandedId === connection.id}
                  loading={loadingId === connection.id}
                  onToggle={() => onToggle(connection.id)}
                />
                {expandedId === connection.id && expanded && (
                  <ConnectionDetail connection={expanded} />
                )}
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

/**
 * 展开后的连接详情。
 *
 * 顺序是有讲究的：先说结论可不可信，再给 HTTP 报文（大多数人只看这个），
 * 最后才是逐包时序图。选中的包由这里持有，梯形图和报文正文共享同一个高亮状态。
 */
function ConnectionDetail({ connection }: { connection: Connection }) {
  const [selectedPacket, setSelectedPacket] = useState<number | null>(null);

  // 换一条连接时上一条的选中项必须清掉，否则会高亮到不相干的位置
  useEffect(() => setSelectedPacket(null), [connection.id]);

  const selectedSpan = useMemo(() => {
    if (selectedPacket === null) return null;
    return (
      connection.packets.find((packet) => packet.packetIndex === selectedPacket)?.appSpan ?? null
    );
  }, [connection.packets, selectedPacket]);

  return (
    <div className="detail">
      <QualityNotes connection={connection} />

      {connection.http ? (
        <HttpTransactions http={connection.http} selectedSpan={selectedSpan} />
      ) : (
        <NonHttpNotice connection={connection} />
      )}

      <LadderDiagram
        connection={connection}
        selectedPacketIndex={selectedPacket}
        onSelectPacket={setSelectedPacket}
      />
    </div>
  );
}

/** 解不出报文时说清楚是为什么，而不是什么都不显示让人以为工具坏了 */
function NonHttpNotice({ connection }: { connection: Connection }) {
  if (connection.stats.byteCount === 0) return null;

  const reason =
    connection.appProtocol === 'tls'
      ? '这条连接跑的是 TLS（HTTPS），内容是加密的，看不到明文报文。'
      : !connection.quality.handshakeCaptured
        ? '抓包开始时这条连接已经在传输中了，看不到报文的开头，无法还原应用层内容。'
        : '没有识别出应用层协议，本工具目前只能还原明文 HTTP/1.x 的报文。';

  return <div className="alert info http-none">{reason}</div>;
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
  expanded: boolean;
  loading: boolean;
  onToggle: () => void;
}

function ConnectionRow({ connection, expanded, loading, onToggle }: RowProps) {
  const label = outcomeLabel(connection.outcome);

  return (
    <button className={`row ${expanded ? 'expanded' : ''}`} onClick={onToggle}>
      <span className="row-caret">{loading ? '⏳' : expanded ? '▾' : '▸'}</span>

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
  const tone = status === null ? 'warn' : status >= 500 ? 'bad' : status >= 400 ? 'warn' : 'ok';
  const text = [summary.firstLine, status === null ? '无响应' : `→ ${status}`]
    .filter(Boolean)
    .join(' ');

  return (
    <span className={`chip ${tone}`} title="展开可以看到完整的请求与响应报文">
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

/** 把「这条连接的结论有多可信」明确写出来，而不是让用户以为所有数字都是准的 */
function QualityNotes({ connection }: { connection: Connection }) {
  const notes: string[] = [];

  if (!connection.quality.handshakeCaptured) {
    notes.push('抓包开始时这条连接就已经存在，没看到握手过程。');
  }
  if (connection.quality.seqBaseEstimated) {
    notes.push('序号基准是用抓到的第一个包估算的，下面带 ≈ 的相对序号只表示「相对抓包起点」，不是连接真实的起始位置。');
  }
  if (!connection.quality.windowScaleKnown) {
    notes.push('窗口缩放因子在握手里协商，没抓到握手就无法换算真实窗口大小，带 ? 的窗口值仅为原始字段（零窗口的判定不受影响）。');
  }
  if (connection.quality.rolesInferred) {
    notes.push('没有 SYN 可依据，客户端与服务端的角色是根据端口号推断的，有可能反了。');
  }

  if (notes.length === 0) return null;

  return (
    <div className="alert warn quality">
      <strong>关于这条连接的可信度：</strong>
      <ul>
        {notes.map((note) => (
          <li key={note}>{note}</li>
        ))}
      </ul>
    </div>
  );
}

function hasAnomaly(connection: ConnectionSummary): boolean {
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
