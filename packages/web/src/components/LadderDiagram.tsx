import { Fragment } from 'react';
import type {
  AppSpan,
  Connection,
  ConnectionPacket,
  HttpMessage,
  HttpTransaction,
} from '@tcpview/core';
import { anomalyLabel, formatDuration } from '@tcpview/core';

const HEADER_HEIGHT = 52;
// 人话注解是这个工具的核心价值，布局优先保证它完整可见。
// 实测最长注解约 410px、最长序号行约 321px，下面的取值使两者都有余量。
const LEFT_LANE = 140;
const RIGHT_LANE = 470;
const BADGE_X = RIGHT_LANE + 38;
const BADGE_WIDTH = 54;

interface Props {
  connection: Connection;
  selectedPacketIndex: number | null;
  onSelectPacket: (packetIndex: number | null) => void;
}

/**
 * 时序梯形图：左客户端、右服务端、纵轴时间。
 *
 * 手写 SVG 而不用图表库，因为需要完全控制布局——箭头方向、标志位、序号、时间差、
 * 人话注解、异常高亮要挤在同一行里且互不遮挡，通用图表库做不到。
 *
 * 报文正文不在这里渲染：SVG 没有文本流式布局，换行要自己算。
 * 这里只负责标出「这个包承载了报文的哪一段」，正文由 HttpTransactions 用 HTML 渲染。
 *
 * 泳道表头是独立的一张 SVG 并吸顶：工作台里这一栏能滚几千像素，
 * 表头跟着滚走的话，滚到中段就不知道左右两条生命线各是谁了。
 * 吸顶元素只锁纵向，横向仍跟着内容走，所以表头始终对齐在生命线正上方。
 */
export function LadderDiagram({ connection, selectedPacketIndex, onSelectPacket }: Props) {
  // 有应用层注解时每行要多放一行字，行高与注解起始位置都跟着变
  const hasAppLayer = connection.packets.some((packet) => packet.appNote !== null);
  const rowHeight = hasAppLayer ? 80 : 62;
  const noteX = hasAppLayer ? BADGE_X + BADGE_WIDTH + 10 : RIGHT_LANE + 38;
  const canvasWidth = noteX + 570;

  const bodyHeight = connection.packets.length * rowHeight + 16;

  return (
    <div className="ladder">
      <div className="ladder-head" style={{ width: canvasWidth }}>
        <svg width={canvasWidth} height={HEADER_HEIGHT} role="presentation">
          <text x={LEFT_LANE} y={20} className="lane-title" textAnchor="middle">
            客户端
          </text>
          <text x={LEFT_LANE} y={38} className="lane-sub" textAnchor="middle">
            {connection.clientAddr}:{connection.clientPort}
          </text>
          <text x={RIGHT_LANE} y={20} className="lane-title" textAnchor="middle">
            服务端
          </text>
          <text x={RIGHT_LANE} y={38} className="lane-sub" textAnchor="middle">
            {connection.serverAddr}:{connection.serverPort}
          </text>

          {/* 生命线在表头里探出一小截，和下面的正文接上 */}
          <line x1={LEFT_LANE} y1={42} x2={LEFT_LANE} y2={HEADER_HEIGHT} className="lifeline" />
          <line x1={RIGHT_LANE} y1={42} x2={RIGHT_LANE} y2={HEADER_HEIGHT} className="lifeline" />
        </svg>
      </div>

      <svg width={canvasWidth} height={bodyHeight} role="img" aria-label="TCP 时序图">
        {/* 两侧的生命线 */}
        <line x1={LEFT_LANE} y1={0} x2={LEFT_LANE} y2={bodyHeight - 8} className="lifeline" />
        <line x1={RIGHT_LANE} y1={0} x2={RIGHT_LANE} y2={bodyHeight - 8} className="lifeline" />

        {connection.packets.map((packet, index) => (
          <PacketRow
            key={`${packet.packetIndex}-${index}`}
            packet={packet}
            y={index * rowHeight + rowHeight / 2}
            rowHeight={rowHeight}
            noteX={noteX}
            canvasWidth={canvasWidth}
            seqBaseEstimated={connection.quality.seqBaseEstimated}
            transaction={
              packet.appSpan
                ? (connection.http?.transactions[packet.appSpan.transactionIndex - 1] ?? null)
                : null
            }
            selected={selectedPacketIndex === packet.packetIndex}
            onSelect={onSelectPacket}
          />
        ))}
      </svg>
    </div>
  );
}

interface RowProps {
  packet: ConnectionPacket;
  y: number;
  rowHeight: number;
  noteX: number;
  canvasWidth: number;
  seqBaseEstimated: boolean;
  transaction: HttpTransaction | null;
  selected: boolean;
  onSelect: (packetIndex: number | null) => void;
}

function PacketRow({
  packet,
  y,
  rowHeight,
  noteX,
  canvasWidth,
  seqBaseEstimated,
  transaction,
  selected,
  onSelect,
}: RowProps) {
  const toRight = packet.direction === 'c2s';
  const startX = toRight ? LEFT_LANE : RIGHT_LANE;
  const endX = toRight ? RIGHT_LANE : LEFT_LANE;

  const severity = worstSeverity(packet);
  const arrowClass = `arrow ${severity}`;
  const clickable = packet.appSpan !== null;

  // 有应用层注解时它占掉第一行，异常注解顺次下移
  const anomalyBaseline = packet.appNote ? y + 30 : y + 13;

  return (
    <Fragment>
      {/* 整行的点击热区。只有承载了报文的包才可选——纯 ACK 点了也没有正文可高亮 */}
      <rect
        x={0}
        y={y - rowHeight / 2}
        width={canvasWidth}
        height={rowHeight}
        className={`row-hit ${selected ? 'selected' : ''} ${clickable ? 'clickable' : ''}`}
        onClick={() => clickable && onSelect(selected ? null : packet.packetIndex)}
      />

      {/* 时间列 */}
      <text x={12} y={y + 4} className="time-cell">
        +{formatDuration(packet.offsetMicros)}
      </text>
      {packet.deltaMicros > 0 && (
        <text x={12} y={y + 20} className="delta-cell">
          Δ {formatDuration(packet.deltaMicros)}
        </text>
      )}
      <text x={12} y={y + 36} className="index-cell">
        #{packet.packetIndex}
      </text>

      <line x1={startX} y1={y} x2={endX} y2={y} className={arrowClass} />
      <polygon points={arrowHead(endX, y, toRight)} className={`arrow-head ${severity}`} />

      {/* 标志位与序号：贴在箭头上方 */}
      <text x={(LEFT_LANE + RIGHT_LANE) / 2} y={y - 22} className="flags" textAnchor="middle">
        {packet.flags.join(' · ') || '（无标志位）'}
      </text>
      <text x={(LEFT_LANE + RIGHT_LANE) / 2} y={y - 7} className="seq" textAnchor="middle">
        {formatSeq(packet, seqBaseEstimated)}
      </text>

      {packet.appSpan && <AppBadge span={packet.appSpan} transaction={transaction} y={y} />}

      {/* 人话注解 */}
      <text x={noteX} y={y - 4} className="note">
        {packet.note}
      </text>
      {packet.appNote && (
        <text x={noteX} y={y + 14} className={`app-note ${appNoteTone(packet.appSpan)}`}>
          {packet.appNote}
        </text>
      )}
      {packet.anomalies.map((anomaly, i) => (
        <text
          key={anomaly.kind}
          x={noteX}
          y={anomalyBaseline + i * 15}
          className={`anomaly-note ${anomalyLabel(anomaly.kind).tone}`}
        >
          ⚠ {anomalyLabel(anomaly.kind).text}：{anomaly.detail}
        </text>
      ))}
    </Fragment>
  );
}

/** 一眼看出这个包在报文里的角色，不用读完整句注解 */
function AppBadge({
  span,
  transaction,
  y,
}: {
  span: AppSpan;
  transaction: HttpTransaction | null;
  y: number;
}) {
  const { text, tone } = badgeContent(span, transaction);

  return (
    <Fragment>
      <rect
        x={BADGE_X}
        y={y - 11}
        width={BADGE_WIDTH}
        height={22}
        rx={4}
        className={`app-badge-box ${tone}`}
      />
      <text
        x={BADGE_X + BADGE_WIDTH / 2}
        y={y + 4}
        className={`app-badge-text ${tone}`}
        textAnchor="middle"
      >
        {text}
      </text>
    </Fragment>
  );
}

function badgeContent(
  span: AppSpan,
  transaction: HttpTransaction | null,
): { text: string; tone: string } {
  if (span.duplicate) return { text: '重复', tone: 'dup' };

  if (span.part === 'start-line' || span.part === 'mixed') {
    const message = messageAt(transaction, span);
    if (span.messageKind === 'request') {
      return { text: message?.method ?? '请求', tone: 'start' };
    }
    const status = message?.statusCode;
    return { text: status === undefined ? '响应' : String(status), tone: 'start' };
  }

  return { text: '…续', tone: 'cont' };
}

/**
 * 找出这个包到底承载的是事务里的哪一条消息。
 *
 * 一个事务可能有多条响应——`100 Continue` 之类的中间响应和正式响应同属一个事务。
 * 直接取 `transaction.response` 的话，承载 100 Continue 的那一行会被标成「200」，
 * 和它自己那句「100 Continue 的响应头在这个包里」当场打架。
 */
function messageAt(transaction: HttpTransaction | null, span: AppSpan): HttpMessage | null {
  if (!transaction) return null;

  const candidates =
    span.messageKind === 'request'
      ? [transaction.request]
      : [...transaction.informationalResponses, transaction.response];

  for (const message of candidates) {
    if (message && span.streamFrom >= message.streamStart && span.streamFrom < message.streamEnd) {
      return message;
    }
  }
  // 落在任何消息区间之外（重传等）时退回第一条，至少方向是对的
  return candidates.find((message): message is HttpMessage => message != null) ?? null;
}

function appNoteTone(span: AppSpan | null): string {
  if (!span) return '';
  if (span.duplicate) return 'dup';
  return span.part === 'start-line' || span.part === 'mixed' ? 'start' : '';
}

/**
 * 序号同时给出相对值和原始值。
 * 相对值让人看得懂（从 0 开始数），原始值让人能跟 Wireshark 对照。
 * 基准为估算时用 ≈ 替掉 =（而不是追加），否则 seq=≈0 会看成 seq==0。
 */
function formatSeq(packet: ConnectionPacket, estimated: boolean): string {
  const parts: string[] = [];
  const eq = estimated ? '≈' : '=';

  parts.push(`seq${eq}${packet.relSeq ?? '?'} (${packet.rawSeq})`);
  if (packet.relAck !== null) {
    parts.push(`ack${eq}${packet.relAck} (${packet.rawAck})`);
  }
  if (packet.payloadLength > 0) {
    parts.push(`len=${packet.payloadLength}`);
  }
  if (packet.scaledWindow !== null) {
    parts.push(`win=${packet.scaledWindow}`);
  } else {
    parts.push(`win=${packet.window}?`);
  }
  return parts.join('  ');
}

function arrowHead(x: number, y: number, toRight: boolean): string {
  const size = 7;
  return toRight
    ? `${x},${y} ${x - size},${y - size / 1.6} ${x - size},${y + size / 1.6}`
    : `${x},${y} ${x + size},${y - size / 1.6} ${x + size},${y + size / 1.6}`;
}

function worstSeverity(packet: ConnectionPacket): string {
  if (packet.flags.includes('RST')) return 'bad';
  let severity = 'normal';
  for (const anomaly of packet.anomalies) {
    const tone = anomalyLabel(anomaly.kind).tone;
    if (tone === 'bad') return 'bad';
    if (tone === 'warn') severity = 'warn';
  }
  return severity;
}
