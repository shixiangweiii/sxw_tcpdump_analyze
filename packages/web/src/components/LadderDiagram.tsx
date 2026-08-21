import { Fragment } from 'react';
import type { Connection, ConnectionPacket } from '@tcpview/core';
import { anomalyLabel, formatDuration } from '@tcpview/core';

const ROW_HEIGHT = 62;
const HEADER_HEIGHT = 56;
// 人话注解是这个工具的核心价值，布局优先保证它完整可见。
// 实测最长注解约 410px、最长序号行约 321px，下面的取值使两者都有余量。
const LEFT_LANE = 140;
const RIGHT_LANE = 470;
const NOTE_X = RIGHT_LANE + 38;
const CANVAS_WIDTH = 1040;

interface Props {
  connection: Connection;
}

/**
 * 时序梯形图：左客户端、右服务端、纵轴时间。
 *
 * 手写 SVG 而不用图表库，因为需要完全控制布局——箭头方向、标志位、序号、时间差、
 * 人话注解、异常高亮要挤在同一行里且互不遮挡，通用图表库做不到。
 */
export function LadderDiagram({ connection }: Props) {
  const height = HEADER_HEIGHT + connection.packets.length * ROW_HEIGHT + 30;

  return (
    <div className="ladder">
      <svg width={CANVAS_WIDTH} height={height} role="img" aria-label="TCP 时序图">
        {/* 两侧的生命线 */}
        <line x1={LEFT_LANE} y1={HEADER_HEIGHT - 18} x2={LEFT_LANE} y2={height - 16} className="lifeline" />
        <line x1={RIGHT_LANE} y1={HEADER_HEIGHT - 18} x2={RIGHT_LANE} y2={height - 16} className="lifeline" />

        <text x={LEFT_LANE} y={22} className="lane-title" textAnchor="middle">
          客户端
        </text>
        <text x={LEFT_LANE} y={40} className="lane-sub" textAnchor="middle">
          {connection.clientAddr}:{connection.clientPort}
        </text>
        <text x={RIGHT_LANE} y={22} className="lane-title" textAnchor="middle">
          服务端
        </text>
        <text x={RIGHT_LANE} y={40} className="lane-sub" textAnchor="middle">
          {connection.serverAddr}:{connection.serverPort}
        </text>

        {connection.packets.map((packet, index) => (
          <PacketRow
            key={`${packet.packetIndex}-${index}`}
            packet={packet}
            y={HEADER_HEIGHT + index * ROW_HEIGHT}
            seqBaseEstimated={connection.quality.seqBaseEstimated}
          />
        ))}
      </svg>
    </div>
  );
}

interface RowProps {
  packet: ConnectionPacket;
  y: number;
  seqBaseEstimated: boolean;
}

function PacketRow({ packet, y, seqBaseEstimated }: RowProps) {
  const toRight = packet.direction === 'c2s';
  const startX = toRight ? LEFT_LANE : RIGHT_LANE;
  const endX = toRight ? RIGHT_LANE : LEFT_LANE;

  const severity = worstSeverity(packet);
  const arrowClass = `arrow ${severity}`;

  return (
    <Fragment>
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
      <text
        x={(LEFT_LANE + RIGHT_LANE) / 2}
        y={y - 22}
        className="flags"
        textAnchor="middle"
      >
        {packet.flags.join(' · ') || '（无标志位）'}
      </text>
      <text
        x={(LEFT_LANE + RIGHT_LANE) / 2}
        y={y - 7}
        className="seq"
        textAnchor="middle"
      >
        {formatSeq(packet, seqBaseEstimated)}
      </text>

      {/* 人话注解 */}
      <text x={NOTE_X} y={y - 4} className="note">
        {packet.note}
      </text>
      {packet.anomalies.map((anomaly, i) => (
        <text
          key={anomaly.kind}
          x={NOTE_X}
          y={y + 13 + i * 15}
          className={`anomaly-note ${anomalyLabel(anomaly.kind).tone}`}
        >
          ⚠ {anomalyLabel(anomaly.kind).text}：{anomaly.detail}
        </text>
      ))}
    </Fragment>
  );
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
