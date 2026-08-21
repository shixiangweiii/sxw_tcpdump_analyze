import type { Connection } from '@tcpview/core';
import { anomalyLabel } from '@tcpview/core';
import { directionText, formatSeq } from '../packet-text';

interface Props {
  connection: Connection;
  /** 已播放（已落笔）的包数。0 表示已进入演示但还没开播 */
  playedCount: number;
}

/**
 * 演示模式的「当前包信息条」：每一步都在这里讲当前这个包——
 * flags、序号、窗口、人话注解。
 *
 * 不分包类型、每步都显示：TLS / 非 HTTP 连接的右栏没有正文可联动，
 * 这里是有且仅有的讲解内容；HTTP 连接则由选中联动在下方正文里补出对应段落。
 * 落笔时才更新——飞行中的图标自带 flags，发送时刻的反馈已经有了。
 */
export function DemoInfoBar({ connection, playedCount }: Props) {
  const total = connection.packets.length;
  const packet = playedCount > 0 ? (connection.packets[playedCount - 1] ?? null) : null;

  return (
    <div className="demo-info">
      {packet === null ? (
        <div className="demo-info-note">
          已就绪：点击「播放下一包」开始逐包重放，这条连接共 {total} 个包。
        </div>
      ) : (
        <>
          <div className="demo-info-head">
            <span className="demo-info-pos">
              第 {playedCount} / {total} 包
            </span>
            <span className="demo-info-index">#{packet.packetIndex}</span>
            <span className="demo-info-dir">{directionText(packet.direction)}</span>
            <span className="demo-info-flags">
              {packet.flags.join(' · ') || '（无标志位）'}
            </span>
          </div>

          <code className="demo-info-seq">
            {formatSeq(packet, connection.quality.seqBaseEstimated)}
          </code>

          <div className="demo-info-note">{packet.note}</div>
          {packet.appNote && <div className="demo-info-app">{packet.appNote}</div>}
          {packet.anomalies.map((anomaly) => (
            <div
              key={anomaly.kind}
              className={`demo-info-anomaly ${anomalyLabel(anomaly.kind).tone}`}
            >
              ⚠ {anomalyLabel(anomaly.kind).text}：{anomaly.detail}
            </div>
          ))}
        </>
      )}
    </div>
  );
}
