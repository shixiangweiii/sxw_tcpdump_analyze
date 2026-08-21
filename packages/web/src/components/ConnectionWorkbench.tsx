import { useCallback, useEffect, useMemo, useState } from 'react';
import type { Connection } from '@tcpview/core';
import { formatBytes, formatDuration, outcomeLabel } from '@tcpview/core';
import { DemoInfoBar } from './DemoInfoBar';
import { HttpTransactions } from './HttpTransactions';
import { LadderDiagram } from './LadderDiagram';

interface Props {
  connection: Connection;
  /** 在筛选后的列表里排第几条，用于「上一条 / 下一条」 */
  position: { index: number; total: number };
  loading: boolean;
  error: string | null;
  onNavigate: (delta: number) => void;
  onClose: () => void;
}

/**
 * 动态演示的状态机。单步播放：每点一次「播放」让一个包从发送端飞到接收端
 * （flyingIndex），飞完落笔（playedCount +1）。选中包由 playedCount 派生，
 * 不单独存——避免落笔时「图上落了笔、选中却还是上一个」的中间态。
 */
interface DemoState {
  active: boolean;
  playedCount: number;
  flyingIndex: number | null;
}

const DEMO_OFF: DemoState = { active: false, playedCount: 0, flyingIndex: null };

/**
 * 单条连接的分析工作台。
 *
 * 之所以是整页而不是列表里的展开项：梯形图和报文都是高度无上限的东西，
 * 挤在同一个页面滚动条里，就会出现「在梯形图底部点一个包，高亮却在几千像素之上」。
 * 整页之后两栏各占满视口高度、各自独立滚动，点哪一行报文就在旁边。
 *
 * 左右次序按因果排：左边梯形图是点的地方，右边报文是点出来的结果。
 */
export function ConnectionWorkbench({
  connection,
  position,
  loading,
  error,
  onNavigate,
  onClose,
}: Props) {
  const [selectedPacket, setSelectedPacket] = useState<number | null>(null);
  const [demo, setDemo] = useState(DEMO_OFF);

  // 换一条连接时上一条的选中项和演示进度必须清掉，否则会高亮/播放到不相干的位置
  useEffect(() => {
    setSelectedPacket(null);
    setDemo(DEMO_OFF);
  }, [connection.id]);

  const packetCount = connection.packets.length;

  const enterDemo = useCallback(() => {
    setDemo({ active: true, playedCount: 0, flyingIndex: null });
    // 进演示时清掉静态模式留下的选中，退出后不让旧高亮凭空回来
    setSelectedPacket(null);
  }, []);

  // 重播就是从头再进一次
  const replayDemo = enterDemo;

  const stepDemo = useCallback(() => {
    setDemo((prev) =>
      !prev.active || prev.flyingIndex !== null || prev.playedCount >= packetCount
        ? prev
        : { ...prev, flyingIndex: prev.playedCount },
    );
  }, [packetCount]);

  // 落笔只改 demo 状态，选中包在下面按 playedCount 派生。
  // 函数式更新自带防护：重播/退出抢先发生时 flyingIndex 已被作废，这里直接跳过
  const handleFlightEnd = useCallback(() => {
    setDemo((prev) =>
      !prev.active || prev.flyingIndex === null
        ? prev
        : { active: true, flyingIndex: null, playedCount: prev.flyingIndex + 1 },
    );
  }, []);

  const exitDemo = useCallback(() => {
    setDemo(DEMO_OFF);
    setSelectedPacket(null);
  }, []);

  // 演示中选中 = 最后落笔的那个包；静态模式回到用户手点的那套逻辑
  const demoSelectedPacket =
    demo.active && demo.playedCount > 0
      ? (connection.packets[demo.playedCount - 1]?.packetIndex ?? null)
      : null;
  const effectiveSelected = demo.active ? demoSelectedPacket : selectedPacket;

  // 没有路由，浏览器后退键退出的是整个 session 而不是这一页，所以至少留一个 Esc。
  // 演示模式下 Esc 先退演示，再按一次才退这一页
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      if (demo.active) exitDemo();
      else onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [demo.active, exitDemo, onClose]);

  const selectedSpan = useMemo(() => {
    if (effectiveSelected === null) return null;
    return (
      connection.packets.find((packet) => packet.packetIndex === effectiveSelected)?.appSpan ?? null
    );
  }, [connection.packets, effectiveSelected]);

  const label = outcomeLabel(connection.outcome);

  return (
    <div className="workbench">
      <header className="workbench-head">
        <button className="link" onClick={onClose}>
          ← 返回列表
        </button>

        <span className="workbench-endpoints">
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

        <span className="workbench-stats">
          <span>{connection.stats.packetCount} 包</span>
          <span>{formatBytes(connection.stats.byteCount)}</span>
          <span>{formatDuration(connection.durationMicros)}</span>
          {connection.handshakeRttMicros !== null && (
            <span title="握手往返时间，反映到对端的网络延迟">
              RTT {formatDuration(connection.handshakeRttMicros)}
            </span>
          )}
        </span>

        {demo.active ? (
          <span className="workbench-demo">
            <button
              className="demo-btn"
              onClick={stepDemo}
              disabled={demo.flyingIndex !== null || demo.playedCount >= packetCount}
              title={
                demo.playedCount >= packetCount ? '已播完，可重播或退出' : '播放下一个包'
              }
            >
              ▶ 播放下一包
            </button>
            <button className="demo-btn" onClick={replayDemo} title="回到第一个包重新演示">
              ↺ 重播
            </button>
            <button className="demo-btn" onClick={exitDemo} title="退出演示（Esc）">
              ✕ 退出演示
            </button>
          </span>
        ) : (
          <span className="workbench-demo">
            <button
              className="demo-btn"
              onClick={enterDemo}
              disabled={packetCount === 0}
              title="收起梯形图，从头逐包重放这条连接"
            >
              ▶ 动态演示
            </button>
          </span>
        )}

        <span className="workbench-nav">
          <button
            className="nav-btn"
            onClick={() => onNavigate(-1)}
            disabled={loading || position.index <= 0}
            title="上一条连接"
          >
            ‹
          </button>
          <span className="nav-pos">
            {position.index + 1} / {position.total}
          </span>
          <button
            className="nav-btn"
            onClick={() => onNavigate(1)}
            disabled={loading || position.index >= position.total - 1}
            title="下一条连接"
          >
            ›
          </button>
        </span>
      </header>

      {error && <div className="alert error workbench-error">{error}</div>}

      {/*
        key 让两栏在换连接时整体重挂载。少了它，滚动位置会跟着 DOM 留在原地——
        翻到下一条连接，梯形图却停在上一条滚到的几百像素处，开头的握手直接看不见。
        顺带把报文栏的折叠状态也复位到第一个事务。
      */}
      <div className={`workbench-panes ${loading ? 'loading' : ''}`} key={connection.id}>
        <section className="workbench-pane pane-ladder">
          <LadderDiagram
            connection={connection}
            selectedPacketIndex={effectiveSelected}
            onSelectPacket={setSelectedPacket}
            demo={
              demo.active
                ? { playedCount: demo.playedCount, flyingIndex: demo.flyingIndex }
                : null
            }
            onFlightEnd={handleFlightEnd}
          />
        </section>

        <section className="workbench-pane pane-messages">
          {demo.active && <DemoInfoBar connection={connection} playedCount={demo.playedCount} />}

          <QualityNotes connection={connection} />

          {connection.http ? (
            <HttpTransactions http={connection.http} selectedSpan={selectedSpan} />
          ) : (
            <NonHttpNotice connection={connection} />
          )}
        </section>
      </div>
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
