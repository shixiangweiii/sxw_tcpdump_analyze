import { useCallback, useLayoutEffect, useMemo, useRef, useState } from 'react';
import type { Connection } from '@tcpview/core';
import { formatBytes, formatDuration } from '@tcpview/core';
import {
  fetchConnection,
  fetchConnections,
  uploadCapture,
  type ConnectionsResponse,
  type UploadResponse,
} from './api';
import { applyFilter, type Filter } from './connection-filter';
import { UploadView } from './components/UploadView';
import { HostPicker } from './components/HostPicker';
import { ConnectionList } from './components/ConnectionList';
import { ConnectionWorkbench } from './components/ConnectionWorkbench';

export function App() {
  const [session, setSession] = useState<UploadResponse | null>(null);
  const [view, setView] = useState<ConnectionsResponse | null>(null);
  const [filter, setFilter] = useState<Filter>('all');
  const [activeId, setActiveId] = useState<string | null>(null);
  const [active, setActive] = useState<Connection | null>(null);
  const [loadingId, setLoadingId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // 工作台是整页视图，进去时列表的滚动位置会丢。退出来还得让人接着刚才那一行看
  const listScroll = useRef<number | null>(null);

  const connections = useMemo(
    () => (view ? applyFilter(view.connections, filter) : []),
    [view, filter],
  );

  const activeIndex = useMemo(
    () => connections.findIndex((connection) => connection.id === activeId),
    [connections, activeId],
  );

  const handleFile = useCallback(async (file: File) => {
    setBusy(true);
    setError(null);
    try {
      const response = await uploadCapture(file);
      setSession(response);
      setView(null);
      setFilter('all');
      setActiveId(null);
      setActive(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : '上传失败');
    } finally {
      setBusy(false);
    }
  }, []);

  const handleSelectHost = useCallback(
    async (host: string) => {
      if (!session) return;
      setBusy(true);
      setError(null);
      try {
        setView(await fetchConnections(session.sessionId, host));
        setFilter('all');
        setActiveId(null);
        setActive(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : '查询失败');
      } finally {
        setBusy(false);
      }
    },
    [session],
  );

  const open = useCallback(
    async (connectionId: string) => {
      if (!session) return;
      setLoadingId(connectionId);
      try {
        const connection = await fetchConnection(session.sessionId, connectionId);
        setActiveId(connectionId);
        setActive(connection);
        setError(null);
      } catch (err) {
        // 加载失败时停在原地：已经在工作台里的话，保住当前这条，不要把人踢回列表
        setError(err instanceof Error ? err.message : '加载连接详情失败');
      } finally {
        setLoadingId(null);
      }
    },
    [session],
  );

  const handleOpen = useCallback(
    (connectionId: string) => {
      listScroll.current = window.scrollY;
      void open(connectionId);
    },
    [open],
  );

  const handleNavigate = useCallback(
    (delta: number) => {
      const next = connections[activeIndex + delta];
      if (next) void open(next.id);
    },
    [connections, activeIndex, open],
  );

  // 只丢掉已加载的详情，activeId 留着——列表靠它标出「刚才看的是这条」
  const handleClose = useCallback(() => {
    setActive(null);
    setError(null);
  }, []);

  // 回到列表后再恢复滚动位置——要等列表重新挂载出高度，所以放在 layout effect 里
  useLayoutEffect(() => {
    if (active === null && listScroll.current !== null) {
      window.scrollTo(0, listScroll.current);
      listScroll.current = null;
    }
  }, [active]);

  if (!session) {
    return <UploadView onFile={handleFile} busy={busy} error={error} />;
  }

  if (activeId && active) {
    return (
      <ConnectionWorkbench
        connection={active}
        position={{ index: activeIndex, total: connections.length }}
        loading={loadingId !== null}
        error={error}
        onNavigate={handleNavigate}
        onClose={handleClose}
      />
    );
  }

  return (
    <div className="app">
      <header className="topbar">
        <button
          className="link"
          onClick={() => {
            setSession(null);
            setView(null);
            setError(null);
          }}
        >
          ← 换个文件
        </button>

        <div className="capture-summary">
          <strong>{session.fileName}</strong>
          <span>{formatBytes(session.fileSize)}</span>
          <span>{session.capture.format.toUpperCase()}</span>
          <span>{session.capture.linkTypeNames.join('、')}</span>
          {session.capture.interfaceNames.length > 0 && (
            <span title="抓包所在的网卡。utun 开头说明流量走的是 VPN / 代理隧道">
              接口 {session.capture.interfaceNames.join('、')}
            </span>
          )}
          <span>{session.capture.packetCount} 个包</span>
          <span>{session.connectionCount} 条 TCP 连接</span>
          <span>历时 {formatDuration(session.capture.durationMicros)}</span>
        </div>

        {view && (
          <button
            className="link"
            onClick={() => {
              setView(null);
              setFilter('all');
              setActiveId(null);
              setActive(null);
            }}
          >
            重选 host
          </button>
        )}
      </header>

      {session.capture.truncated && (
        <div className="alert warn">
          这个文件的末尾不完整（抓包进程可能是被强制结束的），最后一个包已被忽略。
        </div>
      )}

      {session.capture.warnings.length > 0 && (
        <details className="warnings">
          <summary>解析时跳过了一些包（{session.capture.warnings.length} 类）</summary>
          <ul>
            {session.capture.warnings.map((warning) => (
              <li key={warning.reason}>
                {warning.reason} —— {warning.count} 个，首次出现在第 #{warning.firstPacket} 个包
              </li>
            ))}
          </ul>
        </details>
      )}

      {error && <div className="alert error">{error}</div>}

      {!view ? (
        <HostPicker hosts={session.hosts} onSelect={handleSelectHost} />
      ) : (
        <ConnectionList
          view={view}
          connections={connections}
          filter={filter}
          onFilterChange={setFilter}
          activeId={activeId}
          loadingId={loadingId}
          onOpen={handleOpen}
        />
      )}
    </div>
  );
}
