import { useCallback, useState } from 'react';
import type { Connection } from '@tcpview/core';
import { formatBytes, formatDuration } from '@tcpview/core';
import {
  fetchConnection,
  fetchConnections,
  uploadCapture,
  type ConnectionsResponse,
  type UploadResponse,
} from './api';
import { UploadView } from './components/UploadView';
import { HostPicker } from './components/HostPicker';
import { ConnectionList } from './components/ConnectionList';

export function App() {
  const [session, setSession] = useState<UploadResponse | null>(null);
  const [view, setView] = useState<ConnectionsResponse | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Connection | null>(null);
  const [loadingId, setLoadingId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleFile = useCallback(async (file: File) => {
    setBusy(true);
    setError(null);
    try {
      const response = await uploadCapture(file);
      setSession(response);
      setView(null);
      setExpandedId(null);
      setExpanded(null);
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
        setExpandedId(null);
        setExpanded(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : '查询失败');
      } finally {
        setBusy(false);
      }
    },
    [session],
  );

  const handleToggle = useCallback(
    async (connectionId: string) => {
      if (!session) return;
      if (expandedId === connectionId) {
        setExpandedId(null);
        setExpanded(null);
        return;
      }

      setLoadingId(connectionId);
      try {
        const connection = await fetchConnection(session.sessionId, connectionId);
        setExpandedId(connectionId);
        setExpanded(connection);
      } catch (err) {
        setError(err instanceof Error ? err.message : '加载连接详情失败');
      } finally {
        setLoadingId(null);
      }
    },
    [session, expandedId],
  );

  if (!session) {
    return <UploadView onFile={handleFile} busy={busy} error={error} />;
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
              setExpandedId(null);
              setExpanded(null);
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
          expandedId={expandedId}
          expanded={expanded}
          loadingId={loadingId}
          onToggle={handleToggle}
        />
      )}
    </div>
  );
}
