import type { CaptureInfo, Connection, HostEntry, HostView } from '@tcpview/core';

export interface UploadResponse {
  sessionId: string;
  fileName: string;
  fileSize: number;
  capture: CaptureInfo;
  hosts: HostEntry[];
  connectionCount: number;
}

/** 连接列表接口不返回逐包数据，避免大连接把响应撑爆 */
export type ConnectionSummary = Omit<Connection, 'packets'>;

export interface ConnectionsResponse extends Omit<HostView, 'connections'> {
  connections: ConnectionSummary[];
}

async function unwrap<T>(response: Response): Promise<T> {
  if (!response.ok) {
    const body = (await response.json().catch(() => null)) as { error?: string } | null;
    throw new Error(body?.error ?? `请求失败（HTTP ${response.status}）`);
  }
  return (await response.json()) as T;
}

export async function uploadCapture(file: File): Promise<UploadResponse> {
  const form = new FormData();
  form.append('file', file);
  return unwrap<UploadResponse>(
    await fetch('/api/sessions', { method: 'POST', body: form }),
  );
}

export async function fetchConnections(
  sessionId: string,
  host: string,
): Promise<ConnectionsResponse> {
  return unwrap<ConnectionsResponse>(
    await fetch(`/api/sessions/${sessionId}/connections?host=${encodeURIComponent(host)}`),
  );
}

export async function fetchConnection(
  sessionId: string,
  connectionId: string,
): Promise<Connection> {
  return unwrap<Connection>(
    await fetch(`/api/sessions/${sessionId}/connections/${encodeURIComponent(connectionId)}`),
  );
}
