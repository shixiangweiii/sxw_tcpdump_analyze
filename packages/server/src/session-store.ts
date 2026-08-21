import { randomUUID } from 'node:crypto';
import type { AnalysisResult } from '@tcpview/core';

export interface StoredSession {
  id: string;
  fileName: string;
  fileSize: number;
  createdAt: number;
  result: AnalysisResult;
}

/**
 * 内存态的会话存储。
 *
 * P0 不引数据库：分析结果只在浏览器这一次使用期间有意义，落盘反而带来清理与隐私问题
 * （抓包文件里可能含敏感流量）。用 LRU 上限防止长时间运行把内存吃满。
 */
export class SessionStore {
  private readonly sessions = new Map<string, StoredSession>();

  constructor(private readonly maxSessions = 8) {}

  create(fileName: string, fileSize: number, result: AnalysisResult): StoredSession {
    const session: StoredSession = {
      id: randomUUID(),
      fileName,
      fileSize,
      createdAt: Date.now(),
      result,
    };

    this.sessions.set(session.id, session);
    while (this.sessions.size > this.maxSessions) {
      const oldest = this.sessions.keys().next();
      if (oldest.done) break;
      this.sessions.delete(oldest.value);
    }

    return session;
  }

  get(id: string): StoredSession | undefined {
    return this.sessions.get(id);
  }
}
