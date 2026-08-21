import cors from '@fastify/cors';
import multipart from '@fastify/multipart';
import Fastify from 'fastify';
import { analyze, buildHostView } from '@tcpview/core';
import { SessionStore } from './session-store.js';

const MAX_UPLOAD_BYTES = 200 * 1024 * 1024;

export async function buildServer() {
  const app = Fastify({
    logger: { transport: { target: 'pino-pretty' } },
    bodyLimit: MAX_UPLOAD_BYTES,
  });

  await app.register(cors, { origin: true });
  await app.register(multipart, { limits: { fileSize: MAX_UPLOAD_BYTES, files: 1 } });

  const store = new SessionStore();

  /** 上传并解析 pcap，返回抓包概况与自动发现的 host 列表 */
  app.post('/api/sessions', async (request, reply) => {
    const upload = await request.file();
    if (!upload) {
      return reply.status(400).send({ error: '没有收到文件，请选择一个 pcap 或 pcapng 文件' });
    }

    const bytes = await upload.toBuffer();
    if (bytes.length === 0) {
      return reply.status(400).send({ error: '文件是空的' });
    }

    try {
      const started = Date.now();
      const result = analyze(new Uint8Array(bytes));
      const session = store.create(upload.filename, bytes.length, result);

      app.log.info(
        { packets: result.capture.packetCount, connections: result.connections.length },
        `解析完成，耗时 ${Date.now() - started}ms`,
      );

      return {
        sessionId: session.id,
        fileName: session.fileName,
        fileSize: session.fileSize,
        capture: result.capture,
        hosts: result.hosts,
        connectionCount: result.connections.length,
      };
    } catch (error) {
      // 格式不对是用户能自己修的问题，返回 400 并原样带上原因
      const message = error instanceof Error ? error.message : '解析失败';
      app.log.warn({ err: error }, '解析 pcap 失败');
      return reply.status(400).send({ error: message });
    }
  });

  /** 按 host 过滤连接列表。包序列不在这里返回，避免大连接把响应撑爆 */
  app.get<{ Params: { id: string }; Querystring: { host?: string } }>(
    '/api/sessions/:id/connections',
    async (request, reply) => {
      const session = store.get(request.params.id);
      if (!session) {
        return reply.status(404).send({ error: '会话不存在或已过期，请重新上传文件' });
      }

      const host = request.query.host?.trim();
      if (!host) {
        return reply.status(400).send({ error: '缺少 host 参数' });
      }

      const view = buildHostView(session.result, host);
      return {
        query: view.query,
        matchedAddresses: view.matchedAddresses,
        matchedNames: view.matchedNames,
        perspective: view.perspective,
        nonTcp: view.nonTcp,
        connections: view.connections.map(({ packets, ...summary }) => {
          void packets;
          return summary;
        }),
      };
    },
  );

  /** 单条连接的完整包序列，供梯形图渲染 */
  app.get<{ Params: { id: string; connectionId: string } }>(
    '/api/sessions/:id/connections/:connectionId',
    async (request, reply) => {
      const session = store.get(request.params.id);
      if (!session) {
        return reply.status(404).send({ error: '会话不存在或已过期，请重新上传文件' });
      }

      const connectionId = decodeURIComponent(request.params.connectionId);
      const connection = session.result.connections.find((item) => item.id === connectionId);
      if (!connection) {
        return reply.status(404).send({ error: '找不到这条连接' });
      }

      return connection;
    },
  );

  app.get('/api/health', async () => ({ ok: true }));

  return app;
}
