/**
 * 明文 HTTP 的合成夹具。
 *
 * 重点不在「解析一个规规矩矩的 GET」——那部分不容易错。重点是真实抓包里实际出现过的形态：
 * 严重乱序、响应头整包重传、chunked、Content-Type 不带 charset。
 * 这几条都照着 testdata/macos-tcpdump-http-chinakids.pcap 的形状造。
 */

import { PcapBuilder, type TcpFlagName } from './pcap-builder.js';

const CLIENT = '10.20.0.5';
const SERVER = '10.20.0.80';
const CLIENT_PORT = 44_100;
const SERVER_PORT = 80;
const CLIENT_ISN = 3_000;
const SERVER_ISN = 900_000;
const BASE_TS = 1_775_100_000_000_000;

const encoder = new TextEncoder();

interface Step {
  from: 'client' | 'server';
  /** 相对抓包起点的微秒 */
  at: number;
  data?: Uint8Array | string;
  /** 显式指定这段数据在该方向流里的偏移（0 起）。制造乱序与重传时必须给 */
  offset?: number;
  flags?: TcpFlagName[];
}

interface FlowSpec {
  steps: Step[];
  /** 默认带三次握手。false 用来模拟抓包开始时连接已存在 */
  handshake?: boolean;
  teardown?: 'fin' | 'rst' | 'none';
  format?: 'pcap' | 'pcapng';
}

/**
 * 按「谁在什么时候发了哪一段流」来描述一条连接。
 * 序号由方向内的流偏移算出，所以乱序只要把 steps 的顺序打乱、offset 保持原样即可。
 */
function buildFlow(spec: FlowSpec): Uint8Array {
  const b = new PcapBuilder({ format: spec.format ?? 'pcap' });
  const t = (offset: number) => BASE_TS + offset;

  let clientLength = 0;
  let serverLength = 0;

  if (spec.handshake !== false) {
    b.tcp({
      tsMicros: t(0),
      src: CLIENT, srcPort: CLIENT_PORT, dst: SERVER, dstPort: SERVER_PORT,
      seq: CLIENT_ISN, flags: ['SYN'], window: 65_535,
      options: { mss: 1460, sackPermitted: true, windowScale: 7 },
    });
    b.tcp({
      tsMicros: t(1_000),
      src: SERVER, srcPort: SERVER_PORT, dst: CLIENT, dstPort: CLIENT_PORT,
      seq: SERVER_ISN, ack: CLIENT_ISN + 1, flags: ['SYN', 'ACK'], window: 65_535,
      options: { mss: 1460, sackPermitted: true, windowScale: 7 },
    });
    b.tcp({
      tsMicros: t(1_100),
      src: CLIENT, srcPort: CLIENT_PORT, dst: SERVER, dstPort: SERVER_PORT,
      seq: CLIENT_ISN + 1, ack: SERVER_ISN + 1, flags: ['ACK'], window: 512,
    });
  }

  for (const step of spec.steps) {
    const payload = typeof step.data === 'string' ? encoder.encode(step.data) : step.data;
    const isClient = step.from === 'client';
    const offset = step.offset ?? (isClient ? clientLength : serverLength);

    b.tcp({
      tsMicros: t(step.at),
      src: isClient ? CLIENT : SERVER,
      srcPort: isClient ? CLIENT_PORT : SERVER_PORT,
      dst: isClient ? SERVER : CLIENT,
      dstPort: isClient ? SERVER_PORT : CLIENT_PORT,
      seq: (isClient ? CLIENT_ISN : SERVER_ISN) + 1 + offset,
      ack: (isClient ? SERVER_ISN : CLIENT_ISN) + 1 + (isClient ? serverLength : clientLength),
      flags: step.flags ?? ['PSH', 'ACK'],
      window: 512,
      payload,
    });

    const end = offset + (payload?.length ?? 0);
    if (isClient) clientLength = Math.max(clientLength, end);
    else serverLength = Math.max(serverLength, end);
  }

  const lastAt = spec.steps[spec.steps.length - 1]?.at ?? 2_000;
  const teardown = spec.teardown ?? 'fin';

  if (teardown === 'rst') {
    b.tcp({
      tsMicros: t(lastAt + 1_000),
      src: SERVER, srcPort: SERVER_PORT, dst: CLIENT, dstPort: CLIENT_PORT,
      seq: SERVER_ISN + 1 + serverLength, ack: CLIENT_ISN + 1 + clientLength,
      flags: ['RST', 'ACK'], window: 0,
    });
  } else if (teardown === 'fin') {
    b.tcp({
      tsMicros: t(lastAt + 1_000),
      src: SERVER, srcPort: SERVER_PORT, dst: CLIENT, dstPort: CLIENT_PORT,
      seq: SERVER_ISN + 1 + serverLength, ack: CLIENT_ISN + 1 + clientLength,
      flags: ['FIN', 'ACK'], window: 512,
    });
    b.tcp({
      tsMicros: t(lastAt + 1_100),
      src: CLIENT, srcPort: CLIENT_PORT, dst: SERVER, dstPort: SERVER_PORT,
      seq: CLIENT_ISN + 1 + clientLength, ack: SERVER_ISN + 2 + serverLength,
      flags: ['FIN', 'ACK'], window: 512,
    });
    b.tcp({
      tsMicros: t(lastAt + 1_200),
      src: SERVER, srcPort: SERVER_PORT, dst: CLIENT, dstPort: CLIENT_PORT,
      seq: SERVER_ISN + 2 + serverLength, ack: CLIENT_ISN + 2 + clientLength,
      flags: ['ACK'], window: 512,
    });
  }

  return b.build();
}

// ---------------------------------------------------------------- 报文构造

const REQUEST = 'GET /api/order HTTP/1.1\r\nHost: api.internal\r\nUser-Agent: curl/8.7.1\r\n\r\n';

function response(headers: string[], body: Uint8Array): Uint8Array {
  const head = encoder.encode(`HTTP/1.1 200 OK\r\n${headers.join('\r\n')}\r\n\r\n`);
  const out = new Uint8Array(head.length + body.length);
  out.set(head, 0);
  out.set(body, head.length);
  return out;
}

/** 按 chunked 传输编码打包。长度必须按字节算，中文按字符算会把长度写错 */
function chunked(parts: string[]): Uint8Array {
  const pieces: Uint8Array[] = [];
  for (const part of parts) {
    const data = encoder.encode(part);
    pieces.push(encoder.encode(`${data.length.toString(16)}\r\n`));
    pieces.push(data);
    pieces.push(encoder.encode('\r\n'));
  }
  pieces.push(encoder.encode('0\r\n\r\n'));

  const total = pieces.reduce((sum, piece) => sum + piece.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const piece of pieces) {
    out.set(piece, offset);
    offset += piece.length;
  }
  return out;
}

function slice(bytes: Uint8Array, size: number): { offset: number; bytes: Uint8Array }[] {
  const out: { offset: number; bytes: Uint8Array }[] = [];
  for (let offset = 0; offset < bytes.length; offset += size) {
    out.push({ offset, bytes: bytes.subarray(offset, Math.min(offset + size, bytes.length)) });
  }
  return out;
}

// ---------------------------------------------------------------- 夹具

/** 最简单的一来一回，请求与响应各自装在一个包里 */
export function httpSimpleTransaction(options: { format?: 'pcap' | 'pcapng' } = {}): Uint8Array {
  const body = encoder.encode('{"ok":true}');
  return buildFlow({
    format: options.format,
    steps: [
      { from: 'client', at: 2_000, data: REQUEST },
      {
        from: 'server',
        at: 32_000,
        data: response(['Content-Type: application/json', `Content-Length: ${body.length}`], body),
      },
    ],
  });
}

/**
 * 响应被切成 4 段，且**到达顺序完全打乱**。
 *
 * 这是真实抓包里的实际形态：服务端方向先到的是流的第 4195 字节，响应头在第 3 个到达的包里。
 * 按抓包顺序拼会得到乱码，只有按序号排序才能还原。
 */
export function httpOutOfOrderResponse(): Uint8Array {
  const body = encoder.encode('X'.repeat(3_000));
  const full = response(['Content-Type: text/plain', `Content-Length: ${body.length}`], body);
  const [s0, s1, s2, s3] = slice(full, 1_000);

  return buildFlow({
    steps: [
      { from: 'client', at: 2_000, data: REQUEST },
      // 抓包顺序：第 4 段 → 第 2 段 → 第 1 段（含响应头）→ 第 3 段
      { from: 'server', at: 30_000, offset: s3!.offset, data: s3!.bytes },
      { from: 'server', at: 31_000, offset: s1!.offset, data: s1!.bytes },
      { from: 'server', at: 31_500, offset: s0!.offset, data: s0!.bytes },
      { from: 'server', at: 32_000, offset: s2!.offset, data: s2!.bytes },
    ],
  });
}

/** 响应头整包重传。不去重的话正文里会凭空多出一份 HTTP 响应头 */
export function httpRetransmittedHeader(): Uint8Array {
  const body = encoder.encode('Y'.repeat(2_000));
  const full = response(['Content-Type: text/plain', `Content-Length: ${body.length}`], body);
  const [s0, s1, s2] = slice(full, 1_000);

  return buildFlow({
    steps: [
      { from: 'client', at: 2_000, data: REQUEST },
      { from: 'server', at: 30_000, offset: s0!.offset, data: s0!.bytes },
      { from: 'server', at: 31_000, offset: s1!.offset, data: s1!.bytes },
      // 对方没确认，服务端把第一段整个重发一次
      { from: 'server', at: 90_000, offset: s0!.offset, data: s0!.bytes },
      { from: 'server', at: 91_000, offset: s2!.offset, data: s2!.bytes },
    ],
  });
}

/** chunked 传输编码。不解块的话正文里会混进十六进制长度行 */
export function httpChunkedResponse(): Uint8Array {
  const body = chunked(['<!DOCTYPE html><p>第一块内容</p>', '<p>第二块内容</p>']);
  return buildFlow({
    steps: [
      { from: 'client', at: 2_000, data: REQUEST },
      {
        from: 'server',
        at: 32_000,
        data: response(['Content-Type: text/html; charset=utf-8', 'Transfer-Encoding: chunked'], body),
      },
    ],
  });
}

/**
 * Content-Type 不带 charset，只有 HTML 里的 <meta charset>。
 * 真实抓包就是这样，只看响应头会把中文解成乱码。
 */
export function httpNoCharsetHeader(): Uint8Array {
  const html = '<!DOCTYPE html><html><head><meta charset="utf-8" /><title>中国孩子网</title></head><body>正文内容</body></html>';
  const body = encoder.encode(html);
  return buildFlow({
    steps: [
      { from: 'client', at: 2_000, data: REQUEST },
      {
        from: 'server',
        at: 32_000,
        data: response(['Content-Type: text/html', `Content-Length: ${body.length}`], body),
      },
    ],
  });
}

/** 中间少了一段没抓到。正文不能谎报成完整的 */
export function httpGapInStream(): Uint8Array {
  const body = encoder.encode('Z'.repeat(3_000));
  const full = response(['Content-Type: text/plain', `Content-Length: ${body.length}`], body);
  const [s0, , s2, s3] = slice(full, 1_000);

  return buildFlow({
    steps: [
      { from: 'client', at: 2_000, data: REQUEST },
      { from: 'server', at: 30_000, offset: s0!.offset, data: s0!.bytes },
      // 第 2 段没抓到
      { from: 'server', at: 31_000, offset: s2!.offset, data: s2!.bytes },
      { from: 'server', at: 32_000, offset: s3!.offset, data: s3!.bytes },
    ],
  });
}

/** 抓包开始时连接已经在传正文了，看不到任何起始行——不能硬认成 HTTP */
export function httpMidStreamCapture(): Uint8Array {
  return buildFlow({
    handshake: false,
    teardown: 'none',
    steps: [
      { from: 'server', at: 2_000, data: '<p>这是从正文中间开始的一段 HTML</p>'.repeat(10) },
      { from: 'client', at: 3_000, data: undefined, flags: ['ACK'] },
    ],
  });
}

/** 请求发出去了，服务端一个字节都没回就 RST */
export function httpRequestNoResponse(): Uint8Array {
  return buildFlow({
    teardown: 'rst',
    steps: [{ from: 'client', at: 2_000, data: REQUEST }],
  });
}

export const httpScenarios = {
  httpSimpleTransaction,
  httpOutOfOrderResponse,
  httpRetransmittedHeader,
  httpChunkedResponse,
  httpNoCharsetHeader,
  httpGapInStream,
  httpMidStreamCapture,
  httpRequestNoResponse,
};
