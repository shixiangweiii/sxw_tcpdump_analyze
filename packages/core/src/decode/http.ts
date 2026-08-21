/**
 * HTTP/1.x 报文解析。
 *
 * 输入是「已经重组好的单方向字节流」，不是单个包——应用层消息边界和 TCP 段边界不对齐，
 * 逐包解析只能拿到从中间切断的碎片。
 *
 * 约束：本文件（连同整个 core）会被 Vite 打进浏览器包，
 * **不得 import 任何 node: 模块**。只用 TextDecoder 这类两端都有的 API。
 */

import type {
  HttpBody,
  HttpBodyFraming,
  HttpHeader,
  HttpMessage,
} from '../types.js';

/** 流里没抓到的区间。由重组阶段产出，这里只用来判定消息完不完整 */
export interface ByteGap {
  from: number;
  to: number;
}

/** 明文 HTTP 请求的方法。appnames.ts 的 Host 头嗅探也复用这一份 */
export const HTTP_METHODS = [
  'GET',
  'POST',
  'PUT',
  'HEAD',
  'DELETE',
  'PATCH',
  'OPTIONS',
  'TRACE',
  'CONNECT',
] as const;

/** 解码后的正文最多留这么多字符，超出截断。防止一个大下载把响应体撑爆 */
const BODY_TEXT_CAP = 256 * 1024;

/** 在正文开头这么多字节里嗅探 <meta charset> */
const META_CHARSET_SCAN = 1024;

const TLS_HANDSHAKE = 0x16;

// ---------------------------------------------------------------- 协议嗅探

/**
 * 看一个数据段的开头，判断这条连接跑的是什么。
 * 返回 null 表示「还看不出来」，调用方应该继续看后面的段。
 */
export function sniffAppProtocol(
  bytes: Uint8Array,
  direction: 'c2s' | 's2c',
): 'http1' | 'tls' | null {
  if (bytes.length === 0) return null;

  // TLS 记录层：0x16 = handshake，紧跟主版本号 0x03。识别出来就不用再管了
  if (bytes[0] === TLS_HANDSHAKE && bytes[1] === 0x03) return 'tls';

  if (direction === 'c2s') {
    return looksLikeRequestLine(bytes, 0) ? 'http1' : null;
  }
  return looksLikeStatusLine(bytes, 0) ? 'http1' : null;
}

function looksLikeRequestLine(bytes: Uint8Array, offset: number): boolean {
  for (const method of HTTP_METHODS) {
    if (matchesAscii(bytes, offset, method) && bytes[offset + method.length] === 0x20) {
      return true;
    }
  }
  return false;
}

function looksLikeStatusLine(bytes: Uint8Array, offset: number): boolean {
  return matchesAscii(bytes, offset, 'HTTP/1.');
}

function matchesAscii(bytes: Uint8Array, offset: number, text: string): boolean {
  if (offset + text.length > bytes.length) return false;
  for (let i = 0; i < text.length; i += 1) {
    if (bytes[offset + i] !== text.charCodeAt(i)) return false;
  }
  return true;
}

// ---------------------------------------------------------------- 解析入口

export interface ParseOptions {
  /** 流是否从连接起点开始。false 时不能假定偏移 0 就是消息开头 */
  startsAtStreamBeginning: boolean;
  gaps: ByteGap[];
  /** 该方向是否正常收尾（看到 FIN）。决定「读到关闭为止」的正文算不算完整 */
  closedCleanly: boolean;
  /** 载荷保留触顶，后面的数据根本没留下来 */
  capped: boolean;
}

/** 比 HttpMessage 多带解块映射，供上层换算包锚点用，不进最终报告 */
export interface ParsedMessage extends Omit<
  HttpMessage,
  'firstPacketIndex' | 'lastPacketIndex' | 'firstTsMicros' | 'lastTsMicros'
> {
  /** 正文在流里的原始区间（解块前） */
  bodyRawStart: number;
  bodyRawEnd: number;
  /** 解块前后的区间映射。非 chunked 时是一条恒等映射 */
  chunkMap: ChunkSpan[];
}

export interface ChunkSpan {
  rawFrom: number;
  rawTo: number;
  outFrom: number;
  outTo: number;
}

/** 解析客户端方向的流，切出所有请求 */
export function parseRequests(bytes: Uint8Array, options: ParseOptions): ParsedMessage[] {
  return parseStream(bytes, options, 'request', []);
}

/**
 * 解析服务端方向的流，切出所有响应。
 * 必须知道对应请求的方法——HEAD 的响应带 Content-Length 但没有正文。
 */
export function parseResponses(
  bytes: Uint8Array,
  options: ParseOptions,
  requestMethods: string[],
): ParsedMessage[] {
  return parseStream(bytes, options, 'response', requestMethods);
}

function parseStream(
  bytes: Uint8Array,
  options: ParseOptions,
  kind: 'request' | 'response',
  requestMethods: string[],
): ParsedMessage[] {
  const messages: ParsedMessage[] = [];
  let offset = options.startsAtStreamBeginning ? 0 : findMessageStart(bytes, 0, kind);

  while (offset >= 0 && offset < bytes.length) {
    const message = parseOne(bytes, offset, kind, requestMethods[messages.length], options);
    if (!message) break;

    messages.push(message);
    if (!message.complete) break;
    if (message.streamEnd <= offset) break; // 防御：绝不允许原地打转

    offset = message.streamEnd;
  }

  return messages;
}

/** 在流里找下一条消息的起点。只认行首的签名，避免在正文里撞上 "GET " 就误判 */
function findMessageStart(bytes: Uint8Array, from: number, kind: 'request' | 'response'): number {
  const matches = kind === 'request' ? looksLikeRequestLine : looksLikeStatusLine;

  for (let i = from; i < bytes.length; i += 1) {
    const atLineStart = i === 0 || (i >= 2 && bytes[i - 2] === 0x0d && bytes[i - 1] === 0x0a);
    if (atLineStart && matches(bytes, i)) return i;
  }
  return -1;
}

function parseOne(
  bytes: Uint8Array,
  start: number,
  kind: 'request' | 'response',
  requestMethod: string | undefined,
  options: ParseOptions,
): ParsedMessage | null {
  const headerEnd = findHeaderEnd(bytes, start);
  if (headerEnd < 0) {
    // 头部还没收完抓包就断了：报告一条不完整的消息，而不是假装什么都没发生
    if (bytes.length - start < 4) return null;
    const partial = decodeUtf8(bytes.subarray(start, Math.min(bytes.length, start + 4096)));
    const firstLine = partial.split(/\r?\n/)[0] ?? '';
    if (!firstLine) return null;

    return {
      ...emptyShape(kind, firstLine),
      streamStart: start,
      streamEnd: bytes.length,
      headerByteCount: bytes.length - start,
      complete: false,
      incompleteReason: options.capped
        ? '载荷保留已达上限，头部没有收全'
        : '抓包在头部收完之前就结束了',
      bodyRawStart: bytes.length,
      bodyRawEnd: bytes.length,
      chunkMap: [],
    };
  }

  const bodyStart = headerEnd + 4;
  const headerText = decodeUtf8(bytes.subarray(start, headerEnd));
  const lines = unfold(headerText.split('\r\n'));
  const startLine = lines[0] ?? '';
  const headers = parseHeaders(lines.slice(1));

  const base = {
    ...emptyShape(kind, startLine),
    headers,
    streamStart: start,
    headerByteCount: bodyStart - start,
  };

  if (kind === 'request') {
    const [method, target, version] = splitStartLine(startLine, 3);
    base.method = method;
    base.target = target;
    base.httpVersion = version ?? 'HTTP/1.1';
  } else {
    const [version, status, ...reason] = splitStartLine(startLine, 3);
    base.httpVersion = version ?? 'HTTP/1.1';
    base.statusCode = Number.parseInt(status ?? '', 10) || undefined;
    base.reasonPhrase = reason.join(' ') || undefined;
  }

  const framing = decideFraming(kind, base.statusCode, requestMethod, headers);
  const bodyResult = readBody(bytes, bodyStart, framing, headers, options);

  const streamEnd = bodyResult.rawEnd;
  const touchesGap = options.gaps.some((gap) => gap.from < streamEnd && start < gap.to);
  const complete = bodyResult.complete && !touchesGap;

  return {
    ...base,
    streamEnd,
    body: bodyResult.body,
    complete,
    incompleteReason: complete
      ? null
      : touchesGap
        ? '这段报文里有没抓到的字节，内容不完整'
        : bodyResult.incompleteReason,
    bodyRawStart: bodyStart,
    bodyRawEnd: bodyResult.rawEnd,
    chunkMap: bodyResult.chunkMap,
  };
}

function emptyShape(kind: 'request' | 'response', startLine: string) {
  return {
    kind,
    startLine,
    httpVersion: 'HTTP/1.1',
    headers: [] as HttpHeader[],
    body: null as HttpBody | null,
    streamStart: 0,
    streamEnd: 0,
    headerByteCount: 0,
    complete: true,
    incompleteReason: null as string | null,
    method: undefined as string | undefined,
    target: undefined as string | undefined,
    statusCode: undefined as number | undefined,
    reasonPhrase: undefined as string | undefined,
  };
}

function splitStartLine(line: string, limit: number): string[] {
  const parts = line.split(' ');
  if (parts.length <= limit) return parts;
  return [...parts.slice(0, limit - 1), parts.slice(limit - 1).join(' ')];
}

/** 头部续行（obs-fold）：以空格或制表符开头的行是上一行的延续 */
function unfold(lines: string[]): string[] {
  const out: string[] = [];
  for (const line of lines) {
    if (out.length > 1 && (line.startsWith(' ') || line.startsWith('\t'))) {
      out[out.length - 1] += ` ${line.trim()}`;
      continue;
    }
    out.push(line);
  }
  return out;
}

function parseHeaders(lines: string[]): HttpHeader[] {
  const headers: HttpHeader[] = [];
  for (const line of lines) {
    if (!line) continue;
    const colon = line.indexOf(':');
    if (colon <= 0) continue;
    headers.push({ name: line.slice(0, colon).trim(), value: line.slice(colon + 1).trim() });
  }
  return headers;
}

function headerValue(headers: HttpHeader[], name: string): string | null {
  const lower = name.toLowerCase();
  for (const header of headers) {
    if (header.name.toLowerCase() === lower) return header.value;
  }
  return null;
}

// ---------------------------------------------------------------- 正文框定

/**
 * 「这条消息有没有正文、有多长」的判定。
 * 顺序不能变——chunked 优先于 Content-Length 是 RFC 9112 的硬规定，
 * 而 HEAD 的响应会带 Content-Length 却没有正文，只看头部会读过界。
 */
function decideFraming(
  kind: 'request' | 'response',
  statusCode: number | undefined,
  requestMethod: string | undefined,
  headers: HttpHeader[],
): HttpBodyFraming {
  if (kind === 'response') {
    if (requestMethod?.toUpperCase() === 'HEAD') return 'none';
    if (statusCode !== undefined) {
      if (statusCode >= 100 && statusCode < 200) return 'none';
      if (statusCode === 204 || statusCode === 304) return 'none';
    }
  }

  const transferEncoding = headerValue(headers, 'transfer-encoding');
  if (transferEncoding && transferEncoding.toLowerCase().includes('chunked')) return 'chunked';

  const contentLength = headerValue(headers, 'content-length');
  if (contentLength !== null && /^\d+$/.test(contentLength.trim())) return 'content-length';

  return kind === 'response' ? 'until-close' : 'none';
}

interface BodyResult {
  body: HttpBody | null;
  rawEnd: number;
  chunkMap: ChunkSpan[];
  complete: boolean;
  incompleteReason: string | null;
}

function readBody(
  bytes: Uint8Array,
  bodyStart: number,
  framing: HttpBodyFraming,
  headers: HttpHeader[],
  options: ParseOptions,
): BodyResult {
  if (framing === 'none') {
    return {
      body: { framing, byteCount: 0, text: null, truncated: false, charset: null, unavailableReason: null },
      rawEnd: bodyStart,
      chunkMap: [],
      complete: true,
      incompleteReason: null,
    };
  }

  let raw: Uint8Array;
  let rawEnd: number;
  let chunkMap: ChunkSpan[];
  let complete = true;
  let incompleteReason: string | null = null;

  if (framing === 'chunked') {
    const decoded = decodeChunked(bytes, bodyStart);
    raw = decoded.bytes;
    rawEnd = decoded.rawEnd;
    chunkMap = decoded.spans;
    complete = decoded.complete;
    incompleteReason = decoded.complete
      ? null
      : options.capped
        ? '载荷保留已达上限，分块正文没有收全'
        : '分块正文没有出现终止块，抓包可能提前结束了';
  } else if (framing === 'content-length') {
    const declared = Number.parseInt(headerValue(headers, 'content-length') ?? '0', 10);
    const available = Math.max(0, bytes.length - bodyStart);
    const take = Math.min(declared, available);
    raw = bytes.subarray(bodyStart, bodyStart + take);
    rawEnd = bodyStart + take;
    chunkMap = take > 0 ? [{ rawFrom: bodyStart, rawTo: rawEnd, outFrom: 0, outTo: take }] : [];
    complete = take === declared;
    incompleteReason = complete
      ? null
      : `Content-Length 声明 ${declared} 字节，实际只抓到 ${take} 字节`;
  } else {
    raw = bytes.subarray(bodyStart);
    rawEnd = bytes.length;
    chunkMap = raw.length > 0 ? [{ rawFrom: bodyStart, rawTo: rawEnd, outFrom: 0, outTo: raw.length }] : [];
    // 没有长度声明，正文以连接关闭为界——没看到 FIN 就说明还没读完
    complete = options.closedCleanly;
    incompleteReason = complete ? null : '正文没有长度声明，要读到连接关闭为止，但抓包里没看到关闭';
  }

  return {
    body: buildBody(framing, raw, headers),
    rawEnd,
    chunkMap,
    complete,
    incompleteReason,
  };
}

/**
 * 解 chunked 传输编码。
 * 真实抓包里 nginx 默认就用它，不解的话正文里会混进 `2129\r\n` 这样的十六进制长度行。
 */
function decodeChunked(
  bytes: Uint8Array,
  start: number,
): { bytes: Uint8Array; rawEnd: number; spans: ChunkSpan[]; complete: boolean } {
  const parts: Uint8Array[] = [];
  const spans: ChunkSpan[] = [];
  let cursor = start;
  let outLength = 0;

  while (cursor < bytes.length) {
    const lineEnd = indexOfCrLf(bytes, cursor);
    if (lineEnd < 0) break;

    // chunk 扩展（`size;name=value`）要丢掉再解析长度
    const sizeText = decodeLatin1(bytes.subarray(cursor, lineEnd)).split(';')[0]!.trim();
    const size = Number.parseInt(sizeText, 16);
    if (!Number.isFinite(size) || size < 0 || sizeText === '') break;

    const dataStart = lineEnd + 2;

    if (size === 0) {
      // 终止块，后面可能还有 trailer，一路读到空行为止
      const trailerEnd = findHeaderEnd(bytes, cursor);
      return {
        bytes: concatParts(parts, outLength),
        rawEnd: trailerEnd >= 0 ? trailerEnd + 4 : Math.min(dataStart + 2, bytes.length),
        spans,
        complete: true,
      };
    }

    if (dataStart + size > bytes.length) break;

    parts.push(bytes.subarray(dataStart, dataStart + size));
    spans.push({
      rawFrom: dataStart,
      rawTo: dataStart + size,
      outFrom: outLength,
      outTo: outLength + size,
    });
    outLength += size;
    cursor = dataStart + size + 2; // 跳过块尾的 CRLF
  }

  return { bytes: concatParts(parts, outLength), rawEnd: bytes.length, spans, complete: false };
}

function concatParts(parts: Uint8Array[], total: number): Uint8Array {
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

// ---------------------------------------------------------------- 正文解码

const TEXTUAL_TYPES = [
  'application/json',
  'application/xml',
  'application/javascript',
  'application/ecmascript',
  'application/x-www-form-urlencoded',
  'application/graphql',
];

function buildBody(framing: HttpBodyFraming, raw: Uint8Array, headers: HttpHeader[]): HttpBody {
  const contentType = headerValue(headers, 'content-type') ?? '';
  const encoding = (headerValue(headers, 'content-encoding') ?? '').trim().toLowerCase();

  const body: HttpBody = {
    framing,
    byteCount: raw.length,
    text: null,
    truncated: false,
    charset: null,
    unavailableReason: null,
  };

  if (raw.length === 0) return body;

  // 压缩正文本期不解：core 会被打进浏览器包，不能直接用 node:zlib
  if (encoding && encoding !== 'identity') {
    body.unavailableReason = `正文是 ${encoding} 压缩的，本工具暂不解压`;
    return body;
  }

  if (!isTextual(contentType)) {
    body.unavailableReason = contentType
      ? `二进制内容（Content-Type: ${contentType}），不做文本回显`
      : '没有 Content-Type，无法确定是不是文本，不做回显';
    return body;
  }

  const charset = detectCharset(contentType, raw);
  const capped = raw.length > BODY_TEXT_CAP ? raw.subarray(0, BODY_TEXT_CAP) : raw;

  body.charset = charset;
  body.text = decodeWith(charset, capped);
  body.truncated = capped.length < raw.length;
  return body;
}

function isTextual(contentType: string): boolean {
  const type = contentType.split(';')[0]!.trim().toLowerCase();
  if (!type) return false;
  if (type.startsWith('text/')) return true;
  if (type.endsWith('+json') || type.endsWith('+xml')) return true;
  return TEXTUAL_TYPES.includes(type);
}

/**
 * 判定字符集。
 *
 * 真实抓包里 `Content-Type: text/html` 常常**不带 charset**，只在 HTML 里写
 * `<meta charset="utf-8" />`，所以不能只看响应头。内网老系统还会遇到 GBK 且同样不声明。
 */
function detectCharset(contentType: string, raw: Uint8Array): string {
  const fromHeader = /charset\s*=\s*"?([\w-]+)"?/i.exec(contentType)?.[1];
  if (fromHeader) return fromHeader.toLowerCase();

  const head = decodeLatin1(raw.subarray(0, Math.min(raw.length, META_CHARSET_SCAN)));
  const fromMeta =
    /<meta[^>]+charset\s*=\s*["']?([\w-]+)/i.exec(head)?.[1] ??
    /<\?xml[^>]+encoding\s*=\s*["']([\w-]+)/i.exec(head)?.[1];
  if (fromMeta) return fromMeta.toLowerCase();

  return 'utf-8';
}

function decodeWith(charset: string, bytes: Uint8Array): string {
  try {
    return new TextDecoder(charset).decode(bytes);
  } catch {
    // 未知字符集（TextDecoder 会抛）时退回 UTF-8，charset 字段仍保留原始声明供排查
    return decodeUtf8(bytes);
  }
}

function decodeUtf8(bytes: Uint8Array): string {
  return new TextDecoder('utf-8').decode(bytes);
}

function decodeLatin1(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 1) out += String.fromCharCode(bytes[i]!);
  return out;
}

// ---------------------------------------------------------------- 字节工具

/** 找头部结束的空行，返回 `\r\n\r\n` 的起始位置 */
function findHeaderEnd(bytes: Uint8Array, from: number): number {
  for (let i = from; i + 3 < bytes.length; i += 1) {
    if (bytes[i] === 0x0d && bytes[i + 1] === 0x0a && bytes[i + 2] === 0x0d && bytes[i + 3] === 0x0a) {
      return i;
    }
  }
  return -1;
}

function indexOfCrLf(bytes: Uint8Array, from: number): number {
  for (let i = from; i + 1 < bytes.length; i += 1) {
    if (bytes[i] === 0x0d && bytes[i + 1] === 0x0a) return i;
  }
  return -1;
}

/**
 * 把「解块前的原始字节偏移」换算成「解块后正文里的偏移」。
 * 包锚点要用它把一个 TCP 包定位到正文的某一段。
 */
export function mapRawToBody(spans: ChunkSpan[], rawFrom: number, rawTo: number): { from: number; to: number } | null {
  let from: number | null = null;
  let to: number | null = null;

  for (const span of spans) {
    if (span.rawTo <= rawFrom || span.rawFrom >= rawTo) continue;
    const localFrom = span.outFrom + Math.max(0, rawFrom - span.rawFrom);
    const localTo = span.outFrom + Math.min(span.rawTo - span.rawFrom, Math.max(0, rawTo - span.rawFrom));
    from = from === null ? localFrom : Math.min(from, localFrom);
    to = to === null ? localTo : Math.max(to, localTo);
  }

  return from === null || to === null ? null : { from, to };
}
