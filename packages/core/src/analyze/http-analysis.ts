/**
 * 把一条连接的两个方向重组、解析成 HTTP 事务，并把结果映射回每个 TCP 包。
 *
 * 「回显」的产品形态是**消息级为主、包做锚点**：单个包的内容往往是从正文中间切断的碎片
 * （真实抓包里有个包的全部内容就是 `:site_name" content="中国孩子网" />…`），
 * 直接回显没有意义。所以这里除了产出完整报文，还产出「每个包对应正文的哪一段」。
 */

import type {
  AppSpan,
  ConnectionPacket,
  HttpAnalysis,
  HttpMessage,
  HttpSummary,
  HttpTiming,
  HttpTransaction,
} from '../types.js';
import type { ChunkSpan, ParsedMessage } from '../decode/http.js';
import { mapRawToBody, parseRequests, parseResponses } from '../decode/http.js';
import { reassemble, type ReassembledStream, type StreamSegment } from './reassemble.js';
import { formatBytes, formatDuration } from './labels.js';

export interface HttpAnalysisInput {
  clientSegments: StreamSegment[];
  serverSegments: StreamSegment[];
  handshakeCaptured: boolean;
  /** 该方向发过 FIN。决定「读到关闭为止」的正文算不算完整 */
  clientClosed: boolean;
  serverClosed: boolean;
  payloadCapped: boolean;
  packets: ConnectionPacket[];
}

export interface HttpAnalysisOutput {
  analysis: HttpAnalysis;
  summary: HttpSummary;
  /** packetIndex → 该包承载的报文区间 */
  spans: Map<number, AppSpan>;
  /** packetIndex → 应用层视角的一句话注解 */
  notes: Map<number, string>;
}

export function analyzeHttp(input: HttpAnalysisInput): HttpAnalysisOutput {
  const client = reassemble(input.clientSegments, { handshakeCaptured: input.handshakeCaptured });
  const server = reassemble(input.serverSegments, { handshakeCaptured: input.handshakeCaptured });

  const requests = parseRequests(client.bytes, {
    startsAtStreamBeginning: client.startsAtStreamBeginning,
    gaps: client.gaps,
    closedCleanly: input.clientClosed,
    capped: input.payloadCapped,
  });

  const responses = parseResponses(
    server.bytes,
    {
      startsAtStreamBeginning: server.startsAtStreamBeginning,
      gaps: server.gaps,
      closedCleanly: input.serverClosed,
      capped: input.payloadCapped,
    },
    requests.map((request) => request.method ?? ''),
  );

  const requestMessages = requests.map((parsed) => toMessage(parsed, client));
  const responseMessages = responses.map((parsed) => toMessage(parsed, server));

  // HTTP/1.1 不做 pipelining 时，第 n 个响应必然对应第 n 个请求
  const transactions: HttpTransaction[] = [];
  const count = Math.max(requestMessages.length, responseMessages.length);
  for (let i = 0; i < count; i += 1) {
    const request = requestMessages[i] ?? null;
    const response = responseMessages[i] ?? null;
    const timing = computeTiming(request, response, requests[i], client, input.packets);
    transactions.push({ index: i + 1, request, response, timing, note: describeTransaction(request, response, timing) });
  }

  const spans = new Map<number, AppSpan>();
  const notes = new Map<number, string>();
  collectSpans(spans, notes, client, requests, requestMessages, 'request');
  collectSpans(spans, notes, server, responses, responseMessages, 'response');

  const analysis: HttpAnalysis = {
    transactions,
    quality: {
      clientStreamComplete: client.gaps.length === 0 && !client.truncated,
      serverStreamComplete: server.gaps.length === 0 && !server.truncated,
      gaps: [
        ...client.gaps.map((gap) => ({ direction: 'c2s' as const, from: gap.from, to: gap.to })),
        ...server.gaps.map((gap) => ({ direction: 's2c' as const, from: gap.from, to: gap.to })),
      ],
      duplicateSegmentsDropped: client.duplicatesDropped + server.duplicatesDropped,
      payloadCapped: input.payloadCapped,
    },
  };

  const first = transactions[0];
  return {
    analysis,
    summary: {
      transactionCount: transactions.length,
      firstLine: first?.request ? `${first.request.method ?? ''} ${first.request.target ?? ''}`.trim() : null,
      statusCode: first?.response?.statusCode ?? null,
    },
    spans,
    notes,
  };
}

// ---------------------------------------------------------------- 消息定位

/** 把解析结果补上「哪些包承载了它」。用流序而不是抓包序——乱序时两者不一致 */
function toMessage(parsed: ParsedMessage, stream: ReassembledStream): HttpMessage {
  const carriers = stream.pieces.filter(
    (piece) => !piece.duplicate && piece.from < parsed.streamEnd && parsed.streamStart < piece.to,
  );

  const first = carriers[0];
  const last = carriers[carriers.length - 1];

  return {
    kind: parsed.kind,
    streamStart: parsed.streamStart,
    streamEnd: parsed.streamEnd,
    startLine: parsed.startLine,
    method: parsed.method,
    target: parsed.target,
    statusCode: parsed.statusCode,
    reasonPhrase: parsed.reasonPhrase,
    httpVersion: parsed.httpVersion,
    headers: parsed.headers,
    headerByteCount: parsed.headerByteCount,
    body: parsed.body,
    firstPacketIndex: first?.packetIndex ?? -1,
    lastPacketIndex: last?.packetIndex ?? -1,
    firstTsMicros: first?.tsMicros ?? 0,
    lastTsMicros: last?.tsMicros ?? 0,
    complete: parsed.complete,
    incompleteReason: parsed.incompleteReason,
  };
}

/**
 * 给每个包算出它承载了报文的哪一段。
 *
 * 正文的字符偏移要穿过两层换算：原始字节 → 解块后字节 → 解码后字符。
 * 后一步靠一次流式解码把所有边界一趟算出来，避免每个包都从头解一遍。
 */
function collectSpans(
  spans: Map<number, AppSpan>,
  notes: Map<number, string>,
  stream: ReassembledStream,
  parsed: ParsedMessage[],
  messages: HttpMessage[],
  kind: 'request' | 'response',
): void {
  if (parsed.length === 0) return;

  const charMaps = parsed.map((message, i) =>
    buildCharOffsets(message, messages[i]!, stream),
  );

  for (const piece of stream.pieces) {
    const index = parsed.findIndex(
      (message) => piece.from < message.streamEnd && message.streamStart < piece.to,
    );
    if (index < 0) continue;

    const message = parsed[index]!;
    const built = messages[index]!;
    const headerEnd = message.streamStart + message.headerByteCount;

    const touchesHeader = piece.from < headerEnd;
    const touchesBody = piece.to > headerEnd && message.bodyRawEnd > message.bodyRawStart;

    const part: AppSpan['part'] =
      touchesHeader && touchesBody
        ? 'mixed'
        : touchesHeader
          ? piece.from <= message.streamStart
            ? 'start-line'
            : 'headers'
          : 'body';

    let textFrom: number | null = null;
    let textTo: number | null = null;

    if (touchesBody && built.body?.text != null) {
      const rawFrom = Math.max(piece.from, message.bodyRawStart);
      const rawTo = Math.min(piece.to, message.bodyRawEnd);
      const bodyRange = mapRawToBody(message.chunkMap, rawFrom, rawTo);
      const charMap = charMaps[index];
      if (bodyRange && charMap) {
        textFrom = charMap(bodyRange.from);
        textTo = charMap(bodyRange.to);
      }
    }

    spans.set(piece.packetIndex, {
      transactionIndex: index + 1,
      messageKind: kind,
      part,
      streamFrom: piece.from,
      streamTo: piece.to,
      textFrom,
      textTo,
      duplicate: piece.duplicate,
    });

    notes.set(piece.packetIndex, describePacketSpan(built, part, piece.duplicate, textFrom, textTo));
  }
}

/**
 * 建「解块后字节偏移 → 解码后字符偏移」的换算函数。
 *
 * 多字节字符下字节数不等于字符数，直接拿字节偏移去截字符串会切坏中文。
 * 这里对正文单趟流式解码，把所有需要的边界一次算完，复杂度 O(正文长度)。
 */
function buildCharOffsets(
  parsed: ParsedMessage,
  message: HttpMessage,
  stream: ReassembledStream,
): ((byteOffset: number) => number) | null {
  const text = message.body?.text;
  if (text == null || parsed.chunkMap.length === 0) return null;

  const charset = message.body?.charset ?? 'utf-8';
  const bodyBytes = collectBodyBytes(stream.bytes, parsed.chunkMap);

  // 只在包边界处取值，不必给每个字节建表
  const boundaries = new Set<number>([0]);
  for (const piece of stream.pieces) {
    for (const raw of [
      Math.max(piece.from, parsed.bodyRawStart),
      Math.min(piece.to, parsed.bodyRawEnd),
    ]) {
      const mapped = mapRawToBody(parsed.chunkMap, raw, raw + 1);
      if (mapped) boundaries.add(mapped.from);
    }
  }
  for (const span of parsed.chunkMap) {
    boundaries.add(span.outFrom);
    boundaries.add(span.outTo);
  }

  const sorted = [...boundaries].filter((value) => value >= 0 && value <= bodyBytes.length).sort((a, b) => a - b);
  const table = new Map<number, number>();

  let decoder: TextDecoder;
  try {
    decoder = new TextDecoder(charset);
  } catch {
    decoder = new TextDecoder('utf-8');
  }

  let chars = 0;
  let cursor = 0;
  for (const boundary of sorted) {
    if (boundary > cursor) {
      chars += decoder.decode(bodyBytes.subarray(cursor, boundary), { stream: true }).length;
      cursor = boundary;
    }
    table.set(boundary, Math.min(chars, text.length));
  }

  return (byteOffset: number) => {
    const exact = table.get(byteOffset);
    if (exact !== undefined) return exact;
    // 边界表没命中时退回按比例估算，保证高亮区间仍落在正文里
    const ratio = bodyBytes.length === 0 ? 0 : byteOffset / bodyBytes.length;
    return Math.max(0, Math.min(text.length, Math.round(ratio * text.length)));
  };
}

function collectBodyBytes(stream: Uint8Array, chunkMap: ChunkSpan[]): Uint8Array {
  const total = chunkMap.reduce((sum, span) => sum + (span.rawTo - span.rawFrom), 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const span of chunkMap) {
    out.set(stream.subarray(span.rawFrom, span.rawTo), offset);
    offset += span.rawTo - span.rawFrom;
  }
  return out;
}

// ---------------------------------------------------------------- 耗时

function computeTiming(
  request: HttpMessage | null,
  response: HttpMessage | null,
  parsedRequest: ParsedMessage | undefined,
  clientStream: ReassembledStream,
  packets: ConnectionPacket[],
): HttpTiming {
  const timing: HttpTiming = {
    requestAckedMicros: null,
    ttfbMicros: null,
    responseTransferMicros: null,
    totalMicros: null,
  };

  if (request && response) {
    // 首字节必须按流序取：真实抓包里服务端第一个到达的包承载的是正文中段，
    // 拿它算 TTFB 会比真实值早 4ms 以上
    timing.ttfbMicros = response.firstTsMicros - request.lastTsMicros;
    timing.totalMicros = response.lastTsMicros - request.lastTsMicros;
  }

  if (response) {
    timing.responseTransferMicros = response.lastTsMicros - response.firstTsMicros;
  }

  if (request && parsedRequest) {
    // 请求末字节对应的相对序号，服务端的 ACK 越过它就说明请求已经送达
    const needAck = clientStream.base + parsedRequest.streamEnd;
    const ack = packets.find(
      (packet) =>
        packet.direction === 's2c' &&
        packet.relAck !== null &&
        packet.relAck >= needAck &&
        packet.tsMicros >= request.lastTsMicros,
    );
    if (ack) timing.requestAckedMicros = ack.tsMicros - request.lastTsMicros;
  }

  return timing;
}

// ---------------------------------------------------------------- 人话注解

function describeTransaction(
  request: HttpMessage | null,
  response: HttpMessage | null,
  timing: HttpTiming,
): string {
  if (request && !response) {
    return `${requestLabel(request)} 已经发出，但抓包里没有看到任何响应`;
  }
  if (!request && response) {
    return `没抓到请求，只看到服务端返回 ${statusLabel(response)}`;
  }
  if (!request || !response) return '这条连接上没有解析出完整的 HTTP 报文';

  const parts = [`${requestLabel(request)} → ${statusLabel(response)}`];

  // 服务端处理时间 = 等首字节的时间 - 请求送达确认的时间，把网络往返摘出去
  if (timing.ttfbMicros !== null && timing.requestAckedMicros !== null) {
    const think = timing.ttfbMicros - timing.requestAckedMicros;
    if (think > 0) parts.push(`服务端处理 ${formatDuration(think)}`);
  } else if (timing.ttfbMicros !== null) {
    parts.push(`等首字节 ${formatDuration(timing.ttfbMicros)}`);
  }

  const bytes = response.body?.byteCount ?? 0;
  if (bytes > 0) parts.push(`返回 ${formatBytes(bytes)} 正文`);

  if (!response.complete) parts.push('响应不完整');

  return parts.join('，');
}

function requestLabel(request: HttpMessage): string {
  return `${request.method ?? ''} ${request.target ?? ''}`.trim() || request.startLine;
}

function statusLabel(response: HttpMessage): string {
  if (response.statusCode === undefined) return response.startLine;
  return `${response.statusCode} ${response.reasonPhrase ?? ''}`.trim();
}

/** 包级注解，直接回答「这 1398 字节到底是什么」 */
function describePacketSpan(
  message: HttpMessage,
  part: AppSpan['part'],
  duplicate: boolean,
  textFrom: number | null,
  textTo: number | null,
): string {
  const who = message.kind === 'request' ? '请求' : '响应';

  if (duplicate) {
    return `这段数据前面已经传过，不参与${who}拼接`;
  }

  if (part === 'start-line' || part === 'mixed') {
    const head =
      message.kind === 'request'
        ? `${requestLabel(message)} 的请求头在这个包里`
        : `${statusLabel(message)} 的响应头在这个包里`;
    return part === 'mixed' ? `${head}，正文也从这里开始` : head;
  }

  if (part === 'headers') return `${who}头的后续部分`;

  if (textFrom !== null && textTo !== null) {
    return `${who}正文第 ${textFrom}~${textTo} 个字符`;
  }
  return `${who}正文的一段`;
}
