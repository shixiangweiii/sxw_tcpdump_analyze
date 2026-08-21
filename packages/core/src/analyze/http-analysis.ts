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
import { mapRawToBody, parseRequests, parseResponses, resolveCharset } from '../decode/http.js';
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

  const paired = pair(requestMessages, responseMessages, requests, client, input.packets);

  const spans = new Map<number, AppSpan>();
  const notes = new Map<number, string>();
  collectSpans(spans, notes, client, requests, requestMessages, 'request', paired.requestTxIndex);
  collectSpans(spans, notes, server, responses, responseMessages, 'response', paired.responseTxIndex);

  const analysis: HttpAnalysis = {
    transactions: paired.transactions,
    quality: {
      // 「完整」必须同时满足：中间没洞、没触顶、而且确实是从连接起点开始的。
      // 少了最后一条，抓包从中途开始时会报「完整」，等于骗人
      clientStreamComplete:
        client.gaps.length === 0 && !client.truncated && client.startsAtStreamBeginning,
      serverStreamComplete:
        server.gaps.length === 0 && !server.truncated && server.startsAtStreamBeginning,
      clientStartsAtBeginning: client.startsAtStreamBeginning,
      serverStartsAtBeginning: server.startsAtStreamBeginning,
      gaps: [
        ...client.gaps.map((gap) => ({ direction: 'c2s' as const, from: gap.from, to: gap.to })),
        ...server.gaps.map((gap) => ({ direction: 's2c' as const, from: gap.from, to: gap.to })),
      ],
      duplicateSegmentsDropped: client.duplicatesDropped + server.duplicatesDropped,
      payloadCapped: input.payloadCapped,
    },
  };

  const first = paired.transactions[0];
  return {
    analysis,
    summary: {
      transactionCount: paired.transactions.length,
      firstLine: first?.request
        ? `${first.request.method ?? ''} ${first.request.target ?? ''}`.trim()
        : null,
      responded: first?.response != null,
      statusCode: first?.response?.statusCode ?? null,
    },
    spans,
    notes,
  };
}

// ---------------------------------------------------------------- 事务配对

interface Paired {
  transactions: HttpTransaction[];
  /** requestMessages[i] 属于第几个事务（1 基） */
  requestTxIndex: number[];
  responseTxIndex: number[];
}

/** 1xx 是中间响应，不构成独立事务 */
function isInformational(message: HttpMessage): boolean {
  return message.statusCode !== undefined && message.statusCode >= 100 && message.statusCode < 200;
}

/**
 * 请求与响应配对。
 *
 * HTTP/1.1 不做 pipelining 时第 n 个响应对应第 n 个请求，但**不能直接按下标配**：
 * `Expect: 100-continue` 会在正式响应之前插一条 `100 Continue`，
 * 按下标配会让它顶掉真正的响应，后面全部错位一格——
 * 界面上就会显示成「POST /up → 100」，而真正的 200 变成「没抓到请求」。
 */
function pair(
  requestMessages: HttpMessage[],
  responseMessages: HttpMessage[],
  parsedRequests: ParsedMessage[],
  clientStream: ReassembledStream,
  packets: ConnectionPacket[],
): Paired {
  const transactions: HttpTransaction[] = [];
  const requestTxIndex: number[] = [];
  const responseTxIndex: number[] = [];

  let qi = 0;
  let ri = 0;

  while (qi < requestMessages.length || ri < responseMessages.length) {
    const index = transactions.length + 1;

    const requestIndex = qi;
    const request = requestMessages[qi] ?? null;
    if (request) requestTxIndex[qi] = index;
    qi += 1;

    // 正式响应之前夹着的 1xx 全部归到同一个事务
    const informationalResponses: HttpMessage[] = [];
    while (ri < responseMessages.length && isInformational(responseMessages[ri]!)) {
      responseTxIndex[ri] = index;
      informationalResponses.push(responseMessages[ri]!);
      ri += 1;
    }

    const response = responseMessages[ri] ?? null;
    if (response) {
      responseTxIndex[ri] = index;
      ri += 1;
    }

    const timing = computeTiming(
      request,
      response,
      parsedRequests[requestIndex],
      clientStream,
      packets,
    );

    transactions.push({
      index,
      request,
      response,
      informationalResponses,
      timing,
      note: describeTransaction(request, response, timing),
    });
  }

  return { transactions, requestTxIndex, responseTxIndex };
}

// ---------------------------------------------------------------- 消息定位

/** 把解析结果补上「哪些包承载了它」。用流序而不是抓包序——乱序时两者不一致 */
function toMessage(parsed: ParsedMessage, stream: ReassembledStream): HttpMessage {
  const carriers = stream.pieces.filter(
    (piece) => !piece.duplicate && piece.from < parsed.streamEnd && parsed.streamStart < piece.to,
  );

  const first = carriers[0];
  const last = carriers[carriers.length - 1];

  // 收齐时间取**最晚到达**的那个包，不能取流序最末的那段：
  // 乱序时流序最末的段可能最先到，相减会得到负的传输耗时
  let lastTsMicros = 0;
  for (const carrier of carriers) {
    if (carrier.tsMicros > lastTsMicros) lastTsMicros = carrier.tsMicros;
  }

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
    lastTsMicros,
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
  /** 第 i 条消息属于第几个事务。1xx 存在时它不等于 i + 1 */
  txIndex: number[],
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
      transactionIndex: txIndex[index] ?? index + 1,
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

  // 用和解正文时同一套字符集解析逻辑，避免这里和 buildBody 各写一份 try/catch 后走岔
  const { decoder } = resolveCharset(charset);

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
    serverThinkMicros: null,
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

  // 服务端处理时间只有在「送达确认」严格早于「响应首字节」时才测得出来。
  // 内网快链路 + 延迟 ACK 下，服务端常把对请求的 ACK 捎在响应首包上，
  // 两个时间点重合（差值为 0 甚至因时间戳抖动为负），此时如实报 null，
  // 不能对外显示成「服务端处理 0μs」——那是把「测不出来」说成了「不耗时」
  if (timing.ttfbMicros !== null && timing.requestAckedMicros !== null) {
    const think = timing.ttfbMicros - timing.requestAckedMicros;
    timing.serverThinkMicros = think > 0 ? think : null;
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

  // 摘掉网络往返之后剩下的才是服务端处理时间。摘不出来时退回「等首字节」，
  // 而不是什么都不说——这两个分支必须覆盖 ttfb 已知的所有情况，
  // 否则耗时条画着东西、note 却只字不提，两边自相矛盾
  if (timing.serverThinkMicros !== null) {
    parts.push(`服务端处理 ${formatDuration(timing.serverThinkMicros)}`);
  } else if (timing.ttfbMicros !== null) {
    parts.push(`等首字节 ${formatDuration(timing.ttfbMicros)}（含网络往返）`);
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

  if (textFrom !== null && textTo !== null && textTo > textFrom) {
    // 内部偏移是 0 基半开区间，展示成 1 基闭区间才对得上「第 N 个字符」的自然读法
    return `${who}正文第 ${textFrom + 1}~${textTo} 个字符`;
  }
  return `${who}正文的一段`;
}
