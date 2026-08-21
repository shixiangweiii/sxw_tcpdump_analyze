/**
 * 把一个方向上的 TCP 段拼回连续的字节流。
 *
 * 为什么必须做：应用层消息边界和 TCP 段边界完全不对齐，而且**抓包顺序不等于流顺序**。
 * 真实抓包（testdata/macos-tcpdump-http-chinakids.pcap）里服务端方向的到达顺序是
 * relSeq 4195 → 1399 → 1 → 2797，HTTP 响应头是第 3 个到达的数据包——
 * 按抓包顺序拼出来是乱码，按 relSeq 排序才能还原。
 *
 * 本模块只做「排序、去重、补洞」。relSeq 由 connections.ts 算好，
 * 重传/乱序的判定在 anomaly.ts，这里不重复造那套状态。
 */

/** 一个方向上的一个数据段。必须已经算好相对序号 */
export interface StreamSegment {
  relSeq: number;
  bytes: Uint8Array;
  packetIndex: number;
  tsMicros: number;
}

/** 某个包对流的贡献区间。这就是「流偏移 → 包」的映射表 */
export interface StreamPiece {
  /** 在重组结果 bytes 里的区间 [from, to) */
  from: number;
  to: number;
  packetIndex: number;
  tsMicros: number;
  /** 整段数据都已经出现过（重传/重复），不参与拼接 */
  duplicate: boolean;
}

export interface StreamGap {
  from: number;
  to: number;
}

export interface ReassembledStream {
  /** 流第一个字节的相对序号 */
  base: number;
  bytes: Uint8Array;
  pieces: StreamPiece[];
  gaps: StreamGap[];
  duplicatesDropped: number;
  /** 流是否从连接真正的起点开始。false 时不能假定开头就是一条消息的开头 */
  startsAtStreamBeginning: boolean;
  /** 因为空洞过大或超出上限而提前收尾 */
  truncated: boolean;
}

export interface ReassembleOptions {
  /** 握手是否被捕获。决定 relSeq=1 是否真的等于流起点 */
  handshakeCaptured: boolean;
  /** 输出上限，防止畸形序号撑爆内存 */
  maxBytes?: number;
}

/** 单个空洞超过这个大小就认为流已经断了，不再往下拼——否则一个坏序号能吃掉几个 G */
const MAX_GAP_FILL = 1024 * 1024;

const EMPTY = new Uint8Array(0);

export function reassemble(
  segments: StreamSegment[],
  options: ReassembleOptions,
): ReassembledStream {
  const maxBytes = options.maxBytes ?? 4 * 1024 * 1024;

  if (segments.length === 0) {
    return {
      base: 0,
      bytes: EMPTY,
      pieces: [],
      gaps: [],
      duplicatesDropped: 0,
      startsAtStreamBeginning: false,
      truncated: false,
    };
  }

  // relSeq 升序；同一起点时长的排前面，这样重叠重传里信息量大的那段先落地
  const ordered = [...segments].sort((a, b) =>
    a.relSeq !== b.relSeq ? a.relSeq - b.relSeq : b.bytes.length - a.bytes.length,
  );

  const base = ordered[0]!.relSeq;
  const parts: Uint8Array[] = [];
  const pieces: StreamPiece[] = [];
  const gaps: StreamGap[] = [];

  let cursor = base;
  let duplicatesDropped = 0;
  let truncated = false;

  for (const segment of ordered) {
    const start = segment.relSeq;
    const end = start + segment.bytes.length;

    // 整段落在已经拼好的范围里：重传或重复，丢弃但仍记录位置，
    // 好让界面能指出「这个包重发的是正文第 x~y 字节」
    if (end <= cursor) {
      duplicatesDropped += 1;
      pieces.push({
        from: start - base,
        to: end - base,
        packetIndex: segment.packetIndex,
        tsMicros: segment.tsMicros,
        duplicate: true,
      });
      continue;
    }

    if (start > cursor) {
      const gapSize = start - cursor;
      if (gapSize > MAX_GAP_FILL) {
        truncated = true;
        break;
      }
      // 用 0 填洞而不是跳过，这样后续偏移仍然对得上真实流位置；
      // 触及这段区间的消息会被标成不完整，不会拿填充值冒充真实数据
      gaps.push({ from: cursor - base, to: start - base });
      parts.push(new Uint8Array(gapSize));
      cursor = start;
    }

    // 部分重叠：只取新的那一截
    const skip = cursor - start;
    const fresh = skip > 0 ? segment.bytes.subarray(skip) : segment.bytes;

    if (cursor - base + fresh.length > maxBytes) {
      truncated = true;
      break;
    }

    parts.push(fresh);
    pieces.push({
      from: cursor - base,
      to: end - base,
      packetIndex: segment.packetIndex,
      tsMicros: segment.tsMicros,
      duplicate: false,
    });
    cursor = end;
  }

  return {
    base,
    bytes: concat(parts, cursor - base),
    pieces,
    gaps,
    duplicatesDropped,
    // 握手抓全时首个数据字节的相对序号必然是 1（SYN 占掉了 0）
    startsAtStreamBeginning: options.handshakeCaptured && base === 1,
    truncated,
  };
}

function concat(parts: Uint8Array[], total: number): Uint8Array {
  if (total <= 0 || parts.length === 0) return EMPTY;
  if (parts.length === 1 && parts[0]!.length === total) return parts[0]!;

  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
