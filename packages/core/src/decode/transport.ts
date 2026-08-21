import type { TcpFlags, TcpInfo, TcpOptions, UdpInfo } from '../types.js';

const TCP_OPT_EOL = 0;
const TCP_OPT_NOP = 1;
const TCP_OPT_MSS = 2;
const TCP_OPT_WINDOW_SCALE = 3;
const TCP_OPT_SACK_PERMITTED = 4;
const TCP_OPT_TIMESTAMPS = 8;

/**
 * @param data      整个链路帧
 * @param offset    TCP 头起始偏移
 * @param available IP 头声明的载荷长度（不能用帧长，否则会把以太网填充字节算成数据）
 */
export function decodeTcp(
  data: Uint8Array,
  offset: number,
  available: number,
): TcpInfo | { error: string } {
  if (data.length < offset + 20 || available < 20) return { error: 'TCP 头不完整' };

  const dataOffsetByte = data[offset + 12] ?? 0;
  const headerLength = (dataOffsetByte >> 4) * 4;
  if (headerLength < 20) return { error: `TCP 头长度非法（${headerLength} 字节）` };

  const flagBits = data[offset + 13] ?? 0;
  const flags: TcpFlags = {
    cwr: (flagBits & 0x80) !== 0,
    ece: (flagBits & 0x40) !== 0,
    urg: (flagBits & 0x20) !== 0,
    ack: (flagBits & 0x10) !== 0,
    psh: (flagBits & 0x08) !== 0,
    rst: (flagBits & 0x04) !== 0,
    syn: (flagBits & 0x02) !== 0,
    fin: (flagBits & 0x01) !== 0,
  };

  // 选项区可能因 snaplen 被截断，能读多少读多少
  const optionsEnd = Math.min(offset + headerLength, data.length);
  const options = decodeTcpOptions(data, offset + 20, optionsEnd);

  return {
    kind: 'tcp',
    srcPort: readU16(data, offset),
    dstPort: readU16(data, offset + 2),
    seq: readU32(data, offset + 4),
    ack: readU32(data, offset + 8),
    flags,
    window: readU16(data, offset + 14),
    headerLength,
    payloadLength: Math.max(0, available - headerLength),
    options,
  };
}

function decodeTcpOptions(data: Uint8Array, start: number, end: number): TcpOptions {
  const options: TcpOptions = {};
  let cursor = start;

  while (cursor < end) {
    const kind = data[cursor] ?? TCP_OPT_EOL;
    if (kind === TCP_OPT_EOL) break;
    if (kind === TCP_OPT_NOP) {
      cursor += 1;
      continue;
    }

    const length = data[cursor + 1] ?? 0;
    // 长度小于 2 会导致原地打转，视为选项区损坏
    if (length < 2 || cursor + length > end) break;

    switch (kind) {
      case TCP_OPT_MSS:
        if (length === 4) options.mss = readU16(data, cursor + 2);
        break;
      case TCP_OPT_WINDOW_SCALE:
        // 协议规定超过 14 的缩放值应按 14 处理
        if (length === 3) options.windowScale = Math.min(data[cursor + 2] ?? 0, 14);
        break;
      case TCP_OPT_SACK_PERMITTED:
        if (length === 2) options.sackPermitted = true;
        break;
      case TCP_OPT_TIMESTAMPS:
        if (length === 10) {
          options.timestamps = {
            tsval: readU32(data, cursor + 2),
            tsecr: readU32(data, cursor + 6),
          };
        }
        break;
      default:
        break;
    }

    cursor += length;
  }

  return options;
}

export function decodeUdp(
  data: Uint8Array,
  offset: number,
  available: number,
): UdpInfo | { error: string } {
  if (data.length < offset + 8 || available < 8) return { error: 'UDP 头不完整' };

  const declaredLength = readU16(data, offset + 4);
  const payloadLength = declaredLength >= 8 ? declaredLength - 8 : Math.max(0, available - 8);

  return {
    kind: 'udp',
    srcPort: readU16(data, offset),
    dstPort: readU16(data, offset + 2),
    payloadLength: Math.min(payloadLength, Math.max(0, available - 8)),
  };
}

/** 标志位的展示顺序与 Wireshark 保持一致，便于对照 */
export function flagNames(flags: TcpFlags): string[] {
  const names: string[] = [];
  if (flags.syn) names.push('SYN');
  if (flags.ack) names.push('ACK');
  if (flags.psh) names.push('PSH');
  if (flags.fin) names.push('FIN');
  if (flags.rst) names.push('RST');
  if (flags.urg) names.push('URG');
  if (flags.ece) names.push('ECE');
  if (flags.cwr) names.push('CWR');
  return names;
}

function readU16(data: Uint8Array, offset: number): number {
  return ((data[offset] ?? 0) << 8) | (data[offset + 1] ?? 0);
}

function readU32(data: Uint8Array, offset: number): number {
  return (
    (((data[offset] ?? 0) << 24) |
      ((data[offset + 1] ?? 0) << 16) |
      ((data[offset + 2] ?? 0) << 8) |
      (data[offset + 3] ?? 0)) >>>
    0
  );
}
