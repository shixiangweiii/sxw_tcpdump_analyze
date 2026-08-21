import type { NetworkInfo } from '../types.js';
import { formatIpv4, formatIpv6 } from '../pcap/reader.js';

export const IpProtocol = {
  TCP: 6,
  UDP: 17,
} as const;

/** IPv6 扩展头。出现这些说明后面还有一层头，本工具 P0 不追链 */
const IPV6_EXTENSION_HEADERS = new Set([0, 43, 44, 50, 51, 60, 135, 139, 140]);

export interface IpResult {
  network: NetworkInfo;
  /** 传输层起始偏移 */
  payloadOffset: number;
  /** IP 头声明的载荷长度。用它裁掉以太网填充字节 */
  payloadLength: number;
}

export function decodeIpv4(data: Uint8Array, offset: number): IpResult | { error: string } {
  if (data.length < offset + 20) return { error: 'IPv4 头不完整' };

  const versionIhl = data[offset] ?? 0;
  const ihl = (versionIhl & 0x0f) * 4;
  if (ihl < 20) return { error: `IPv4 头长度非法（${ihl} 字节）` };
  if (data.length < offset + ihl) return { error: 'IPv4 选项被截断' };

  const totalLength = readU16(data, offset + 2);
  const flagsFragment = readU16(data, offset + 6);
  const moreFragments = (flagsFragment & 0x2000) !== 0;
  const fragmentOffset = (flagsFragment & 0x1fff) * 8;

  const network: NetworkInfo = {
    version: 4,
    src: formatIpv4(data, offset + 12),
    dst: formatIpv4(data, offset + 16),
    protocol: data[offset + 9] ?? 0,
    ttl: data[offset + 8] ?? 0,
    fragmented: moreFragments || fragmentOffset > 0,
    fragmentOffset,
  };

  // totalLength 为 0 说明启用了 TSO/GSO 卸载，长度交给网卡填，此时以实际抓到的字节为准
  const declared = totalLength === 0 ? data.length - offset : totalLength;
  const payloadLength = Math.max(0, Math.min(declared - ihl, data.length - offset - ihl));

  return { network, payloadOffset: offset + ihl, payloadLength };
}

export function decodeIpv6(data: Uint8Array, offset: number): IpResult | { error: string } {
  if (data.length < offset + 40) return { error: 'IPv6 头不完整' };

  const payloadLengthField = readU16(data, offset + 4);
  const nextHeader = data[offset + 6] ?? 0;

  if (IPV6_EXTENSION_HEADERS.has(nextHeader)) {
    return { error: `IPv6 扩展头暂不支持（next header ${nextHeader}）` };
  }

  const network: NetworkInfo = {
    version: 6,
    src: formatIpv6(data, offset + 8),
    dst: formatIpv6(data, offset + 24),
    protocol: nextHeader,
    ttl: data[offset + 7] ?? 0,
    fragmented: false,
    fragmentOffset: 0,
  };

  const declared = payloadLengthField === 0 ? data.length - offset - 40 : payloadLengthField;
  const payloadLength = Math.max(0, Math.min(declared, data.length - offset - 40));

  return { network, payloadOffset: offset + 40, payloadLength };
}

function readU16(data: Uint8Array, offset: number): number {
  return ((data[offset] ?? 0) << 8) | (data[offset + 1] ?? 0);
}
