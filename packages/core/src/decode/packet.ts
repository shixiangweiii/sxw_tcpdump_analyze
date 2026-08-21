import type { DecodedPacket, RawPacket } from '../types.js';
import { decodeLink } from './link.js';
import { IpProtocol, decodeIpv4, decodeIpv6 } from './ip.js';
import { decodeTcp, decodeUdp } from './transport.js';

export interface DecodeOutcome {
  packet: DecodedPacket;
  /** 解码在哪一层停下了。上层据此聚合告警 */
  error?: string;
}

/**
 * 把一个原始帧解到传输层。
 * 任何一层失败都不抛异常——抓包文件里混入 ARP、IPv6 扩展头、被 snaplen 截断的包都是常态，
 * 单个包解不动不应该让整个分析失败，只记录原因。
 */
export function decodePacket(raw: RawPacket): DecodeOutcome {
  const packet: DecodedPacket = {
    index: raw.index,
    tsMicros: raw.tsMicros,
    capturedLength: raw.capturedLength,
    originalLength: raw.originalLength,
  };

  const link = decodeLink(raw.data, raw.linkType);
  if ('error' in link) return { packet, error: link.error };

  const ip =
    link.ipVersion === 4
      ? decodeIpv4(raw.data, link.offset)
      : decodeIpv6(raw.data, link.offset);
  if ('error' in ip) return { packet, error: ip.error };

  packet.network = ip.network;

  // 分片包除首片外没有传输层头，强行解会读到数据当端口号
  if (ip.network.fragmented && ip.network.fragmentOffset > 0) {
    return { packet, error: 'IP 分片（非首片），不做重组' };
  }

  if (ip.network.protocol === IpProtocol.TCP) {
    const tcp = decodeTcp(raw.data, ip.payloadOffset, ip.payloadLength);
    if ('error' in tcp) return { packet, error: tcp.error };
    packet.transport = tcp;

    const payloadStart = ip.payloadOffset + tcp.headerLength;
    const payloadEnd = Math.min(payloadStart + tcp.payloadLength, raw.data.length);
    if (payloadEnd > payloadStart) {
      packet.payload = raw.data.subarray(payloadStart, payloadEnd);
    }
    return { packet };
  }

  if (ip.network.protocol === IpProtocol.UDP) {
    const udp = decodeUdp(raw.data, ip.payloadOffset, ip.payloadLength);
    if ('error' in udp) return { packet, error: udp.error };
    packet.transport = udp;

    const payloadStart = ip.payloadOffset + 8;
    const payloadEnd = Math.min(payloadStart + udp.payloadLength, raw.data.length);
    if (payloadEnd > payloadStart) {
      packet.payload = raw.data.subarray(payloadStart, payloadEnd);
    }
    return { packet };
  }

  return { packet, error: `非 TCP/UDP（IP 协议号 ${ip.network.protocol}）` };
}
