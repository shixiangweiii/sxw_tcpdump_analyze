import type { CaptureFormat, RawPacket } from '../types.js';
import { ClassicPcapReader, sniffClassic } from './classic.js';
import { PcapngReader, sniffPcapng } from './pcapng.js';

export interface CaptureReader {
  format: CaptureFormat;
  /** 已观察到的链路类型。pcapng 可能有多个接口，需要迭代后才完整 */
  readonly linkTypes: number[];
  /** 抓包接口名。仅 pcapng 的 IDB 携带该信息，经典 pcap 恒为空 */
  readonly interfaceNames: string[];
  /** 迭代过程中发现文件被截断时置位 */
  readonly truncated: boolean;
  packets(): Generator<RawPacket>;
}

/**
 * 按魔数自动识别容器格式。
 * tcpdump -w 产出经典 pcap，Wireshark 默认另存为 pcapng，两种都必须支持。
 */
export function openCapture(bytes: Uint8Array): CaptureReader {
  if (sniffPcapng(bytes)) {
    const reader = new PcapngReader(bytes);
    return {
      format: 'pcapng',
      get linkTypes() {
        return reader.linkTypes;
      },
      get interfaceNames() {
        return reader.interfaceNames;
      },
      get truncated() {
        return reader.truncated;
      },
      packets: () => reader.packets(),
    };
  }

  if (sniffClassic(bytes)) {
    const reader = new ClassicPcapReader(bytes);
    return {
      format: 'pcap',
      get linkTypes() {
        return reader.linkTypes;
      },
      get interfaceNames() {
        return reader.interfaceNames;
      },
      get truncated() {
        return reader.truncated;
      },
      packets: () => reader.packets(),
    };
  }

  throw new Error(
    '无法识别的文件格式：既不是 pcap 也不是 pcapng。请确认这是 tcpdump -w 或 Wireshark 保存的抓包文件。',
  );
}

export { ClassicPcapReader, PcapngReader, sniffClassic, sniffPcapng };
export { ByteReader, formatIpv4, formatIpv6 } from './reader.js';
