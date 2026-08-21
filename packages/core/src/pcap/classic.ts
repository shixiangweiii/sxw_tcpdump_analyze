import type { RawPacket } from '../types.js';
import { ByteReader } from './reader.js';

const MAGIC_LE_MICRO = 0xd4c3b2a1;
const MAGIC_BE_MICRO = 0xa1b2c3d4;
const MAGIC_LE_NANO = 0x4d3cb2a1;
const MAGIC_BE_NANO = 0xa1b23c4d;

export interface ClassicHeader {
  littleEndian: boolean;
  nanoseconds: boolean;
  versionMajor: number;
  versionMinor: number;
  snaplen: number;
  linkType: number;
}

/** 读前 4 字节判断是否为经典 pcap，并给出字节序与时间精度 */
export function sniffClassic(bytes: Uint8Array): Pick<ClassicHeader, 'littleEndian' | 'nanoseconds'> | null {
  if (bytes.byteLength < 4) return null;
  const magic = new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, false);
  switch (magic) {
    case MAGIC_BE_MICRO:
      return { littleEndian: false, nanoseconds: false };
    case MAGIC_LE_MICRO:
      return { littleEndian: true, nanoseconds: false };
    case MAGIC_BE_NANO:
      return { littleEndian: false, nanoseconds: true };
    case MAGIC_LE_NANO:
      return { littleEndian: true, nanoseconds: true };
    default:
      return null;
  }
}

/**
 * 经典 pcap（tcpdump -w 的默认产物）。
 * 全局头 24 字节，之后每个包 16 字节记录头 + 数据。
 */
export class ClassicPcapReader {
  readonly header: ClassicHeader;
  truncated = false;

  constructor(private readonly bytes: Uint8Array) {
    const sniff = sniffClassic(bytes);
    if (!sniff) {
      throw new Error('不是合法的 pcap 文件：魔数不匹配');
    }
    if (bytes.byteLength < 24) {
      throw new Error('pcap 文件头不完整（不足 24 字节）');
    }
    const reader = new ByteReader(bytes, sniff.littleEndian);
    reader.skip(4); // magic
    const versionMajor = reader.u16();
    const versionMinor = reader.u16();
    reader.i32(); // thiszone，现代抓包一律为 0，忽略
    reader.u32(); // sigfigs，实际从未被使用
    const snaplen = reader.u32();
    const linkType = reader.u32();

    this.header = { ...sniff, versionMajor, versionMinor, snaplen, linkType };
  }

  get linkTypes(): number[] {
    return [this.header.linkType];
  }

  /** 经典 pcap 的全局头里没有接口名字段 */
  get interfaceNames(): string[] {
    return [];
  }

  *packets(): Generator<RawPacket> {
    const { littleEndian, nanoseconds, linkType } = this.header;
    const reader = new ByteReader(this.bytes, littleEndian);
    reader.seek(24);

    let index = 0;
    while (reader.remaining > 0) {
      // 记录头必须完整，否则视为文件被截断（抓包进程被强杀时很常见）
      if (reader.remaining < 16) {
        this.truncated = true;
        return;
      }
      const tsSec = reader.u32();
      const tsFrac = reader.u32();
      const capturedLength = reader.u32();
      const originalLength = reader.u32();

      if (capturedLength > reader.remaining) {
        this.truncated = true;
        return;
      }
      const data = reader.bytesOf(capturedLength);

      yield {
        index: index++,
        tsMicros: tsSec * 1_000_000 + (nanoseconds ? Math.floor(tsFrac / 1000) : tsFrac),
        capturedLength,
        originalLength,
        linkType,
        data,
      };
    }
  }
}
