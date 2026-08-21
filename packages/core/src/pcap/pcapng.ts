import type { RawPacket } from '../types.js';
import { ByteReader } from './reader.js';

const BLOCK_SHB = 0x0a0d0d0a;
const BLOCK_IDB = 0x00000001;
const BLOCK_EPB = 0x00000006;
const BYTE_ORDER_MAGIC = 0x1a2b3c4d;

interface InterfaceDescription {
  linkType: number;
  /** if_tsresol 原始值，默认 6（微秒） */
  tsResolution: number;
  /** if_name，例如 en0 / utun4。抓包接口决定了 DLT_NULL 到底是回环还是隧道 */
  name?: string;
}

/** 判断是否为 pcapng：第一个 block 必须是 SHB */
export function sniffPcapng(bytes: Uint8Array): boolean {
  if (bytes.byteLength < 12) return false;
  const view = new DataView(bytes.buffer, bytes.byteOffset, 12);
  return view.getUint32(0, false) === BLOCK_SHB;
}

/**
 * pcapng（Wireshark 默认另存格式）。
 * 只实现 SHB / IDB / EPB 三种 block，其余 block（NRB、ISB、DSB 等）按长度跳过。
 */
export class PcapngReader {
  truncated = false;
  private readonly seenLinkTypes = new Set<number>();
  private readonly seenInterfaceNames = new Set<string>();

  constructor(private readonly bytes: Uint8Array) {
    if (!sniffPcapng(bytes)) {
      throw new Error('不是合法的 pcapng 文件：首个 block 不是 Section Header Block');
    }
  }

  get linkTypes(): number[] {
    return [...this.seenLinkTypes];
  }

  get interfaceNames(): string[] {
    return [...this.seenInterfaceNames];
  }

  *packets(): Generator<RawPacket> {
    const reader = new ByteReader(this.bytes, false);
    let interfaces: InterfaceDescription[] = [];
    let index = 0;

    while (reader.remaining > 0) {
      if (reader.remaining < 12) {
        this.truncated = true;
        return;
      }

      const blockStart = reader.position;
      // block 类型也受 section 字节序影响。首个 SHB 的 0x0A0D0D0A 是字节回文，
      // 两种读法结果相同，因此可以安全地在还不知道字节序时先读它。
      const blockType = reader.u32();

      // SHB 自带字节序标记，需要先探测再决定后续所有字段的读法
      if (blockType === BLOCK_SHB) {
        const bomProbe = new DataView(
          this.bytes.buffer,
          this.bytes.byteOffset + blockStart + 8,
          4,
        );
        const littleEndian = bomProbe.getUint32(0, true) === BYTE_ORDER_MAGIC;
        if (!littleEndian && bomProbe.getUint32(0, false) !== BYTE_ORDER_MAGIC) {
          throw new Error('pcapng Section Header Block 的字节序标记非法');
        }
        reader.setLittleEndian(littleEndian);
        // 新的 section 意味着接口列表重新编号
        interfaces = [];
      }

      const blockLength = reader.u32();
      // block 长度必须 >= 12 且 4 字节对齐，否则无法继续推进，直接判定为损坏
      if (blockLength < 12 || blockLength % 4 !== 0) {
        this.truncated = true;
        return;
      }
      if (blockStart + blockLength > this.bytes.byteLength) {
        this.truncated = true;
        return;
      }

      const bodyLength = blockLength - 12;
      const body = reader.bytesOf(bodyLength);
      reader.skip(4); // 尾部重复的 block_total_length

      if (blockType === BLOCK_IDB) {
        interfaces.push(this.parseInterfaceDescription(body, reader));
      } else if (blockType === BLOCK_EPB) {
        const packet = this.parseEnhancedPacket(body, reader, interfaces, index);
        if (packet) {
          index += 1;
          yield packet;
        }
      }
    }
  }

  private parseInterfaceDescription(body: Uint8Array, outer: ByteReader): InterfaceDescription {
    const reader = new ByteReader(body, outer.isLittleEndian);
    const linkType = reader.u16();
    reader.u16(); // reserved
    reader.u32(); // snaplen

    let tsResolution = 6;
    let name: string | undefined;
    for (const option of this.readOptions(reader)) {
      // if_name
      if (option.code === 2 && option.value.length > 0) {
        name = latin1(option.value);
      }
      // if_tsresol
      if (option.code === 9 && option.value.length >= 1) {
        tsResolution = option.value[0] ?? 6;
      }
    }

    this.seenLinkTypes.add(linkType);
    if (name) this.seenInterfaceNames.add(name);
    return { linkType, tsResolution, name };
  }

  private parseEnhancedPacket(
    body: Uint8Array,
    outer: ByteReader,
    interfaces: InterfaceDescription[],
    index: number,
  ): RawPacket | null {
    const reader = new ByteReader(body, outer.isLittleEndian);

    if (body.byteLength < 20) return null;
    const interfaceId = reader.u32();
    const tsHigh = reader.u32();
    const tsLow = reader.u32();
    const capturedLength = reader.u32();
    const originalLength = reader.u32();

    if (capturedLength > reader.remaining) {
      this.truncated = true;
      return null;
    }
    const data = reader.bytesOf(capturedLength);

    const iface = interfaces[interfaceId];
    const linkType = iface?.linkType ?? 1;
    this.seenLinkTypes.add(linkType);

    return {
      index,
      tsMicros: toMicros(tsHigh, tsLow, iface?.tsResolution ?? 6),
      capturedLength,
      originalLength,
      linkType,
      data,
    };
  }

  /** option 序列：code(2) + length(2) + value（补齐到 4 字节），以 code=0 结束 */
  private *readOptions(reader: ByteReader): Generator<{ code: number; value: Uint8Array }> {
    while (reader.remaining >= 4) {
      const code = reader.u16();
      const length = reader.u16();
      if (code === 0) return;
      if (length > reader.remaining) return;
      const value = reader.bytesOf(length);
      const padding = (4 - (length % 4)) % 4;
      if (padding > reader.remaining) return;
      reader.skip(padding);
      yield { code, value };
    }
  }
}

/**
 * pcapng 时间戳是 64 位整数 + 每接口自定义精度。
 * 用 BigInt 拼接避免 53 位精度丢失，再换算成微秒。
 */
function toMicros(high: number, low: number, tsResolution: number): number {
  const raw = (BigInt(high >>> 0) << 32n) | BigInt(low >>> 0);

  // 最高位为 0 表示十进制负幂，为 1 表示二进制负幂
  if ((tsResolution & 0x80) === 0) {
    const exp = tsResolution;
    if (exp <= 6) {
      return Number(raw * 10n ** BigInt(6 - exp));
    }
    return Number(raw / 10n ** BigInt(exp - 6));
  }

  const exp = BigInt(tsResolution & 0x7f);
  return Number((raw * 1_000_000n) >> exp);
}

/** option 里的字符串按 UTF-8 存，但接口名实际只用 ASCII；尾部可能带 NUL 填充 */
function latin1(value: Uint8Array): string {
  let out = '';
  for (const byte of value) {
    if (byte === 0) break;
    out += String.fromCharCode(byte);
  }
  return out;
}
