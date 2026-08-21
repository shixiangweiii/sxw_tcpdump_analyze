/** 带边界检查的字节读取器。所有容器/协议解析都走这里，避免各处手写越界判断。 */
export class ByteReader {
  private readonly view: DataView;
  private offset = 0;

  constructor(
    private readonly bytes: Uint8Array,
    private littleEndian = false,
  ) {
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }

  get position(): number {
    return this.offset;
  }

  get remaining(): number {
    return this.bytes.byteLength - this.offset;
  }

  get isLittleEndian(): boolean {
    return this.littleEndian;
  }

  setLittleEndian(le: boolean): void {
    this.littleEndian = le;
  }

  has(count: number): boolean {
    return this.remaining >= count;
  }

  seek(offset: number): void {
    if (offset < 0 || offset > this.bytes.byteLength) {
      throw new RangeError(`seek 越界: ${offset} / ${this.bytes.byteLength}`);
    }
    this.offset = offset;
  }

  skip(count: number): void {
    this.seek(this.offset + count);
  }

  u8(): number {
    this.require(1);
    return this.view.getUint8(this.offset++);
  }

  u16(): number {
    this.require(2);
    const value = this.view.getUint16(this.offset, this.littleEndian);
    this.offset += 2;
    return value;
  }

  u16be(): number {
    this.require(2);
    const value = this.view.getUint16(this.offset, false);
    this.offset += 2;
    return value;
  }

  u32(): number {
    this.require(4);
    const value = this.view.getUint32(this.offset, this.littleEndian);
    this.offset += 4;
    return value;
  }

  u32be(): number {
    this.require(4);
    const value = this.view.getUint32(this.offset, false);
    this.offset += 4;
    return value;
  }

  i32(): number {
    this.require(4);
    const value = this.view.getInt32(this.offset, this.littleEndian);
    this.offset += 4;
    return value;
  }

  bytesOf(count: number): Uint8Array {
    this.require(count);
    const slice = this.bytes.subarray(this.offset, this.offset + count);
    this.offset += count;
    return slice;
  }

  /** 剩余全部字节 */
  rest(): Uint8Array {
    return this.bytesOf(this.remaining);
  }

  private require(count: number): void {
    if (this.remaining < count) {
      throw new RangeError(`读取越界: 需要 ${count} 字节，仅剩 ${this.remaining}`);
    }
  }
}

/** 4 字节点分十进制 */
export function formatIpv4(bytes: Uint8Array, offset: number): string {
  return `${bytes[offset]}.${bytes[offset + 1]}.${bytes[offset + 2]}.${bytes[offset + 3]}`;
}

/**
 * 16 字节 IPv6 地址，按 RFC 5952 规范化：小写、去前导零、最长零段压缩为 ::
 */
export function formatIpv6(bytes: Uint8Array, offset: number): string {
  const groups: number[] = [];
  for (let i = 0; i < 8; i += 1) {
    groups.push(((bytes[offset + i * 2] ?? 0) << 8) | (bytes[offset + i * 2 + 1] ?? 0));
  }

  // 找最长的连续零段（长度需 >= 2 才压缩）
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;
  for (let i = 0; i < 8; i += 1) {
    if (groups[i] === 0) {
      if (curStart < 0) curStart = i;
      curLen += 1;
      if (curLen > bestLen) {
        bestStart = curStart;
        bestLen = curLen;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }
  if (bestLen < 2) {
    bestStart = -1;
  }

  const parts: string[] = [];
  for (let i = 0; i < 8; i += 1) {
    if (bestStart >= 0 && i === bestStart) {
      parts.push('');
      i += bestLen - 1;
      if (bestStart === 0) parts.push('');
      if (bestStart + bestLen === 8) parts.push('');
      continue;
    }
    parts.push((groups[i] ?? 0).toString(16));
  }
  return parts.join(':');
}
