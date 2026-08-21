import { LinkType } from '../decode/link.js';

export type TcpFlagName = 'FIN' | 'SYN' | 'RST' | 'PSH' | 'ACK' | 'URG' | 'ECE' | 'CWR';

const FLAG_BITS: Record<TcpFlagName, number> = {
  FIN: 0x01,
  SYN: 0x02,
  RST: 0x04,
  PSH: 0x08,
  ACK: 0x10,
  URG: 0x20,
  ECE: 0x40,
  CWR: 0x80,
};

export interface TcpOptionSpec {
  mss?: number;
  windowScale?: number;
  sackPermitted?: boolean;
}

export interface TcpPacketSpec {
  tsMicros: number;
  src: string;
  srcPort: number;
  dst: string;
  dstPort: number;
  seq: number;
  ack?: number;
  flags: TcpFlagName[];
  window?: number;
  payload?: Uint8Array | string;
  options?: TcpOptionSpec;
  /** VLAN 标签，仅以太网链路有效 */
  vlanId?: number;
}

export interface UdpPacketSpec {
  tsMicros: number;
  src: string;
  srcPort: number;
  dst: string;
  dstPort: number;
  payload: Uint8Array;
  vlanId?: number;
}

export interface BuilderOptions {
  linkType?: number;
  format?: 'pcap' | 'pcapng';
  /** pcapng 的 IDB 里写 if_name（例如 utun4）。经典 pcap 无此字段，传了也不生效 */
  interfaceName?: string;
}

interface Frame {
  tsMicros: number;
  bytes: Uint8Array;
}

/**
 * 逐字节构造 pcap / pcapng 文件。
 *
 * 测试夹具全部用它合成，而不是靠真实抓包：不需要 sudo、结果完全确定、能进 CI，
 * 而且可以精确制造重传/乱序/零窗口这类现实中难以复现的场景。
 * 校验和按真实规则计算，这样产出的文件同样能被 tshark / Wireshark 正常打开。
 */
export class PcapBuilder {
  private readonly frames: Frame[] = [];
  private readonly linkType: number;
  private readonly format: 'pcap' | 'pcapng';
  private readonly interfaceName: string | undefined;

  constructor(options: BuilderOptions = {}) {
    this.linkType = options.linkType ?? LinkType.ETHERNET;
    this.format = options.format ?? 'pcap';
    this.interfaceName = options.interfaceName;
  }

  tcp(spec: TcpPacketSpec): this {
    const payload =
      typeof spec.payload === 'string'
        ? new TextEncoder().encode(spec.payload)
        : (spec.payload ?? new Uint8Array(0));

    const options = buildTcpOptions(spec.options);
    const headerLength = 20 + options.length;
    const tcpSegment = new Uint8Array(headerLength + payload.length);
    const view = new DataView(tcpSegment.buffer);

    view.setUint16(0, spec.srcPort);
    view.setUint16(2, spec.dstPort);
    view.setUint32(4, spec.seq >>> 0);
    view.setUint32(8, (spec.ack ?? 0) >>> 0);
    view.setUint8(12, (headerLength / 4) << 4);
    view.setUint8(13, spec.flags.reduce((bits, flag) => bits | FLAG_BITS[flag], 0));
    view.setUint16(14, spec.window ?? 65535);
    tcpSegment.set(options, 20);
    tcpSegment.set(payload, headerLength);

    const checksum = transportChecksum(spec.src, spec.dst, 6, tcpSegment);
    view.setUint16(16, checksum);

    this.push(spec.tsMicros, spec.src, spec.dst, 6, tcpSegment, spec.vlanId);
    return this;
  }

  udp(spec: UdpPacketSpec): this {
    const datagram = new Uint8Array(8 + spec.payload.length);
    const view = new DataView(datagram.buffer);
    view.setUint16(0, spec.srcPort);
    view.setUint16(2, spec.dstPort);
    view.setUint16(4, datagram.length);
    datagram.set(spec.payload, 8);
    view.setUint16(6, transportChecksum(spec.src, spec.dst, 17, datagram));

    this.push(spec.tsMicros, spec.src, spec.dst, 17, datagram, spec.vlanId);
    return this;
  }

  build(): Uint8Array {
    return this.format === 'pcapng' ? this.buildPcapng() : this.buildClassic();
  }

  private push(
    tsMicros: number,
    src: string,
    dst: string,
    protocol: number,
    transport: Uint8Array,
    vlanId?: number,
  ): void {
    const ipPacket = buildIpv4(src, dst, protocol, transport);
    this.frames.push({ tsMicros, bytes: this.wrapLink(ipPacket, vlanId) });
  }

  private wrapLink(ipPacket: Uint8Array, vlanId?: number): Uint8Array {
    switch (this.linkType) {
      case LinkType.ETHERNET: {
        const vlanSize = vlanId === undefined ? 0 : 4;
        const frame = new Uint8Array(14 + vlanSize + ipPacket.length);
        const view = new DataView(frame.buffer);
        frame.set([0x02, 0x00, 0x00, 0x00, 0x00, 0x01], 0);
        frame.set([0x02, 0x00, 0x00, 0x00, 0x00, 0x02], 6);
        if (vlanId === undefined) {
          view.setUint16(12, 0x0800);
          frame.set(ipPacket, 14);
        } else {
          view.setUint16(12, 0x8100);
          view.setUint16(14, vlanId & 0x0fff);
          view.setUint16(16, 0x0800);
          frame.set(ipPacket, 18);
        }
        return frame;
      }

      case LinkType.LINUX_SLL: {
        // k8s pod 里 tcpdump -i any 产出的就是这种封装
        const frame = new Uint8Array(16 + ipPacket.length);
        const view = new DataView(frame.buffer);
        view.setUint16(0, 0); // packet type: 发给本机
        view.setUint16(2, 1); // ARPHRD_ETHER
        view.setUint16(4, 6); // 链路地址长度
        view.setUint16(14, 0x0800);
        frame.set(ipPacket, 16);
        return frame;
      }

      case LinkType.LINUX_SLL2: {
        const frame = new Uint8Array(20 + ipPacket.length);
        const view = new DataView(frame.buffer);
        view.setUint16(0, 0x0800);
        view.setUint32(4, 1); // interface index
        view.setUint16(8, 1); // ARPHRD_ETHER
        view.setUint8(10, 0);
        view.setUint8(11, 6);
        frame.set(ipPacket, 20);
        return frame;
      }

      case LinkType.NULL: {
        const frame = new Uint8Array(4 + ipPacket.length);
        new DataView(frame.buffer).setUint32(0, 2, true); // AF_INET，主机字节序
        frame.set(ipPacket, 4);
        return frame;
      }

      default:
        return ipPacket;
    }
  }

  private buildClassic(): Uint8Array {
    const total = 24 + this.frames.reduce((sum, frame) => sum + 16 + frame.bytes.length, 0);
    const out = new Uint8Array(total);
    const view = new DataView(out.buffer);

    view.setUint32(0, 0xa1b2c3d4); // 大端、微秒精度
    view.setUint16(4, 2);
    view.setUint16(6, 4);
    view.setInt32(8, 0);
    view.setUint32(12, 0);
    view.setUint32(16, 262144);
    view.setUint32(20, this.linkType);

    let offset = 24;
    for (const frame of this.frames) {
      view.setUint32(offset, Math.floor(frame.tsMicros / 1_000_000));
      view.setUint32(offset + 4, frame.tsMicros % 1_000_000);
      view.setUint32(offset + 8, frame.bytes.length);
      view.setUint32(offset + 12, frame.bytes.length);
      out.set(frame.bytes, offset + 16);
      offset += 16 + frame.bytes.length;
    }
    return out;
  }

  private buildPcapng(): Uint8Array {
    const blocks: Uint8Array[] = [];

    // Section Header Block
    const shb = new Uint8Array(28);
    const shbView = new DataView(shb.buffer);
    shbView.setUint32(0, 0x0a0d0d0a);
    shbView.setUint32(4, 28, true);
    shbView.setUint32(8, 0x1a2b3c4d, true);
    shbView.setUint16(12, 1, true);
    shbView.setUint16(14, 0, true);
    shbView.setBigInt64(16, -1n, true);
    shbView.setUint32(24, 28, true);
    blocks.push(shb);

    // Interface Description Block
    // 带 if_name 时要追加 option：code(2)+len(2)+value（补齐到 4 字节）+ opt_endofopt
    const nameBytes = this.interfaceName
      ? new TextEncoder().encode(this.interfaceName)
      : null;
    const optionsLength = nameBytes
      ? 4 + Math.ceil(nameBytes.length / 4) * 4 + 4
      : 0;
    const idbLength = 20 + optionsLength;

    const idb = new Uint8Array(idbLength);
    const idbView = new DataView(idb.buffer);
    idbView.setUint32(0, 0x00000001, true);
    idbView.setUint32(4, idbLength, true);
    idbView.setUint16(8, this.linkType, true);
    idbView.setUint16(10, 0, true);
    idbView.setUint32(12, 262144, true);
    if (nameBytes) {
      idbView.setUint16(16, 2, true); // if_name
      idbView.setUint16(18, nameBytes.length, true);
      idb.set(nameBytes, 20);
      // 尾部 opt_endofopt（code 0, len 0），位置在总长字段之前
      idbView.setUint16(idbLength - 8, 0, true);
      idbView.setUint16(idbLength - 6, 0, true);
    }
    idbView.setUint32(idbLength - 4, idbLength, true);
    blocks.push(idb);

    for (const frame of this.frames) {
      const padded = Math.ceil(frame.bytes.length / 4) * 4;
      const length = 32 + padded;
      const epb = new Uint8Array(length);
      const view = new DataView(epb.buffer);
      view.setUint32(0, 0x00000006, true);
      view.setUint32(4, length, true);
      view.setUint32(8, 0, true); // interface id
      const ts = BigInt(frame.tsMicros);
      view.setUint32(12, Number(ts >> 32n), true);
      view.setUint32(16, Number(ts & 0xffffffffn), true);
      view.setUint32(20, frame.bytes.length, true);
      view.setUint32(24, frame.bytes.length, true);
      epb.set(frame.bytes, 28);
      view.setUint32(length - 4, length, true);
      blocks.push(epb);
    }

    const total = blocks.reduce((sum, block) => sum + block.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const block of blocks) {
      out.set(block, offset);
      offset += block.length;
    }
    return out;
  }
}

function buildTcpOptions(spec: TcpOptionSpec | undefined): Uint8Array {
  if (!spec) return new Uint8Array(0);

  const parts: number[] = [];
  if (spec.mss !== undefined) {
    parts.push(2, 4, (spec.mss >> 8) & 0xff, spec.mss & 0xff);
  }
  if (spec.sackPermitted) {
    parts.push(4, 2);
  }
  if (spec.windowScale !== undefined) {
    parts.push(3, 3, spec.windowScale);
  }
  // 选项区必须 4 字节对齐，用 NOP 补齐
  while (parts.length % 4 !== 0) {
    parts.push(1);
  }
  return new Uint8Array(parts);
}

function buildIpv4(src: string, dst: string, protocol: number, payload: Uint8Array): Uint8Array {
  const packet = new Uint8Array(20 + payload.length);
  const view = new DataView(packet.buffer);

  view.setUint8(0, 0x45);
  view.setUint8(1, 0);
  view.setUint16(2, packet.length);
  view.setUint16(4, 0);
  view.setUint16(6, 0x4000); // Don't Fragment
  view.setUint8(8, 64);
  view.setUint8(9, protocol);
  packet.set(parseIpv4(src), 12);
  packet.set(parseIpv4(dst), 16);
  view.setUint16(10, checksum16(packet.subarray(0, 20)));
  packet.set(payload, 20);

  return packet;
}

function parseIpv4(address: string): Uint8Array {
  return Uint8Array.from(address.split('.').map((part) => Number(part) & 0xff));
}

/** TCP/UDP 校验和需要带上由源、目的、协议号、长度组成的伪首部 */
function transportChecksum(
  src: string,
  dst: string,
  protocol: number,
  segment: Uint8Array,
): number {
  const pseudo = new Uint8Array(12 + segment.length);
  pseudo.set(parseIpv4(src), 0);
  pseudo.set(parseIpv4(dst), 4);
  pseudo[9] = protocol;
  pseudo[10] = (segment.length >> 8) & 0xff;
  pseudo[11] = segment.length & 0xff;
  pseudo.set(segment, 12);
  return checksum16(pseudo);
}

function checksum16(data: Uint8Array): number {
  let sum = 0;
  for (let i = 0; i + 1 < data.length; i += 2) {
    sum += ((data[i] ?? 0) << 8) | (data[i + 1] ?? 0);
  }
  if (data.length % 2 === 1) {
    sum += (data[data.length - 1] ?? 0) << 8;
  }
  while (sum > 0xffff) {
    sum = (sum & 0xffff) + (sum >>> 16);
  }
  return ~sum & 0xffff;
}
