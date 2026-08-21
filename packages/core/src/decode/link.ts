/** libpcap 链路类型常量。只列出本工具支持的。 */
export const LinkType = {
  NULL: 0,
  ETHERNET: 1,
  RAW_BSD: 12,
  RAW: 101,
  LOOP: 108,
  LINUX_SLL: 113,
  LINUX_SLL2: 276,
} as const;

const LINK_TYPE_NAMES: Record<number, string> = {
  [LinkType.NULL]: 'NULL（本机回环）',
  [LinkType.ETHERNET]: 'EN10MB（以太网）',
  [LinkType.RAW_BSD]: 'RAW（裸 IP）',
  [LinkType.RAW]: 'RAW（裸 IP）',
  [LinkType.LOOP]: 'LOOP（本机回环）',
  [LinkType.LINUX_SLL]: 'LINUX_SLL（tcpdump -i any）',
  [LinkType.LINUX_SLL2]: 'LINUX_SLL2（tcpdump -i any，新版）',
};

export function linkTypeName(linkType: number): string {
  return LINK_TYPE_NAMES[linkType] ?? `未知链路类型 ${linkType}`;
}

const ETHERTYPE_IPV4 = 0x0800;
const ETHERTYPE_IPV6 = 0x86dd;
const VLAN_ETHERTYPES = new Set([0x8100, 0x88a8, 0x9100, 0x9200]);

/** BSD/Linux 的 AF_INET6 取值各不相同，全部接受 */
const AF_INET = 2;
const AF_INET6_VALUES = new Set([10, 23, 24, 28, 30]);

export interface LinkResult {
  /** 网络层的起始偏移 */
  offset: number;
  ipVersion: 4 | 6;
  /** 剥掉的 VLAN ID，按外层到内层顺序 */
  vlanIds: number[];
}

/**
 * 剥掉链路层，返回 IP 头的起始位置。
 * 无法识别或非 IP 流量（ARP 等）时返回失败原因，由上层聚合成解码告警。
 */
export function decodeLink(
  data: Uint8Array,
  linkType: number,
): LinkResult | { error: string } {
  switch (linkType) {
    case LinkType.ETHERNET:
      return decodeEthernet(data, 12, []);

    case LinkType.LINUX_SLL: {
      // packet_type(2) arphrd(2) addr_len(2) addr(8) protocol(2)
      if (data.length < 16) return { error: 'LINUX_SLL 头不完整' };
      return decodeEthertype(data, readU16(data, 14), 16, []);
    }

    case LinkType.LINUX_SLL2: {
      // protocol(2) reserved(2) ifindex(4) arphrd(2) pkt_type(1) addr_len(1) addr(8)
      if (data.length < 20) return { error: 'LINUX_SLL2 头不完整' };
      return decodeEthertype(data, readU16(data, 0), 20, []);
    }

    case LinkType.NULL:
      return decodeLoopback(data, true);

    case LinkType.LOOP:
      return decodeLoopback(data, false);

    case LinkType.RAW:
    case LinkType.RAW_BSD:
      return decodeRawIp(data, 0);

    default:
      return { error: `不支持的链路类型 ${linkType}` };
  }
}

function decodeEthernet(data: Uint8Array, typeOffset: number, vlanIds: number[]): LinkResult | { error: string } {
  if (data.length < typeOffset + 2) return { error: '以太网头不完整' };
  const etherType = readU16(data, typeOffset);

  // VLAN tag：TCI(2) + 内层 ethertype(2)，可以多层嵌套（QinQ）
  if (VLAN_ETHERTYPES.has(etherType)) {
    if (data.length < typeOffset + 6) return { error: 'VLAN 标签不完整' };
    const tci = readU16(data, typeOffset + 2);
    return decodeEthernet(data, typeOffset + 4, [...vlanIds, tci & 0x0fff]);
  }

  return decodeEthertype(data, etherType, typeOffset + 2, vlanIds);
}

function decodeEthertype(
  data: Uint8Array,
  etherType: number,
  offset: number,
  vlanIds: number[],
): LinkResult | { error: string } {
  if (VLAN_ETHERTYPES.has(etherType)) {
    // SLL 封装的 VLAN：此处 offset 指向 TCI
    if (data.length < offset + 4) return { error: 'VLAN 标签不完整' };
    const tci = readU16(data, offset);
    return decodeEthertype(data, readU16(data, offset + 2), offset + 4, [...vlanIds, tci & 0x0fff]);
  }
  if (etherType === ETHERTYPE_IPV4) return { offset, ipVersion: 4, vlanIds };
  if (etherType === ETHERTYPE_IPV6) return { offset, ipVersion: 6, vlanIds };
  return { error: `非 IP 流量（ethertype 0x${etherType.toString(16).padStart(4, '0')}）` };
}

/**
 * BSD 回环封装：4 字节地址族。
 * NULL 用抓包机的主机字节序，LOOP 固定网络字节序，因此 NULL 需要两种读法都试。
 */
function decodeLoopback(data: Uint8Array, hostOrder: boolean): LinkResult | { error: string } {
  if (data.length < 4) return { error: '回环链路头不完整' };
  const candidates = hostOrder
    ? [readU32LE(data, 0), readU32BE(data, 0)]
    : [readU32BE(data, 0)];

  for (const af of candidates) {
    if (af === AF_INET) return { offset: 4, ipVersion: 4, vlanIds: [] };
    if (AF_INET6_VALUES.has(af)) return { offset: 4, ipVersion: 6, vlanIds: [] };
  }
  return { error: `回环链路的地址族无法识别（${candidates[0]}）` };
}

/** 裸 IP：没有链路层，直接看首字节的版本号 */
function decodeRawIp(data: Uint8Array, offset: number): LinkResult | { error: string } {
  if (data.length < offset + 1) return { error: '裸 IP 包为空' };
  const version = ((data[offset] ?? 0) & 0xf0) >> 4;
  if (version === 4) return { offset, ipVersion: 4, vlanIds: [] };
  if (version === 6) return { offset, ipVersion: 6, vlanIds: [] };
  return { error: `裸 IP 包的版本号非法（${version}）` };
}

function readU16(data: Uint8Array, offset: number): number {
  return ((data[offset] ?? 0) << 8) | (data[offset + 1] ?? 0);
}

function readU32BE(data: Uint8Array, offset: number): number {
  return (
    (((data[offset] ?? 0) << 24) |
      ((data[offset + 1] ?? 0) << 16) |
      ((data[offset + 2] ?? 0) << 8) |
      (data[offset + 3] ?? 0)) >>>
    0
  );
}

function readU32LE(data: Uint8Array, offset: number): number {
  return (
    (((data[offset + 3] ?? 0) << 24) |
      ((data[offset + 2] ?? 0) << 16) |
      ((data[offset + 1] ?? 0) << 8) |
      (data[offset] ?? 0)) >>>
    0
  );
}
