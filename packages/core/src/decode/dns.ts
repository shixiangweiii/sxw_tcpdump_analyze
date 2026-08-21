import { formatIpv4, formatIpv6 } from '../pcap/reader.js';

const TYPE_A = 1;
const TYPE_CNAME = 5;
const TYPE_AAAA = 28;

export interface DnsMapping {
  /** 域名（已去掉末尾的点） */
  name: string;
  address: string;
}

/**
 * 从 DNS 应答里提取「域名 → IP」。
 *
 * CNAME 链的处理：不显式追链，而是把问题名和应答里出现过的每个 owner name
 * 都关联到本次应答的全部 A/AAAA 地址。这样 www.baidu.com 和中间的
 * www.a.shifen.com 都能查到同一批 IP，鲁棒性比逐跳追链更好。
 */
export function extractDnsMappings(payload: Uint8Array): DnsMapping[] {
  if (payload.length < 12) return [];

  const flags = readU16(payload, 2);
  const isResponse = (flags & 0x8000) !== 0;
  const rcode = flags & 0x000f;
  if (!isResponse || rcode !== 0) return [];

  const questionCount = readU16(payload, 4);
  const answerCount = readU16(payload, 6);
  if (answerCount === 0) return [];

  let cursor = 12;
  const names: string[] = [];

  for (let i = 0; i < questionCount; i += 1) {
    const parsed = readName(payload, cursor);
    if (!parsed) return [];
    names.push(parsed.name);
    cursor = parsed.next + 4; // qtype(2) + qclass(2)
    if (cursor > payload.length) return [];
  }

  const addresses: string[] = [];

  for (let i = 0; i < answerCount; i += 1) {
    const owner = readName(payload, cursor);
    if (!owner) break;
    cursor = owner.next;
    if (cursor + 10 > payload.length) break;

    const type = readU16(payload, cursor);
    const rdLength = readU16(payload, cursor + 8);
    cursor += 10;
    if (cursor + rdLength > payload.length) break;

    if (type === TYPE_A && rdLength === 4) {
      addresses.push(formatIpv4(payload, cursor));
      names.push(owner.name);
    } else if (type === TYPE_AAAA && rdLength === 16) {
      addresses.push(formatIpv6(payload, cursor));
      names.push(owner.name);
    } else if (type === TYPE_CNAME) {
      const alias = readName(payload, cursor);
      if (alias) names.push(alias.name);
      names.push(owner.name);
    }

    cursor += rdLength;
  }

  if (addresses.length === 0) return [];

  const mappings: DnsMapping[] = [];
  const seen = new Set<string>();
  for (const name of new Set(names)) {
    if (!name) continue;
    for (const address of addresses) {
      const key = `${name}|${address}`;
      if (seen.has(key)) continue;
      seen.add(key);
      mappings.push({ name, address });
    }
  }
  return mappings;
}

interface NameResult {
  name: string;
  /** 名字之后的偏移（跟随压缩指针时不会越到指针目标处） */
  next: number;
}

/**
 * DNS 名字支持压缩指针（0xC0 前缀指回报文早先的位置）。
 * jumps 上限用来防御互相指向的恶意/损坏报文造成死循环。
 */
function readName(data: Uint8Array, start: number): NameResult | null {
  const labels: string[] = [];
  let cursor = start;
  let next = -1;
  let jumps = 0;

  while (cursor < data.length) {
    const length = data[cursor] ?? 0;

    if (length === 0) {
      cursor += 1;
      break;
    }

    if ((length & 0xc0) === 0xc0) {
      if (cursor + 1 >= data.length) return null;
      if (next < 0) next = cursor + 2;
      cursor = ((length & 0x3f) << 8) | (data[cursor + 1] ?? 0);
      jumps += 1;
      if (jumps > 64) return null;
      continue;
    }

    if ((length & 0xc0) !== 0) return null;
    if (cursor + 1 + length > data.length) return null;

    labels.push(latin1(data, cursor + 1, length));
    cursor += 1 + length;
  }

  return { name: labels.join('.').toLowerCase(), next: next >= 0 ? next : cursor };
}

function latin1(data: Uint8Array, offset: number, length: number): string {
  let out = '';
  for (let i = 0; i < length; i += 1) {
    out += String.fromCharCode(data[offset + i] ?? 0);
  }
  return out;
}

function readU16(data: Uint8Array, offset: number): number {
  return ((data[offset] ?? 0) << 8) | (data[offset + 1] ?? 0);
}
