import type { HostEntry, HostNameSource } from '../types.js';

interface MutableHost {
  address: string;
  ipVersion: 4 | 6;
  names: Map<string, { source: HostNameSource; firstSeenPacket: number; observations: number }>;
  tcpPackets: number;
  udpPackets: number;
  quicPackets: number;
  otherPackets: number;
}

/**
 * 记录抓包里出现过的所有 IP，以及「这个 IP 属于哪个域名」的证据。
 *
 * 证据有三个来源，可靠性递减：
 *  1. DNS 应答      —— 最直接，但抓包晚于 DNS 查询时（连接池复用）就没有
 *  2. TLS SNI       —— HTTPS 下仍是明文，是主要兜底手段
 *  3. HTTP Host 头  —— 只有明文 HTTP 才有
 *
 * 保留证据来源是为了让界面能解释「为什么这个 IP 算作这个域名」，
 * 而不是让用户面对一个凭空出现的映射。
 */
export class HostRegistry {
  private readonly hosts = new Map<string, MutableHost>();

  observeAddress(address: string, ipVersion: 4 | 6): void {
    this.ensure(address, ipVersion);
  }

  countTcp(address: string, ipVersion: 4 | 6): void {
    this.ensure(address, ipVersion).tcpPackets += 1;
  }

  countUdp(address: string, ipVersion: 4 | 6, port: number): void {
    const host = this.ensure(address, ipVersion);
    host.udpPackets += 1;
    // UDP/443 基本可以断定是 QUIC（HTTP/3）
    if (port === 443) host.quicPackets += 1;
  }

  countOther(address: string, ipVersion: 4 | 6): void {
    this.ensure(address, ipVersion).otherPackets += 1;
  }

  addName(address: string, name: string, source: HostNameSource, packetIndex: number): void {
    if (!name) return;
    const ipVersion = address.includes(':') ? 6 : 4;
    const host = this.ensure(address, ipVersion);
    const key = `${name}|${source}`;
    const existing = host.names.get(key);
    if (existing) {
      existing.observations += 1;
      return;
    }
    host.names.set(key, { source, firstSeenPacket: packetIndex, observations: 1 });
  }

  build(connectionCounts: Map<string, number>): HostEntry[] {
    const entries: HostEntry[] = [];

    for (const host of this.hosts.values()) {
      const names = [...host.names.entries()]
        .map(([key, value]) => ({
          name: key.slice(0, key.lastIndexOf('|')),
          source: value.source,
          firstSeenPacket: value.firstSeenPacket,
          observations: value.observations,
        }))
        // DNS 证据最可信，排在最前面
        .sort((a, b) => sourceRank(a.source) - sourceRank(b.source) || a.name.localeCompare(b.name));

      entries.push({
        address: host.address,
        ipVersion: host.ipVersion,
        names,
        tcpPackets: host.tcpPackets,
        udpPackets: host.udpPackets,
        quicPackets: host.quicPackets,
        otherPackets: host.otherPackets,
        connectionCount: connectionCounts.get(host.address) ?? 0,
      });
    }

    // 界面上按「谁的流量多」排序，用户通常想看的就在最前面
    return entries.sort(
      (a, b) =>
        b.connectionCount - a.connectionCount ||
        b.tcpPackets + b.udpPackets - (a.tcpPackets + a.udpPackets) ||
        a.address.localeCompare(b.address),
    );
  }

  private ensure(address: string, ipVersion: 4 | 6): MutableHost {
    let host = this.hosts.get(address);
    if (!host) {
      host = {
        address,
        ipVersion,
        names: new Map(),
        tcpPackets: 0,
        udpPackets: 0,
        quicPackets: 0,
        otherPackets: 0,
      };
      this.hosts.set(address, host);
    }
    return host;
  }
}

function sourceRank(source: HostNameSource): number {
  switch (source) {
    case 'dns':
      return 0;
    case 'sni':
      return 1;
    default:
      return 2;
  }
}
