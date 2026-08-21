import type { AnalysisResult, Connection, HostEntry, HostView } from '../types.js';

/** 输入串看起来像 IP 字面量（而不是域名）吗 */
export function looksLikeIpLiteral(query: string): boolean {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(query)) {
    return query.split('.').every((part) => Number(part) <= 255);
  }
  // IPv6 至少含两个冒号，且只由十六进制、冒号、点组成
  return query.includes(':') && /^[0-9a-fA-F:.]+$/.test(query);
}

export interface HostMatch {
  addresses: Set<string>;
  names: string[];
}

/**
 * 把用户输入解析成一组 IP。
 *
 * IP 字面量直接命中；域名则查 host 注册表里由 DNS / SNI / Host 头建立的映射。
 * 域名与 IP 是多对多关系（CDN 一个域名多个 IP、一个 IP 承载多个域名），
 * 所以返回的是集合而不是单值。
 */
export function resolveHost(hosts: HostEntry[], query: string): HostMatch {
  const normalized = query.trim().toLowerCase();
  const addresses = new Set<string>();
  const names = new Set<string>();

  if (!normalized) return { addresses, names: [] };

  if (looksLikeIpLiteral(normalized)) {
    for (const host of hosts) {
      if (host.address.toLowerCase() === normalized) {
        addresses.add(host.address);
        for (const evidence of host.names) names.add(evidence.name);
      }
    }
    return { addresses, names: [...names] };
  }

  for (const host of hosts) {
    for (const evidence of host.names) {
      if (evidence.name === normalized) {
        addresses.add(host.address);
        names.add(evidence.name);
      }
    }
  }
  return { addresses, names: [...names] };
}

/**
 * 按 host 过滤连接，并自动推断视角。
 *
 * 视角这件事之所以要自动判断：抓包位置决定了同一个输入的含义。在自己机器上抓包时
 * 输入某域名意味着「我访问它」，在 nginx 服务端抓包时则意味着「别人访问我」。
 * 与其让用户去理解这个概念，不如看 host 落在连接的哪一侧，然后把结论直接写在界面上。
 */
export function buildHostView(result: AnalysisResult, query: string): HostView {
  const match = resolveHost(result.hosts, query);
  const connections: Connection[] = [];

  let asServer = 0;
  let asClient = 0;

  for (const connection of result.connections) {
    const hostIsServer = match.addresses.has(connection.serverAddr);
    const hostIsClient = match.addresses.has(connection.clientAddr);
    if (!hostIsServer && !hostIsClient) continue;

    connections.push(connection);
    if (hostIsServer) asServer += 1;
    if (hostIsClient) asClient += 1;
  }

  let nonTcpUdp = 0;
  let nonTcpQuic = 0;
  let nonTcpOther = 0;
  for (const host of result.hosts) {
    if (!match.addresses.has(host.address)) continue;
    nonTcpUdp += host.udpPackets;
    nonTcpQuic += host.quicPackets;
    nonTcpOther += host.otherPackets;
  }

  return {
    query,
    matchedAddresses: [...match.addresses],
    matchedNames: match.names,
    perspective:
      asServer > 0 && asClient > 0
        ? 'mixed'
        : asClient > asServer
          ? 'host-as-client'
          : 'host-as-server',
    connections,
    nonTcp: { udpPackets: nonTcpUdp, quicPackets: nonTcpQuic, otherPackets: nonTcpOther },
  };
}
