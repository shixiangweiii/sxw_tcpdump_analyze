import type { AnalysisResult, CaptureInfo, DecodeWarning } from '../types.js';
import { openCapture } from '../pcap/index.js';
import { decodePacket } from '../decode/packet.js';
import { linkTypeName } from '../decode/link.js';
import { extractDnsMappings } from '../decode/dns.js';
import { extractHttpHost, extractSni } from '../decode/appnames.js';
import { ConnectionTracker } from './connections.js';
import { HostRegistry } from './hosts.js';

const DNS_PORT = 53;

export interface AnalyzeOptions {
  /** 超过这个包数就停止解析，防止超大文件把内存吃满 */
  maxPackets?: number;
}

/**
 * 单趟流式分析：解码 → 喂 host 注册表 → 喂连接跟踪器 → 丢弃载荷。
 *
 * 大部分载荷只在这一趟里短暂持有（嗅探 DNS / SNI / HTTP Host）用完即弃，
 * 但**被识别为明文 HTTP 的连接会保留载荷**用于还原报文，上限见 connections.ts 的
 * SNIFF_BUDGET / HTTP_RETAIN_CAP。保留量天然被文件里的实际载荷总量封顶，
 * 实测常驻内存约为抓包文件的 1.7 倍，其中大头是解码后的正文字符串（UTF-16，双倍字节）。
 */
export function analyze(bytes: Uint8Array, options: AnalyzeOptions = {}): AnalysisResult {
  const maxPackets = options.maxPackets ?? 2_000_000;
  const capture = openCapture(bytes);
  const hosts = new HostRegistry();
  const tracker = new ConnectionTracker();
  const warnings = new Map<string, DecodeWarning>();

  let packetCount = 0;
  let decodedPackets = 0;
  let firstTsMicros: number | null = null;
  let lastTsMicros: number | null = null;
  let reachedLimit = false;

  for (const raw of capture.packets()) {
    if (packetCount >= maxPackets) {
      reachedLimit = true;
      break;
    }
    packetCount += 1;

    if (firstTsMicros === null) firstTsMicros = raw.tsMicros;
    lastTsMicros = raw.tsMicros;

    const { packet, error } = decodePacket(raw);

    if (packet.network) {
      const { src, dst, version } = packet.network;
      hosts.observeAddress(src, version);
      hosts.observeAddress(dst, version);
    }

    if (error) {
      recordWarning(warnings, error, raw.index);
      // 有 IP 头但传输层没解出来的包（分片、ICMP 等）仍计入 host 流量
      if (packet.network) {
        hosts.countOther(packet.network.src, packet.network.version);
        hosts.countOther(packet.network.dst, packet.network.version);
      }
      continue;
    }

    if (!packet.network || !packet.transport) continue;
    decodedPackets += 1;

    const { src, dst, version } = packet.network;

    if (packet.transport.kind === 'tcp') {
      const tcp = packet.transport;
      hosts.countTcp(src, version);
      hosts.countTcp(dst, version);

      if (packet.payload && packet.payload.length > 0) {
        // SNI 只出现在客户端发出的第一个 TLS 记录里，Host 头只出现在请求首包，
        // 两者都在连接早期，因此不需要缓存跨包状态
        const sni = extractSni(packet.payload);
        if (sni) hosts.addName(dst, sni, 'sni', packet.index);

        const httpHost = extractHttpHost(packet.payload);
        if (httpHost) hosts.addName(dst, httpHost, 'http-host', packet.index);
      }

      // 载荷在这里交给连接跟踪器，由它按协议嗅探结果决定留不留——
      // 只有可能是 HTTP 的连接才会保留，其余仍然即用即弃
      tracker.add(packet.index, packet.tsMicros, packet.network, tcp, packet.payload);
      continue;
    }

    const udp = packet.transport;
    hosts.countUdp(src, version, udp.srcPort);
    hosts.countUdp(dst, version, udp.dstPort);

    if (
      packet.payload &&
      packet.payload.length > 0 &&
      (udp.srcPort === DNS_PORT || udp.dstPort === DNS_PORT)
    ) {
      for (const mapping of extractDnsMappings(packet.payload)) {
        hosts.addName(mapping.address, mapping.name, 'dns', packet.index);
      }
    }
  }

  if (reachedLimit) {
    recordWarning(
      warnings,
      `包数超过上限 ${maxPackets}，后续内容未解析`,
      maxPackets,
    );
  }

  const connections = tracker.finish();

  const connectionCounts = new Map<string, number>();
  for (const connection of connections) {
    connectionCounts.set(
      connection.clientAddr,
      (connectionCounts.get(connection.clientAddr) ?? 0) + 1,
    );
    connectionCounts.set(
      connection.serverAddr,
      (connectionCounts.get(connection.serverAddr) ?? 0) + 1,
    );
  }

  // linkTypes / interfaceNames 对 pcapng 而言要迭代完所有 block 才完整，必须在循环之后取
  const linkTypes = capture.linkTypes;
  const captureInfo: CaptureInfo = {
    format: capture.format,
    linkTypes,
    linkTypeNames: linkTypes.map(linkTypeName),
    interfaceNames: capture.interfaceNames,
    packetCount,
    decodedPackets,
    firstTsMicros,
    lastTsMicros,
    durationMicros:
      firstTsMicros !== null && lastTsMicros !== null ? lastTsMicros - firstTsMicros : 0,
    warnings: [...warnings.values()].sort((a, b) => b.count - a.count),
    truncated: capture.truncated,
  };

  return { capture: captureInfo, hosts: hosts.build(connectionCounts), connections };
}

function recordWarning(warnings: Map<string, DecodeWarning>, reason: string, packet: number): void {
  const existing = warnings.get(reason);
  if (existing) {
    existing.count += 1;
    return;
  }
  warnings.set(reason, { reason, count: 1, firstPacket: packet });
}
