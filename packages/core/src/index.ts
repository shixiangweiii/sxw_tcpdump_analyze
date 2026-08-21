export * from './types.js';

export { openCapture, type CaptureReader } from './pcap/index.js';
export { LinkType, linkTypeName } from './decode/link.js';
export { decodePacket } from './decode/packet.js';
export { flagNames } from './decode/transport.js';
export { extractDnsMappings } from './decode/dns.js';
export { extractHttpHost, extractSni } from './decode/appnames.js';

export { analyze, type AnalyzeOptions } from './analyze/analyzer.js';
export {
  buildHostView,
  looksLikeIpLiteral,
  resolveHost,
  type HostMatch,
} from './analyze/hostview.js';
export {
  anomalyLabel,
  formatBytes,
  formatDuration,
  outcomeLabel,
  type AnomalyLabel,
  type OutcomeLabel,
} from './analyze/labels.js';
