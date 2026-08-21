import { HTTP_METHODS } from './http.js';

const TLS_RECORD_HANDSHAKE = 0x16;
const HANDSHAKE_CLIENT_HELLO = 0x01;
const EXTENSION_SERVER_NAME = 0x0000;
const SNI_TYPE_HOSTNAME = 0x00;

/**
 * 从 TLS ClientHello 里取 SNI。
 *
 * 这是 HTTPS 场景下把 IP 关联回域名的主要手段——即使载荷全加密，
 * ClientHello 本身仍是明文，SNI 就在里面。
 *
 * 局限：ClientHello 跨多个 TCP 段时无法解析（P0 不做流重组）。
 * 现实中 ClientHello 通常在单个段内，命中率足够。
 */
export function extractSni(payload: Uint8Array): string | null {
  if (payload.length < 6) return null;
  if (payload[0] !== TLS_RECORD_HANDSHAKE) return null;
  // 记录层版本必须是 TLS 1.x（0x0301~0x0304）或 SSL 3.0（0x0300）
  if (payload[1] !== 0x03) return null;

  const recordLength = readU16(payload, 3);
  const recordEnd = Math.min(5 + recordLength, payload.length);
  let cursor = 5;

  if (cursor + 4 > recordEnd) return null;
  if (payload[cursor] !== HANDSHAKE_CLIENT_HELLO) return null;

  const handshakeLength = readU24(payload, cursor + 1);
  const handshakeEnd = Math.min(cursor + 4 + handshakeLength, recordEnd);
  cursor += 4;

  cursor += 2; // client_version
  cursor += 32; // random
  if (cursor >= handshakeEnd) return null;

  const sessionIdLength = payload[cursor] ?? 0;
  cursor += 1 + sessionIdLength;
  if (cursor + 2 > handshakeEnd) return null;

  const cipherSuitesLength = readU16(payload, cursor);
  cursor += 2 + cipherSuitesLength;
  if (cursor + 1 > handshakeEnd) return null;

  const compressionLength = payload[cursor] ?? 0;
  cursor += 1 + compressionLength;
  if (cursor + 2 > handshakeEnd) return null;

  const extensionsLength = readU16(payload, cursor);
  cursor += 2;
  const extensionsEnd = Math.min(cursor + extensionsLength, handshakeEnd);

  while (cursor + 4 <= extensionsEnd) {
    const type = readU16(payload, cursor);
    const length = readU16(payload, cursor + 2);
    const body = cursor + 4;
    if (body + length > extensionsEnd) return null;

    if (type === EXTENSION_SERVER_NAME) {
      return parseServerNameList(payload, body, body + length);
    }
    cursor = body + length;
  }

  return null;
}

function parseServerNameList(data: Uint8Array, start: number, end: number): string | null {
  if (start + 2 > end) return null;
  let cursor = start + 2; // server_name_list 总长度

  while (cursor + 3 <= end) {
    const nameType = data[cursor] ?? 0;
    const nameLength = readU16(data, cursor + 1);
    const nameStart = cursor + 3;
    if (nameStart + nameLength > end) return null;

    if (nameType === SNI_TYPE_HOSTNAME) {
      return latin1(data, nameStart, nameLength).toLowerCase();
    }
    cursor = nameStart + nameLength;
  }

  return null;
}

/** 明文 HTTP 请求的 Host 头。只有未加密流量才拿得到 */
export function extractHttpHost(payload: Uint8Array): string | null {
  if (payload.length < 16) return null;

  const head = latin1(payload, 0, Math.min(payload.length, 12));
  if (!HTTP_METHODS.some((method) => head.startsWith(`${method} `))) return null;

  // 头部区最多看 8KB，避免在大 body 上做无谓扫描
  const text = latin1(payload, 0, Math.min(payload.length, 8192));
  const headerEnd = text.indexOf('\r\n\r\n');
  const headers = headerEnd >= 0 ? text.slice(0, headerEnd) : text;

  for (const line of headers.split('\r\n')) {
    const colon = line.indexOf(':');
    if (colon < 0) continue;
    if (line.slice(0, colon).trim().toLowerCase() !== 'host') continue;

    const value = line.slice(colon + 1).trim();
    if (!value) return null;
    // 去掉端口后缀，但要避开 IPv6 字面量 [::1]:8080
    if (value.startsWith('[')) {
      const bracket = value.indexOf(']');
      return bracket > 0 ? value.slice(1, bracket).toLowerCase() : value.toLowerCase();
    }
    const colonIndex = value.lastIndexOf(':');
    return (colonIndex > 0 ? value.slice(0, colonIndex) : value).toLowerCase();
  }

  return null;
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

function readU24(data: Uint8Array, offset: number): number {
  return ((data[offset] ?? 0) << 16) | ((data[offset + 1] ?? 0) << 8) | (data[offset + 2] ?? 0);
}
