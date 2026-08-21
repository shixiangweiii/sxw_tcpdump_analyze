import type { ConnectionPacket, Direction } from '@tcpview/core';

/** 演示信息条和梯形图共用的方向文案 */
export function directionText(direction: Direction): string {
  return direction === 'c2s' ? '客户端 → 服务端' : '服务端 → 客户端';
}

/**
 * 序号同时给出相对值和原始值。
 * 相对值让人看得懂（从 0 开始数），原始值让人能跟 Wireshark 对照。
 * 基准为估算时用 ≈ 替掉 =（而不是追加），否则 seq=≈0 会看成 seq==0。
 */
export function formatSeq(packet: ConnectionPacket, estimated: boolean): string {
  const parts: string[] = [];
  const eq = estimated ? '≈' : '=';

  parts.push(`seq${eq}${packet.relSeq ?? '?'} (${packet.rawSeq})`);
  if (packet.relAck !== null) {
    parts.push(`ack${eq}${packet.relAck} (${packet.rawAck})`);
  }
  if (packet.payloadLength > 0) {
    parts.push(`len=${packet.payloadLength}`);
  }
  if (packet.scaledWindow !== null) {
    parts.push(`win=${packet.scaledWindow}`);
  } else {
    parts.push(`win=${packet.window}?`);
  }
  return parts.join('  ');
}
