import type { Direction, TcpInfo } from '../types.js';

export interface NoteContext {
  direction: Direction;
  tcp: TcpInfo;
  relSeq: number | null;
  relAck: number | null;
  /** 是否为三次握手的第三个包 */
  isHandshakeAck: boolean;
  /** 到这个包为止，连接是否已经建立 */
  established: boolean;
}

/**
 * 把一个 TCP 包翻译成一句人话。
 *
 * 措辞一律用「客户端 / 服务端」而不是「我 / 对方」：抓包可能发生在客户端机器上，
 * 也可能在 nginx 服务端或 k8s pod 里，「我」指谁会随抓包位置漂移，角色词才是稳定的。
 */
export function describePacket(ctx: NoteContext): string {
  const { tcp, direction, relSeq, relAck } = ctx;
  const who = direction === 'c2s' ? '客户端' : '服务端';
  const peer = direction === 'c2s' ? '服务端' : '客户端';

  if (tcp.flags.rst) {
    if (!ctx.established) {
      return `${who}拒绝连接（RST）——这个端口多半没有程序在监听`;
    }
    return `${who}强制中断连接（RST），连接被立即丢弃，没有走正常挥手`;
  }

  if (tcp.flags.syn && !tcp.flags.ack) {
    return `${who}发起建连（SYN），起始编号 ${fmt(relSeq)}`;
  }

  if (tcp.flags.syn && tcp.flags.ack) {
    return `${who}同意建连（SYN-ACK），起始编号 ${fmt(relSeq)}，并确认收到${peer}第 ${fmt(relAck)} 字节`;
  }

  if (ctx.isHandshakeAck) {
    return `${who}确认（ACK），三次握手完成，连接建立`;
  }

  if (tcp.flags.fin) {
    const payloadNote = tcp.payloadLength > 0 ? `，同时带了 ${tcp.payloadLength} 字节数据` : '';
    return `${who}请求关闭连接（FIN）${payloadNote}`;
  }

  if (tcp.payloadLength > 0) {
    return `${who}发送 ${tcp.payloadLength} 字节数据`;
  }

  if (tcp.flags.ack) {
    return `${who}确认已收到${peer} ${fmt(relAck)} 字节`;
  }

  return `${who}发送了一个没有标志位的包`;
}

function fmt(value: number | null): string {
  return value === null ? '未知' : String(value);
}
