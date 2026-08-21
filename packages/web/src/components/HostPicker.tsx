import { useMemo, useState } from 'react';
import type { HostEntry } from '@tcpview/core';

interface Props {
  hosts: HostEntry[];
  onSelect: (host: string) => void;
}

const SOURCE_TEXT: Record<string, string> = {
  dns: 'DNS 应答',
  sni: 'TLS SNI',
  'http-host': 'HTTP Host 头',
};

/**
 * host 选择器。
 *
 * 提供自动发现列表而不是只给一个输入框，是「小白友好」的关键一环——
 * 新手往往并不知道自己该输入什么，让他从抓包里实际出现过的 host 里挑要容易得多。
 */
export function HostPicker({ hosts, onSelect }: Props) {
  const [keyword, setKeyword] = useState('');

  const filtered = useMemo(() => {
    const needle = keyword.trim().toLowerCase();
    if (!needle) return hosts;
    return hosts.filter(
      (host) =>
        host.address.toLowerCase().includes(needle) ||
        host.names.some((name) => name.name.includes(needle)),
    );
  }, [hosts, keyword]);

  return (
    <div className="host-picker">
      <div className="section-head">
        <h2>选一个要查的 host</h2>
        <p className="muted">
          下面是这个抓包文件里出现过的所有地址。也可以直接输入域名或 IP 搜索。
        </p>
      </div>

      <input
        className="search"
        placeholder="输入域名或 IP，例如 www.example.com 或 192.168.1.6"
        value={keyword}
        onChange={(event) => setKeyword(event.target.value)}
        onKeyDown={(event) => {
          if (event.key === 'Enter' && keyword.trim()) onSelect(keyword.trim());
        }}
      />

      <div className="host-list">
        {filtered.length === 0 && <div className="empty">没有匹配的 host</div>}

        {filtered.map((host) => (
          <button key={host.address} className="host-card" onClick={() => onSelect(host.address)}>
            <div className="host-main">
              <span className="host-addr">{host.address}</span>
              {host.names.length > 0 && (
                <span className="host-names">
                  {[...new Set(host.names.map((n) => n.name))].join('、')}
                </span>
              )}
            </div>

            <div className="host-meta">
              <span className={host.connectionCount > 0 ? 'chip strong' : 'chip'}>
                {host.connectionCount} 条 TCP 连接
              </span>
              <span className="chip">{host.tcpPackets} 个 TCP 包</span>
              {host.quicPackets > 0 && (
                <span className="chip warn">{host.quicPackets} 个 QUIC 包</span>
              )}
            </div>

            {host.names.length > 0 && (
              <div className="host-evidence">
                {host.names.map((name) => (
                  <span key={`${name.name}-${name.source}`}>
                    {name.name} ← 来自{SOURCE_TEXT[name.source] ?? name.source}（第 #
                    {name.firstSeenPacket} 个包）
                  </span>
                ))}
              </div>
            )}
          </button>
        ))}
      </div>
    </div>
  );
}
