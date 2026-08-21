import { useCallback, useRef, useState } from 'react';

interface Props {
  onFile: (file: File) => void;
  busy: boolean;
  error: string | null;
}

export function UploadView({ onFile, busy, error }: Props) {
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleDrop = useCallback(
    (event: React.DragEvent) => {
      event.preventDefault();
      setDragging(false);
      const file = event.dataTransfer.files[0];
      if (file) onFile(file);
    },
    [onFile],
  );

  return (
    <div className="upload-page">
      <h1>抓包看得懂</h1>
      <p className="tagline">
        丢一个 pcap 进来，选一个 host，看清楚跟它之间每一条 TCP 连接是怎么建立、怎么结束的。
      </p>

      <div
        className={`dropzone ${dragging ? 'dragging' : ''} ${busy ? 'busy' : ''}`}
        onDragOver={(event) => {
          event.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={handleDrop}
        onClick={() => inputRef.current?.click()}
        role="button"
        tabIndex={0}
        onKeyDown={(event) => {
          if (event.key === 'Enter' || event.key === ' ') inputRef.current?.click();
        }}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".pcap,.pcapng,.cap"
          hidden
          onChange={(event) => {
            const file = event.target.files?.[0];
            if (file) onFile(file);
            event.target.value = '';
          }}
        />
        {busy ? (
          <>
            <div className="dropzone-icon">⏳</div>
            <div className="dropzone-title">正在解析…</div>
          </>
        ) : (
          <>
            <div className="dropzone-icon">📦</div>
            <div className="dropzone-title">把抓包文件拖到这里，或点击选择</div>
            <div className="dropzone-hint">支持 .pcap 和 .pcapng，最大 200MB</div>
          </>
        )}
      </div>

      {error && <div className="alert error">{error}</div>}

      <div className="how-to">
        <h2>还没有抓包文件？</h2>
        <p>在需要排查的机器上执行下面任意一条，Ctrl+C 结束后把文件拖进来：</p>
        <pre>
          <code>
            {`# 抓与某个域名/IP 之间的流量（推荐先解析出 IP）
sudo tcpdump -i any host 93.184.216.34 -w capture.pcap

# k8s pod 里抓全部网卡
tcpdump -i any -w /tmp/capture.pcap

# 想让域名也能被识别出来，记得把 DNS 一起抓上
sudo tcpdump -i any 'host 93.184.216.34 or port 53' -w capture.pcap`}
          </code>
        </pre>
      </div>
    </div>
  );
}
