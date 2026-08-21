import type { AppSpan, HttpAnalysis, HttpMessage, HttpTiming, HttpTransaction } from '@tcpview/core';
import { formatBytes, formatDuration } from '@tcpview/core';

interface Props {
  http: HttpAnalysis;
  /** 当前在梯形图上选中的包，用来高亮它对应的报文区间 */
  selectedSpan: AppSpan | null;
}

/**
 * HTTP 事务卡片。
 *
 * 用 HTML 而不是画进梯形图的 SVG：报文正文要换行、要能选中复制，SVG 都做不到。
 * 这里是「回显」的主视图，梯形图只负责标出每个包对应哪一段。
 */
export function HttpTransactions({ http, selectedSpan }: Props) {
  return (
    <div className="http-transactions">
      <QualityNotice quality={http.quality} />
      {http.transactions.map((transaction) => (
        <TransactionCard
          key={transaction.index}
          transaction={transaction}
          selectedSpan={
            selectedSpan?.transactionIndex === transaction.index ? selectedSpan : null
          }
        />
      ))}
    </div>
  );
}

/** 报文有多可信要写在正文前面，而不是让人以为看到的就是全部 */
function QualityNotice({ quality }: { quality: HttpAnalysis['quality'] }) {
  const notes: string[] = [];

  if (!quality.clientStreamComplete || !quality.serverStreamComplete) {
    const total = quality.gaps.reduce((sum, gap) => sum + (gap.to - gap.from), 0);
    notes.push(`有 ${quality.gaps.length} 段共 ${total} 字节没有被抓到，下面的报文是不完整的。`);
  }
  if (quality.payloadCapped) {
    notes.push('这条连接的数据量超过了保留上限，正文只有前面一部分。');
  }
  if (quality.duplicateSegmentsDropped > 0) {
    notes.push(
      `有 ${quality.duplicateSegmentsDropped} 段数据是重传或重复的，已经在拼接时排除，不会重复出现在正文里。`,
    );
  }

  if (notes.length === 0) return null;

  const tone = quality.clientStreamComplete && quality.serverStreamComplete ? 'info' : 'warn';
  return (
    <div className={`alert ${tone}`}>
      <ul>
        {notes.map((note) => (
          <li key={note}>{note}</li>
        ))}
      </ul>
    </div>
  );
}

function TransactionCard({
  transaction,
  selectedSpan,
}: {
  transaction: HttpTransaction;
  selectedSpan: AppSpan | null;
}) {
  return (
    <div className="http-card">
      <div className="http-card-head">
        <span className="http-index">#{transaction.index}</span>
        <span className="http-note">{transaction.note}</span>
      </div>

      <TimingBar timing={transaction.timing} />

      {transaction.request && (
        <MessageBlock
          message={transaction.request}
          span={selectedSpan?.messageKind === 'request' ? selectedSpan : null}
        />
      )}
      {transaction.response ? (
        <MessageBlock
          message={transaction.response}
          span={selectedSpan?.messageKind === 'response' ? selectedSpan : null}
        />
      ) : (
        <div className="http-message empty">抓包里没有这个请求的响应。</div>
      )}
    </div>
  );
}

/**
 * 耗时分解条。回答内网排查最常见的那个争论：慢在网络还是慢在服务端。
 * 「送达确认」约等于一个网络往返，从「等首字节」里减掉它才是服务端真正花的时间。
 */
function TimingBar({ timing }: { timing: HttpTiming }) {
  const acked = timing.requestAckedMicros;
  const ttfb = timing.ttfbMicros;
  const transfer = timing.responseTransferMicros;

  if (ttfb === null && transfer === null) return null;

  const think = ttfb !== null && acked !== null ? Math.max(0, ttfb - acked) : null;
  const parts = [
    { label: '请求送达', value: acked, tone: 'net' },
    { label: '服务端处理', value: think, tone: 'server' },
    { label: '响应传输', value: transfer, tone: 'net' },
  ].filter((part): part is { label: string; value: number; tone: string } => part.value !== null);

  const total = parts.reduce((sum, part) => sum + part.value, 0);
  if (total <= 0) return null;

  return (
    <div className="http-timing">
      <div className="http-timing-bar">
        {parts.map((part) => (
          <div
            key={part.label}
            className={`http-timing-seg ${part.tone}`}
            style={{ width: `${(part.value / total) * 100}%` }}
            title={`${part.label} ${formatDuration(part.value)}`}
          />
        ))}
      </div>
      <div className="http-timing-legend">
        {parts.map((part) => (
          <span key={part.label} className={`http-timing-key ${part.tone}`}>
            {part.label} {formatDuration(part.value)}
          </span>
        ))}
      </div>
    </div>
  );
}

function MessageBlock({ message, span }: { message: HttpMessage; span: AppSpan | null }) {
  const isRequest = message.kind === 'request';

  return (
    <div className={`http-message ${isRequest ? 'request' : 'response'}`}>
      <div className="http-start-line">
        <span className="http-dir">{isRequest ? '请求 →' : '← 响应'}</span>
        <code>{message.startLine}</code>
      </div>

      {!message.complete && message.incompleteReason && (
        <div className="alert warn http-incomplete">{message.incompleteReason}</div>
      )}

      <dl className="http-headers">
        {message.headers.map((header) => (
          <div key={`${header.name}:${header.value}`} className="http-header-row">
            <dt>{header.name}</dt>
            <dd>{header.value}</dd>
          </div>
        ))}
      </dl>

      <BodyBlock message={message} span={span} />
    </div>
  );
}

function BodyBlock({ message, span }: { message: HttpMessage; span: AppSpan | null }) {
  const body = message.body;
  if (!body || body.byteCount === 0) return null;

  const meta = [
    `正文 ${formatBytes(body.byteCount)}`,
    body.framing === 'chunked' ? '分块传输（已解块）' : null,
    body.charset,
    body.truncated ? '已截断' : null,
  ].filter(Boolean);

  return (
    <div className="http-body">
      <div className="http-body-meta">{meta.join(' · ')}</div>

      {body.text === null ? (
        <div className="muted http-body-unavailable">{body.unavailableReason}</div>
      ) : (
        <pre className="http-body-text">{renderHighlighted(body.text, span)}</pre>
      )}
    </div>
  );
}

/** 把选中包对应的那一段正文高亮出来，这就是「点包看内容」的落点 */
function renderHighlighted(text: string, span: AppSpan | null) {
  if (!span || span.textFrom === null || span.textTo === null) return text;

  const from = Math.max(0, Math.min(text.length, span.textFrom));
  const to = Math.max(from, Math.min(text.length, span.textTo));
  if (to <= from) return text;

  return (
    <>
      {text.slice(0, from)}
      <mark className="http-span-highlight">{text.slice(from, to)}</mark>
      {text.slice(to)}
    </>
  );
}
