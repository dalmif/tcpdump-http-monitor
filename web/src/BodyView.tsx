import { useMemo, useState } from 'react'
import { b64ToBytes, bytesToText, category, fmtBytes, looksBinary } from './util'

type Mode = 'auto' | 'text' | 'hex' | 'preview'

const HL_LIMIT = 600_000

function highlightJSON(src: string): React.ReactNode[] {
  const out: React.ReactNode[] = []
  const re = /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g
  let last = 0
  let m: RegExpExecArray | null
  let k = 0
  while ((m = re.exec(src))) {
    if (m.index > last) out.push(src.slice(last, m.index))
    if (m[1]) {
      if (m[2]) {
        out.push(<span key={k++} className="j-key">{m[1]}</span>, m[2])
      } else out.push(<span key={k++} className="j-str">{m[1]}</span>)
    } else if (m[3]) out.push(<span key={k++} className="j-lit">{m[3]}</span>)
    else if (m[4]) out.push(<span key={k++} className="j-num">{m[4]}</span>)
    last = re.lastIndex
  }
  if (last < src.length) out.push(src.slice(last))
  return out
}

function prettyXML(src: string): string {
  if (src.length > HL_LIMIT) return src
  let indent = 0
  return src
    .replace(/>\s*</g, '><')
    .replace(/</g, '\n<')
    .split('\n')
    .filter(l => l.trim())
    .map(l => {
      if (/^<\//.test(l)) indent = Math.max(0, indent - 1)
      const line = '  '.repeat(indent) + l
      if (/^<[^!?/][^>]*[^/]>/.test(l) && !/<\/[^>]+>$/.test(l)) indent++
      return line
    })
    .join('\n')
}

function hexDump(b: Uint8Array, limit = 64 * 1024): string {
  const lines: string[] = []
  const n = Math.min(b.length, limit)
  for (let i = 0; i < n; i += 16) {
    const row = b.subarray(i, Math.min(i + 16, n))
    const hex = Array.from(row, x => x.toString(16).padStart(2, '0')).join(' ')
    const asc = Array.from(row, x => (x >= 32 && x < 127 ? String.fromCharCode(x) : '.')).join('')
    lines.push(i.toString(16).padStart(8, '0') + '  ' + hex.padEnd(48) + '  ' + asc)
  }
  if (b.length > limit) lines.push(`… ${b.length - limit} more bytes`)
  return lines.join('\n')
}

export function BodyView(props: { b64?: string; contentType: string; truncated?: boolean; wireSize: number; bodyUrl: string }) {
  const { b64, contentType, truncated, wireSize, bodyUrl } = props
  const bytes = useMemo(() => b64ToBytes(b64), [b64])
  const cat = category(contentType)
  const binary = useMemo(() => looksBinary(bytes), [bytes])
  const canPreview = cat === 'image' || cat === 'html' || cat === 'media' || contentType.includes('pdf') || contentType.includes('svg')
  const [mode, setMode] = useState<Mode>('auto')
  const [wrap, setWrap] = useState(true)

  const text = useMemo(() => (binary ? '' : bytesToText(bytes)), [bytes, binary])

  const rendered = useMemo(() => {
    if (mode === 'hex' || (mode === 'auto' && binary && cat !== 'image')) return { kind: 'pre' as const, node: hexDump(bytes) }
    if (mode === 'preview' || (mode === 'auto' && cat === 'image')) return { kind: 'preview' as const }
    if (mode === 'text') return { kind: 'pre' as const, node: text }
    // auto
    const trimmed = text.trimStart()
    if (cat === 'json' || ((trimmed.startsWith('{') || trimmed.startsWith('[')) && text.length < HL_LIMIT * 4)) {
      try {
        const pretty = JSON.stringify(JSON.parse(text), null, 2)
        return { kind: 'pre' as const, node: pretty.length < HL_LIMIT ? highlightJSON(pretty) : pretty }
      } catch {
        /* not JSON */
      }
    }
    if (cat === 'form') {
      try {
        const rows = [...new URLSearchParams(text).entries()]
        if (rows.length) return { kind: 'form' as const, rows }
      } catch {
        /* ignore */
      }
    }
    if (cat === 'xml') return { kind: 'pre' as const, node: prettyXML(text) }
    return { kind: 'pre' as const, node: text }
  }, [mode, bytes, text, binary, cat])

  if (!bytes.length) {
    return <div className="empty-body">{wireSize > 0 ? `${fmtBytes(wireSize)} body not captured` : 'No body'}</div>
  }

  return (
    <div className="body-view">
      <div className="body-toolbar">
        <div className="seg">
          {(['auto', 'text', 'hex'] as Mode[]).map(m => (
            <button key={m} className={mode === m ? 'on' : ''} onClick={() => setMode(m)}>
              {m === 'auto' ? 'Pretty' : m === 'text' ? 'Raw' : 'Hex'}
            </button>
          ))}
          {canPreview && (
            <button className={mode === 'preview' || (mode === 'auto' && cat === 'image') ? 'on' : ''} onClick={() => setMode('preview')}>
              Preview
            </button>
          )}
        </div>
        <label className="chk">
          <input type="checkbox" checked={wrap} onChange={e => setWrap(e.target.checked)} /> Wrap
        </label>
        <span className="muted">
          {fmtBytes(bytes.length)}
          {wireSize && wireSize !== bytes.length ? ` (${fmtBytes(wireSize)} on wire)` : ''}
          {truncated ? ' · truncated' : ''}
        </span>
        <span className="spacer" />
        <a className="btn small" href={bodyUrl + '?download=1'}>Download</a>
        <a className="btn small" href={bodyUrl} target="_blank" rel="noreferrer">Open</a>
      </div>
      {rendered.kind === 'preview' ? (
        <div className="preview">
          {cat === 'image' ? (
            <img src={bodyUrl} alt="" />
          ) : cat === 'media' ? (
            contentType.startsWith('audio') ? <audio controls src={bodyUrl} /> : <video controls src={bodyUrl} />
          ) : (
            <iframe title="preview" sandbox="" src={bodyUrl} />
          )}
        </div>
      ) : rendered.kind === 'form' ? (
        <table className="kv">
          <tbody>
            {rendered.rows.map(([k, v], i) => (
              <tr key={i}><td>{k}</td><td>{v}</td></tr>
            ))}
          </tbody>
        </table>
      ) : (
        <pre className={'code' + (wrap ? ' wrap' : '')}>{rendered.node}</pre>
      )}
    </div>
  )
}
