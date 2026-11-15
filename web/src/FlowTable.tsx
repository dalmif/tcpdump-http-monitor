import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import type { Flow } from './types'
import { clientIP, fmtBytes, fmtDuration, fmtTime, hostOf, shortType } from './util'

const ROW_H = 24

function statusClass(f: Flow): string {
  if (f.state === 'error') return 'st-err'
  if (f.kind === 'tls') return 'st-tls'
  if (f.state === 'pending') return 'st-pending'
  if (f.status >= 500) return 'st-5'
  if (f.status >= 400) return 'st-4'
  if (f.status >= 300) return 'st-3'
  if (f.status >= 200) return 'st-2'
  return ''
}

function statusLabel(f: Flow): string {
  if (f.kind === 'tls') return f.state === 'error' ? 'TLS ✕' : '🔒'
  if (f.state === 'error' && !f.status) return 'ERR'
  if (f.state === 'pending') return '…'
  return String(f.status || '')
}

function methodClass(m: string) {
  return 'm-' + (['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'TLS'].includes(m) ? m.toLowerCase() : 'other')
}

export function FlowTable(props: {
  flows: Flow[]
  selected: number | null
  onSelect: (id: number) => void
  autoScroll: boolean
  onUserScroll: (atBottom: boolean) => void
}) {
  const { flows, selected, onSelect, autoScroll, onUserScroll } = props
  const ref = useRef<HTMLDivElement>(null)
  const [scrollTop, setScrollTop] = useState(0)
  const [height, setHeight] = useState(600)

  useLayoutEffect(() => {
    const el = ref.current
    if (!el) return
    const ro = new ResizeObserver(() => setHeight(el.clientHeight))
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  useEffect(() => {
    const el = ref.current
    if (el && autoScroll) el.scrollTop = el.scrollHeight
  }, [flows.length, autoScroll])

  // Keep the selected row visible when navigating with the keyboard.
  useEffect(() => {
    const el = ref.current
    if (!el || selected == null) return
    const i = flows.findIndex(f => f.id === selected)
    if (i < 0) return
    const top = i * ROW_H
    if (top < el.scrollTop) el.scrollTop = top
    else if (top + ROW_H > el.scrollTop + el.clientHeight - ROW_H) el.scrollTop = top - el.clientHeight + 2 * ROW_H
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected])

  const start = Math.max(0, Math.floor(scrollTop / ROW_H) - 10)
  const end = Math.min(flows.length, Math.ceil((scrollTop + height) / ROW_H) + 10)
  const rows = flows.slice(start, end)

  return (
    <div className="flow-table">
      <div className="ft-head">
        <div className="c-id">#</div>
        <div className="c-time">Time</div>
        <div className="c-client">Client</div>
        <div className="c-method">Method</div>
        <div className="c-status">Status</div>
        <div className="c-host">Host</div>
        <div className="c-path">Path</div>
        <div className="c-type">Type</div>
        <div className="c-size">Size</div>
        <div className="c-dur">Duration</div>
        <div className="c-src">Source</div>
      </div>
      <div
        className="ft-body"
        ref={ref}
        onScroll={e => {
          const el = e.currentTarget
          setScrollTop(el.scrollTop)
          onUserScroll(el.scrollHeight - el.scrollTop - el.clientHeight < ROW_H * 2)
        }}
      >
        {flows.length === 0 && (
          <div className="ft-empty">
            <div className="big">No traffic yet</div>
            <div>Start the gateway capture or point a device at the proxy. Open <b>Setup</b> for instructions.</div>
          </div>
        )}
        <div style={{ height: flows.length * ROW_H, position: 'relative' }}>
          {rows.map((f, i) => (
            <div
              key={f.id}
              className={'ft-row' + (f.id === selected ? ' sel' : '') + ((start + i) % 2 ? ' odd' : '') + (f.state === 'error' ? ' err' : '')}
              style={{ top: (start + i) * ROW_H, height: ROW_H }}
              onMouseDown={() => onSelect(f.id)}
            >
              <div className="c-id">{f.id}</div>
              <div className="c-time">{fmtTime(f.startedAt)}</div>
              <div className="c-client" title={f.client}>{clientIP(f)}</div>
              <div className={'c-method ' + methodClass(f.method)}>{f.method}</div>
              <div className={'c-status ' + statusClass(f)} title={f.error || f.statusText}>{statusLabel(f)}</div>
              <div className="c-host" title={hostOf(f)}>
                {f.kind === 'https' && <span className="lock" title="Decrypted HTTPS">🔓</span>}
                {hostOf(f)}
              </div>
              <div className="c-path" title={f.url}>{f.kind === 'tls' ? <span className="muted">{f.error ? f.error : `encrypted · ${f.tls?.version || 'TLS'}${f.tls?.alpn ? ' · ' + f.tls.alpn : ''}`}</span> : f.path}</div>
              <div className="c-type">{shortType(f.respContentType)}</div>
              <div className="c-size">{f.kind === 'tls' ? fmtBytes((f.bytesUp || 0) + (f.bytesDown || 0)) : fmtBytes(f.respSize)}</div>
              <div className="c-dur">{fmtDuration(f.durationMs)}</div>
              <div className="c-src"><span className={'src src-' + f.source}>{f.source}</span></div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
