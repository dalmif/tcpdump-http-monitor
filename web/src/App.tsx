import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api, download } from './api'
import { Detail } from './Detail'
import { FlowTable } from './FlowTable'
import { Compose, Setup } from './Modals'
import type { Flow, FlowEvent, Status } from './types'
import { clientIP, flowMatches, fmtBytes, hostOf, parseQuery, type QuickFilter } from './util'

type Sel = { host?: string; client?: string; source?: string }

const TYPE_FILTERS: [QuickFilter['type'], string][] = [
  ['all', 'All'], ['json', 'JSON'], ['xml', 'XML'], ['html', 'HTML'], ['js', 'JS'], ['css', 'CSS'],
  ['image', 'Image'], ['media', 'Media'], ['form', 'Form'], ['binary', 'Binary'], ['errors', 'Errors'],
]

const KIND_FILTERS: [QuickFilter['kind'], string][] = [
  ['all', 'All'], ['http', 'HTTP'], ['https', 'HTTPS (decrypted)'], ['tls', 'TLS (encrypted)'],
]

export default function App() {
  // Flow data lives in a ref; `version` triggers re-renders in batches.
  const flowsRef = useRef<Map<number, Flow>>(new Map())
  const [version, setVersion] = useState(0)
  const [connected, setConnected] = useState(false)
  const [status, setStatus] = useState<Status | null>(null)
  const [selected, setSelected] = useState<number | null>(null)
  const [query, setQuery] = useState('')
  const [qf, setQf] = useState<QuickFilter>({ kind: 'all', type: 'all' })
  const [sel, setSel] = useState<Sel>({})
  const [autoScroll, setAutoScroll] = useState(true)
  const [setup, setSetup] = useState<false | 'capture' | 'proxy' | 'ca' | 'device'>(false)
  const [compose, setCompose] = useState<false | { base: Flow | null }>(false)
  const [toast, setToast] = useState<string | null>(null)
  const [detailW, setDetailW] = useState(() => Number(localStorage.getItem('detailW')) || 46)
  const [hideTLS, setHideTLS] = useState(false)
  const filterRef = useRef<HTMLInputElement>(null)
  const fileRef = useRef<HTMLInputElement>(null)

  const notify = useCallback((m: string) => {
    setToast(m)
    window.clearTimeout((notify as unknown as { t?: number }).t)
    ;(notify as unknown as { t?: number }).t = window.setTimeout(() => setToast(null), 2500)
  }, [])

  const refresh = useCallback(() => {
    api.status().then(setStatus).catch(() => {})
  }, [])

  useEffect(() => {
    refresh()
    const t = setInterval(refresh, 2000)
    return () => clearInterval(t)
  }, [refresh])

  // Live event stream.
  useEffect(() => {
    let es: EventSource | null = null
    let retry: number | undefined
    const connect = () => {
      es = new EventSource('/api/events')
      es.onopen = () => setConnected(true)
      es.onerror = () => {
        setConnected(false)
        es?.close()
        retry = window.setTimeout(connect, 2000)
      }
      es.addEventListener('snapshot', e => {
        const list: Flow[] = JSON.parse((e as MessageEvent).data)
        const m = new Map<number, Flow>()
        for (const f of list) m.set(f.id, f)
        flowsRef.current = m
        setVersion(v => v + 1)
      })
      es.addEventListener('batch', e => {
        const evs: FlowEvent[] = JSON.parse((e as MessageEvent).data)
        const m = flowsRef.current
        for (const ev of evs) {
          if (ev.type === 'clear') m.clear()
          else m.set(ev.flow.id, ev.flow)
        }
        setVersion(v => v + 1)
      })
    }
    connect()
    return () => {
      es?.close()
      window.clearTimeout(retry)
    }
  }, [])

  const all = useMemo(() => [...flowsRef.current.values()].sort((a, b) => a.id - b.id), [version]) // eslint-disable-line react-hooks/exhaustive-deps
  const toks = useMemo(() => parseQuery(query), [query])
  const filtered = useMemo(
    () => all.filter(f => (!hideTLS || f.kind !== 'tls') && flowMatches(f, toks, qf, sel)),
    [all, toks, qf, sel, hideTLS],
  )

  // Sidebar aggregates.
  const { hosts, clients, sources } = useMemo(() => {
    const hosts = new Map<string, number>()
    const clients = new Map<string, number>()
    const sources = new Map<string, number>()
    for (const f of all) {
      const h = hostOf(f)
      hosts.set(h, (hosts.get(h) || 0) + 1)
      const c = clientIP(f)
      if (c) clients.set(c, (clients.get(c) || 0) + 1)
      sources.set(f.source, (sources.get(f.source) || 0) + 1)
    }
    return {
      hosts: [...hosts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])),
      clients: [...clients.entries()].sort((a, b) => b[1] - a[1]),
      sources: [...sources.entries()],
    }
  }, [all])
  const [hostFilter, setHostFilter] = useState('')

  const selectedFlow = selected != null ? flowsRef.current.get(selected) : undefined

  // Keyboard navigation.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement).tagName
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        filterRef.current?.focus()
        return
      }
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return
      if (document.querySelector('.modal')) return
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp' || e.key === 'j' || e.key === 'k') {
        e.preventDefault()
        const i = filtered.findIndex(f => f.id === selected)
        const ni = e.key === 'ArrowDown' || e.key === 'j' ? Math.min(filtered.length - 1, i + 1) : Math.max(0, i - 1)
        if (filtered[ni]) {
          setSelected(filtered[ni].id)
          setAutoScroll(false)
        }
      } else if (e.key === 'Escape') setSelected(null)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [filtered, selected])

  const sniffing = status?.sniff.running
  const paused = status?.paused

  const toggleCapture = async () => {
    try {
      if (sniffing) await api.sniffStop()
      else await api.sniffStart(status?.sniff.config.sshHost ? status.sniff.config : status!.sniffDefault)
      refresh()
    } catch (e) {
      notify('Error: ' + (e as Error).message)
      setSetup('capture')
    }
  }

  const saveHAR = (onlyFiltered: boolean) => {
    if (onlyFiltered) {
      const ids = filtered.map(f => f.id).join(',')
      if (!ids) return notify('Nothing to save')
      // Large selections: POSTing would be nicer, but GET keeps it a plain download.
      download('/api/export/har?ids=' + ids)
    } else download('/api/export/har')
  }

  const openHAR = async (file: File) => {
    try {
      const r = await api.importHAR(await file.text())
      notify(`Imported ${r.imported} entries`)
    } catch (e) {
      notify('Error: ' + (e as Error).message)
    }
  }

  const startResize = (e: React.MouseEvent) => {
    e.preventDefault()
    const onMove = (ev: MouseEvent) => {
      const pct = Math.min(75, Math.max(25, ((window.innerWidth - ev.clientX) / window.innerWidth) * 100))
      setDetailW(pct)
      localStorage.setItem('detailW', String(pct))
    }
    const onUp = () => {
      window.removeEventListener('mousemove', onMove)
      window.removeEventListener('mouseup', onUp)
    }
    window.addEventListener('mousemove', onMove)
    window.addEventListener('mouseup', onUp)
  }

  const visibleHosts = hostFilter ? hosts.filter(([h]) => h.toLowerCase().includes(hostFilter.toLowerCase())) : hosts

  return (
    <div className="app">
      <header className="toolbar">
        <div className="brand">
          <span className="logo">◆</span> HTTP Monitor
        </div>
        <button className={'btn ' + (sniffing ? 'rec' : 'primary')} onClick={toggleCapture} disabled={!status} title={status ? `ssh ${status.sniff.config.sshHost || status.sniffDefault.sshHost} — ${status.remoteCmd}` : ''}>
          <span className={'dot' + (sniffing ? ' live' : '')} />
          {sniffing ? 'Stop capture' : 'Start capture'}
        </button>
        <button className="btn" onClick={() => setSetup('proxy')} title="Proxy settings">
          <span className={'dot' + (status?.proxy.running ? ' ok' : '')} />
          Proxy {status?.proxy.running ? `:${status.proxy.port}` : 'off'}
          {status?.proxy.config.mitm && status.proxy.running ? ' · SSL' : ''}
        </button>
        <div className="sep" />
        <button className={'btn' + (paused ? ' on' : '')} onClick={() => api.pause(!paused).then(refresh)} title="Pause recording">
          {paused ? '▶ Resume' : '❚❚ Pause'}
        </button>
        <button className="btn" onClick={() => { api.clear(); setSelected(null) }} title="Clear all flows">⌫ Clear</button>
        <div className="sep" />
        <div className="dropdown">
          <button className="btn">💾 Save ▾</button>
          <div className="menu">
            <button onClick={() => saveHAR(false)}>Session as HAR (all {all.length})</button>
            <button onClick={() => saveHAR(true)}>Filtered as HAR ({filtered.length})</button>
            <button onClick={() => download('/api/export/pcap')}>Raw packets as PCAP (Wireshark){status?.sniff.pcapBytes ? ` · ${fmtBytes(status.sniff.pcapBytes)}` : ''}</button>
          </div>
        </div>
        <button className="btn" onClick={() => fileRef.current?.click()}>📂 Open HAR</button>
        <input ref={fileRef} type="file" accept=".har,application/json" hidden onChange={e => { const f = e.target.files?.[0]; if (f) openHAR(f); e.target.value = '' }} />
        <button className="btn" onClick={() => setCompose({ base: null })}>✎ Compose</button>
        <span className="spacer" />
        <span className={'conn' + (connected ? ' ok' : '')}>{connected ? 'live' : 'disconnected'}</span>
        <button className="btn" onClick={() => setSetup('capture')}>⚙ Setup</button>
      </header>

      {status?.sniff.error && !sniffing && (
        <div className="banner err top">
          Capture stopped: {status.sniff.error} <button className="link" onClick={() => setSetup('capture')}>details</button>
        </div>
      )}

      <div className="main">
        <aside className="sidebar">
          <div className="side-section">
            <div className="side-title">Source</div>
            <div className={'side-item' + (!sel.source ? ' on' : '')} onClick={() => setSel({ ...sel, source: undefined })}>
              <span>All</span><span className="count">{all.length}</span>
            </div>
            {sources.map(([s, n]) => (
              <div key={s} className={'side-item' + (sel.source === s ? ' on' : '')} onClick={() => setSel({ ...sel, source: sel.source === s ? undefined : s })}>
                <span><span className={'src src-' + s}>{s}</span></span><span className="count">{n}</span>
              </div>
            ))}
          </div>
          <div className="side-section">
            <div className="side-title">Devices</div>
            {clients.length === 0 && <div className="muted side-empty">None yet</div>}
            {clients.map(([c, n]) => (
              <div key={c} className={'side-item' + (sel.client === c ? ' on' : '')} onClick={() => setSel({ ...sel, client: sel.client === c ? undefined : c })} title={c}>
                <span className="ellipsis">{c}</span><span className="count">{n}</span>
              </div>
            ))}
          </div>
          <div className="side-section grow">
            <div className="side-title">Domains <span className="muted">{hosts.length}</span></div>
            <input className="side-filter" placeholder="Filter domains" value={hostFilter} onChange={e => setHostFilter(e.target.value)} />
            <div className="side-list">
              {visibleHosts.map(([h, n]) => (
                <div key={h} className={'side-item' + (sel.host === h ? ' on' : '')} onClick={() => setSel({ ...sel, host: sel.host === h ? undefined : h })} title={h}>
                  <span className="ellipsis">{h}</span><span className="count">{n}</span>
                </div>
              ))}
            </div>
          </div>
        </aside>

        <section className="content">
          <div className="filterbar">
            <div className="search">
              <span className="search-icon">⌕</span>
              <input
                ref={filterRef}
                value={query}
                onChange={e => setQuery(e.target.value)}
                placeholder="Filter: text, host:api.example.com, method:POST, status:4xx, status:>=500, client:192.0.2.10, -host:apple.com    (Ctrl+K)"
                spellCheck={false}
              />
              {query && <button className="icon-btn" onClick={() => setQuery('')}>✕</button>}
            </div>
            <div className="chips">
              {KIND_FILTERS.map(([k, l]) => (
                <button key={k} className={'chip' + (qf.kind === k ? ' on' : '')} onClick={() => setQf({ ...qf, kind: k })}>{l}</button>
              ))}
              <span className="chip-sep" />
              {TYPE_FILTERS.map(([k, l]) => (
                <button key={k} className={'chip' + (qf.type === k ? ' on' : '')} onClick={() => setQf({ ...qf, type: k })}>{l}</button>
              ))}
              <span className="chip-sep" />
              <label className="chk"><input type="checkbox" checked={hideTLS} onChange={e => setHideTLS(e.target.checked)} /> Hide encrypted</label>
              <label className="chk"><input type="checkbox" checked={autoScroll} onChange={e => setAutoScroll(e.target.checked)} /> Auto-scroll</label>
            </div>
            {(sel.host || sel.client || sel.source) && (
              <div className="active-filters">
                {sel.source && <span className="tag" onClick={() => setSel({ ...sel, source: undefined })}>source: {sel.source} ✕</span>}
                {sel.client && <span className="tag" onClick={() => setSel({ ...sel, client: undefined })}>device: {sel.client} ✕</span>}
                {sel.host && <span className="tag" onClick={() => setSel({ ...sel, host: undefined })}>domain: {sel.host} ✕</span>}
              </div>
            )}
          </div>
          <div className="split-h">
            <div className="list-wrap" style={{ width: selectedFlow ? `${100 - detailW}%` : '100%' }}>
              <FlowTable
                flows={filtered}
                selected={selected}
                onSelect={id => { setSelected(id); setAutoScroll(false) }}
                autoScroll={autoScroll}
                onUserScroll={atBottom => { if (!atBottom && autoScroll) setAutoScroll(false) }}
              />
            </div>
            {selectedFlow && (
              <>
                <div className="resizer" onMouseDown={startResize} />
                <div className="detail-wrap" style={{ width: `${detailW}%` }}>
                  <Detail summary={selectedFlow} onSelect={id => setSelected(id)} onEdit={f => setCompose({ base: f })} notify={notify} />
                </div>
              </>
            )}
          </div>
          <footer className="statusbar">
            <span>{filtered.length.toLocaleString()} / {all.length.toLocaleString()} flows</span>
            {status && (
              <>
                <span>Capture: {sniffing ? `${status.sniff.config.sshHost} · ${status.sniff.packets.toLocaleString()} pkts · ${fmtBytes(status.sniff.bytes)}` : 'stopped'}</span>
                <span>Proxy: {status.proxy.running ? `${(status.proxy.localIps || [])[0] || '0.0.0.0'}:${status.proxy.port}` : 'off'}</span>
                {paused && <span className="warn-text">recording paused</span>}
              </>
            )}
          </footer>
        </section>
      </div>

      {setup && status && <Setup status={status} initialTab={setup} onClose={() => setSetup(false)} refresh={refresh} notify={notify} />}
      {compose && <Compose base={compose.base} onClose={() => setCompose(false)} onSent={id => { setSelected(id); setAutoScroll(false) }} notify={notify} />}
      {toast && <div className="toast">{toast}</div>}
    </div>
  )
}
