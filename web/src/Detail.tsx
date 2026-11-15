import { useEffect, useState } from 'react'
import { api } from './api'
import { BodyView } from './BodyView'
import type { Flow, Header } from './types'
import { clientIP, copy, fmtBytes, fmtDuration, parseCookies, queryParams, rawRequest, rawResponse, toCurl } from './util'

function HeaderTable({ headers }: { headers?: Header[] }) {
  if (!headers?.length) return <div className="empty-body">No headers</div>
  return (
    <table className="kv">
      <tbody>
        {headers.map((h, i) => (
          <tr key={i}>
            <td>{h.name}</td>
            <td>{h.value}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function KV({ rows, empty }: { rows: [string, React.ReactNode][]; empty: string }) {
  if (!rows.length) return <div className="empty-body">{empty}</div>
  return (
    <table className="kv">
      <tbody>
        {rows.map(([k, v], i) => (
          <tr key={i}>
            <td>{k}</td>
            <td>{v}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function Tabs<T extends string>(props: { tabs: [T, string, number?][]; value: T; onChange: (t: T) => void; right?: React.ReactNode }) {
  return (
    <div className="tabs">
      {props.tabs.map(([k, label, count]) => (
        <button key={k} className={props.value === k ? 'on' : ''} onClick={() => props.onChange(k)}>
          {label}
          {count ? <span className="count">{count}</span> : null}
        </button>
      ))}
      <span className="spacer" />
      {props.right}
    </div>
  )
}

type ReqTab = 'headers' | 'query' | 'body' | 'cookies' | 'raw'
type RespTab = 'headers' | 'body' | 'cookies' | 'raw'

export function Detail(props: { summary: Flow; onSelect: (id: number) => void; onEdit: (f: Flow) => void; notify: (msg: string) => void }) {
  const { summary, onSelect, onEdit, notify } = props
  const [flow, setFlow] = useState<Flow | null>(null)
  const [reqTab, setReqTab] = useState<ReqTab>('headers')
  const [respTab, setRespTab] = useState<RespTab>('body')
  const [overview, setOverview] = useState(false)

  // Refetch whenever the summary changes (e.g. the response arrived).
  useEffect(() => {
    let cancel = false
    api.flow(summary.id).then(f => !cancel && setFlow(f)).catch(() => !cancel && setFlow(null))
    return () => {
      cancel = true
    }
  }, [summary.id, summary.state, summary.status, summary.respSize, summary.bytesDown])

  const f = flow && flow.id === summary.id ? flow : summary
  const tls = f.kind === 'tls'
  const q = queryParams(f.url)
  const reqCookies = parseCookies(f.reqHeaders, false)
  const respCookies = parseCookies(f.respHeaders, true)

  const overviewRows: [string, React.ReactNode][] = [
    ['URL', f.url],
    ['Status', f.status ? `${f.status} ${f.statusText}` : f.state],
    ['Protocol', f.proto || '—'],
    ['Captured by', f.source === 'sniff' ? 'Gateway capture (tcpdump over SSH)' : f.source === 'proxy' ? 'MITM proxy' : f.source],
    ['Client', `${f.client}${clientIP(f) ? '' : ''}`],
    ['Server', f.server],
    ['Started', new Date(f.startedAt).toLocaleString()],
    ['Duration', fmtDuration(f.durationMs) || '—'],
    ['Request size', fmtBytes(f.reqSize) || '0 B'],
    ['Response size', fmtBytes(f.respSize) || '0 B'],
  ]
  if (f.tls) overviewRows.push(['TLS', [f.tls.version, f.tls.sni && `SNI ${f.tls.sni}`, f.tls.alpn && `ALPN ${f.tls.alpn}`].filter(Boolean).join(' · ') || '—'])
  if (tls) overviewRows.push(['Bytes ↑ / ↓', `${fmtBytes(f.bytesUp || 0)} / ${fmtBytes(f.bytesDown || 0)}`])
  if (f.error) overviewRows.push(['Error', <span className="err-text">{f.error}</span>])

  const replay = async () => {
    try {
      const r = await api.replay(f.id)
      onSelect(r.id)
      notify('Request repeated')
    } catch (e) {
      notify(String(e))
    }
  }

  return (
    <div className="detail">
      <div className="detail-head">
        <div className="detail-title" title={f.url}>
          <span className={'pill m-' + f.method.toLowerCase()}>{f.method}</span>
          <span className="url">{f.url}</span>
        </div>
        <div className="detail-actions">
          <button className={'btn small' + (overview ? ' on' : '')} onClick={() => setOverview(!overview)}>Overview</button>
          <button className="btn small" onClick={() => copy(f.url).then(() => notify('URL copied'))}>Copy URL</button>
          {!tls && <button className="btn small" onClick={() => copy(toCurl(f)).then(() => notify('cURL copied'))}>Copy cURL</button>}
          {!tls && <button className="btn small" onClick={replay} title="Send this request again">Repeat</button>}
          {!tls && <button className="btn small" onClick={() => onEdit(f)} title="Edit and send">Edit & Repeat</button>}
        </div>
      </div>
      {tls && !overview ? (
        <div className="tls-note">
          <div className="big">🔒 Encrypted TLS connection</div>
          <p>
            Passive capture sees TLS traffic as ciphertext, so only metadata is shown: <b>{f.tls?.sni || f.host}</b>
            {f.tls?.version ? ` · ${f.tls.version}` : ''}
            {f.tls?.alpn ? ` · ALPN ${f.tls.alpn}` : ''} · {fmtBytes(f.bytesUp || 0)} up / {fmtBytes(f.bytesDown || 0)} down.
          </p>
          {f.error && <p className="err-text">{f.error}</p>}
          {f.source === 'sniff' && (
            <p>
              To see the decrypted requests and responses, route the device through the <b>MITM proxy</b> and install the CA on it. Open <b>Setup</b> for the steps.
            </p>
          )}
          <KV rows={overviewRows} empty="" />
        </div>
      ) : overview ? (
        <div className="pane-scroll">
          <KV rows={overviewRows} empty="" />
        </div>
      ) : (
        <div className="split-v">
          <section className="pane">
            <Tabs<ReqTab>
              value={reqTab}
              onChange={setReqTab}
              tabs={[
                ['headers', 'Request', f.reqHeaders?.length],
                ['query', 'Query', q.length],
                ['body', 'Body'],
                ['cookies', 'Cookies', reqCookies.length],
                ['raw', 'Raw'],
              ]}
            />
            <div className="pane-scroll">
              {reqTab === 'headers' && <HeaderTable headers={f.reqHeaders} />}
              {reqTab === 'query' && <KV rows={q} empty="No query parameters" />}
              {reqTab === 'body' && <BodyView b64={f.reqBody} contentType={f.reqContentType || ''} truncated={f.reqTruncated} wireSize={f.reqSize} bodyUrl={`/api/flows/${f.id}/body/req`} />}
              {reqTab === 'cookies' && <KV rows={reqCookies.map(c => [c.name, c.value])} empty="No cookies" />}
              {reqTab === 'raw' && <pre className="code wrap">{rawRequest(f)}</pre>}
            </div>
          </section>
          <section className="pane">
            <Tabs<RespTab>
              value={respTab}
              onChange={setRespTab}
              tabs={[
                ['headers', 'Response', f.respHeaders?.length],
                ['body', 'Body'],
                ['cookies', 'Set-Cookie', respCookies.length],
                ['raw', 'Raw'],
              ]}
              right={
                <span className="resp-meta">
                  {f.status ? <b className={f.status >= 400 ? 'err-text' : 'ok-text'}>{f.status} {f.statusText}</b> : <span className="muted">{f.state === 'pending' ? 'waiting…' : f.error}</span>}
                  {f.durationMs ? <span className="muted"> · {fmtDuration(f.durationMs)}</span> : null}
                </span>
              }
            />
            <div className="pane-scroll">
              {f.error && <div className="banner err">{f.error}</div>}
              {respTab === 'headers' && <HeaderTable headers={f.respHeaders} />}
              {respTab === 'body' && <BodyView b64={f.respBody} contentType={f.respContentType || ''} truncated={f.respTruncated} wireSize={f.respSize} bodyUrl={`/api/flows/${f.id}/body/resp`} />}
              {respTab === 'cookies' && <KV rows={respCookies.map(c => [c.name, <>{c.value} {c.attrs && <span className="muted">; {c.attrs}</span>}</>])} empty="No cookies set" />}
              {respTab === 'raw' && <pre className="code wrap">{rawResponse(f)}</pre>}
            </div>
          </section>
        </div>
      )}
    </div>
  )
}
