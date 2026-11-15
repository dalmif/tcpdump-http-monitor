import { useEffect, useRef, useState } from 'react'
import { api, download } from './api'
import type { Flow, Header, ProxyConfig, SniffConfig, Status } from './types'
import { b64ToBytes, bytesToText, fmtBytes } from './util'

export function Modal(props: { title: string; onClose: () => void; children: React.ReactNode; wide?: boolean }) {
  // Register once and read onClose through a ref: re-registering on every
  // render can drop the listener mid-dispatch when another key handler
  // triggers a synchronous re-render.
  const onClose = useRef(props.onClose)
  onClose.current = props.onClose
  useEffect(() => {
    const k = (e: KeyboardEvent) => e.key === 'Escape' && onClose.current()
    window.addEventListener('keydown', k)
    return () => window.removeEventListener('keydown', k)
  }, [])
  return (
    <div className="modal-bg" onMouseDown={e => e.target === e.currentTarget && props.onClose()}>
      <div className={'modal' + (props.wide ? ' wide' : '')}>
        <div className="modal-head">
          <h2>{props.title}</h2>
          <button className="icon-btn" onClick={props.onClose} aria-label="Close">✕</button>
        </div>
        <div className="modal-body">{props.children}</div>
      </div>
    </div>
  )
}

type SetupTab = 'capture' | 'proxy' | 'ca' | 'device'

export function Setup(props: { status: Status; onClose: () => void; refresh: () => void; notify: (m: string) => void; initialTab?: SetupTab }) {
  const { status, refresh, notify } = props
  const [tab, setTab] = useState<SetupTab>(props.initialTab || 'capture')
  const [sniff, setSniff] = useState<SniffConfig>(status.sniff.config.sshHost ? status.sniff.config : status.sniffDefault)
  const [px, setPx] = useState<ProxyConfig>(status.proxy.config)
  const [bypassText, setBypassText] = useState((status.proxy.config.bypass || []).join('\n'))
  const [caCert, setCaCert] = useState('')
  const [caKey, setCaKey] = useState('')
  const [busy, setBusy] = useState(false)

  const run = async (fn: () => Promise<unknown>, ok: string) => {
    setBusy(true)
    try {
      await fn()
      notify(ok)
      refresh()
    } catch (e) {
      notify('Error: ' + (e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const readFile = (set: (s: string) => void) => (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) file.text().then(set)
  }

  const ips = status.proxy.localIps || []
  const port = status.proxy.port || px.addr.split(':').pop()

  return (
    <Modal title="Setup" onClose={props.onClose} wide>
      <div className="tabs big-tabs">
        {([['capture', 'Gateway capture'], ['proxy', 'HTTPS proxy'], ['ca', 'Certificate (CA)'], ['device', 'Device setup']] as [SetupTab, string][]).map(([k, l]) => (
          <button key={k} className={tab === k ? 'on' : ''} onClick={() => setTab(k)}>{l}</button>
        ))}
      </div>

      {tab === 'capture' && (
        <div className="form">
          <p className="help">
            Streams packets from the gateway with <code>tcpdump</code> over SSH. It decodes plain HTTP completely and shows HTTPS connections by hostname (SNI). Nothing is installed or changed on the gateway; it only needs <code>tcpdump</code> and an SSH login that may run it (root, a <code>pcap</code> group, or <code>setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)</code>).
          </p>
          <label>SSH destination (host alias from ~/.ssh/config, or user@host)
            <input value={sniff.sshHost} onChange={e => setSniff({ ...sniff, sshHost: e.target.value })} placeholder="gateway" />
          </label>
          <label>Remote command
            <input value={sniff.remoteCmd} onChange={e => setSniff({ ...sniff, remoteCmd: e.target.value })} placeholder="tcpdump -U -s0 -w - {qfilter}" />
            <small>
              <code>{'{filter}'}</code> is replaced by the BPF filter (<code>{'{qfilter}'}</code> = shell-quoted). Add <code>-i &lt;interface&gt;</code> to choose an interface. If the SSH key has a forced command that runs tcpdump itself and takes the filter from <code>$SSH_ORIGINAL_COMMAND</code>, set this to just <code>{'{filter}'}</code>.
            </small>
          </label>
          <label>BPF filter
            <input value={sniff.filter} onChange={e => setSniff({ ...sniff, filter: e.target.value })} placeholder="tcp" />
            <small>Examples: <code>tcp</code> · <code>tcp port 80 or tcp port 443</code> · <code>host 192.0.2.10</code></small>
          </label>
          <label className="chk"><input type="checkbox" checked={sniff.excludeSsh} onChange={e => setSniff({ ...sniff, excludeSsh: e.target.checked })} /> Exclude SSH (port 22), so the capture doesn't record itself</label>
          <label className="chk"><input type="checkbox" checked={sniff.dedup} onChange={e => setSniff({ ...sniff, dedup: e.target.checked })} /> Collapse NAT duplicates (the same request seen before and after the gateway's NAT)</label>
          {status.sniff.error && <div className="banner err">{status.sniff.error}{status.sniff.stderr ? <pre>{status.sniff.stderr}</pre> : null}</div>}
          <div className="row">
            <button className="btn primary" disabled={busy} onClick={() => run(() => api.sniffStart(sniff), 'Capture started')}>
              {status.sniff.running ? 'Restart capture' : 'Start capture'}
            </button>
            {status.sniff.running && <button className="btn" disabled={busy} onClick={() => run(api.sniffStop, 'Capture stopped')}>Stop</button>}
            <span className="muted">
              {status.sniff.running ? `Running · ${status.sniff.packets.toLocaleString()} packets · ${fmtBytes(status.sniff.bytes)}` : 'Stopped'}
            </span>
          </div>
        </div>
      )}

      {tab === 'proxy' && (
        <div className="form">
          <p className="help">
            An HTTP/HTTPS proxy running on this computer. Devices that use it get their HTTPS decrypted with your CA (man-in-the-middle). It handles HTTP/1.1, HTTP/2 and WebSockets.
          </p>
          <label>Listen address
            <input value={px.addr} onChange={e => setPx({ ...px, addr: e.target.value })} placeholder=":8080" />
          </label>
          <label className="chk"><input type="checkbox" checked={px.mitm} onChange={e => setPx({ ...px, mitm: e.target.checked })} /> Decrypt HTTPS (SSL proxying)</label>
          <label>Bypass hosts (tunnelled without decryption, one per line, globs allowed)
            <textarea rows={4} value={bypassText} onChange={e => setBypassText(e.target.value)} placeholder={'*.apple.com\napi.pinned-app.com'} />
            <small>Add hosts here when an app uses certificate pinning and refuses the proxy's certificate.</small>
          </label>
          <label className="chk"><input type="checkbox" checked={px.insecureUpstream} onChange={e => setPx({ ...px, insecureUpstream: e.target.checked })} /> Ignore upstream certificate errors (self-signed servers)</label>
          {status.proxy.error && <div className="banner err">{status.proxy.error}</div>}
          <div className="row">
            <button className="btn primary" disabled={busy} onClick={() => run(() => api.proxyConfig({ ...px, bypass: bypassText.split('\n').map(s => s.trim()).filter(Boolean) }), 'Proxy settings applied')}>Apply</button>
            <span className="muted">{status.proxy.running ? `Listening on port ${status.proxy.port}` : 'Not running'}</span>
          </div>
        </div>
      )}

      {tab === 'ca' && (
        <div className="form">
          <div className="ca-card">
            <div><b>{status.proxy.ca.subject}</b></div>
            <div className="muted">{status.proxy.ca.keyType} · expires {new Date(status.proxy.ca.notAfter).toLocaleDateString()}</div>
            <div className="mono small">SHA-256 {status.proxy.ca.fingerprint.match(/.{2}/g)?.join(':')}</div>
            <div className="row">
              <button className="btn" onClick={() => download('/api/ca.pem')}>Download .pem</button>
              <button className="btn" onClick={() => download('/api/ca.crt')}>Download .crt (DER)</button>
              <button className="btn danger" disabled={busy} onClick={() => confirm('Generate a new CA? Devices will need to trust the new certificate.') && run(api.regenerateCA, 'New CA generated')}>Regenerate</button>
            </div>
          </div>
          <h3>Use your own CA</h3>
          <p className="help">Paste or choose a PEM certificate and its private key (PKCS#8, PKCS#1 or EC). The certificate must be a CA (basicConstraints CA:TRUE). It is saved to the config directory and used for all new connections.</p>
          <label>CA certificate (PEM) <input type="file" accept=".pem,.crt,.cer" onChange={readFile(setCaCert)} />
            <textarea rows={4} className="mono" value={caCert} onChange={e => setCaCert(e.target.value)} placeholder="-----BEGIN CERTIFICATE-----" />
          </label>
          <label>Private key (PEM) <input type="file" accept=".pem,.key" onChange={readFile(setCaKey)} />
            <textarea rows={4} className="mono" value={caKey} onChange={e => setCaKey(e.target.value)} placeholder="-----BEGIN PRIVATE KEY-----" />
          </label>
          <div className="row">
            <button className="btn primary" disabled={busy || !caCert} onClick={() => run(() => api.uploadCA(caCert, caKey), 'CA installed')}>Use this CA</button>
          </div>
        </div>
      )}

      {tab === 'device' && (
        <div className="form help-steps">
          <h3>Decrypt HTTPS from a phone or another computer</h3>
          <ol>
            <li>Connect the device to the same network as this computer.</li>
            <li>
              In the device's Wi-Fi settings, set <b>HTTP Proxy → Manual</b>: server{' '}
              {ips.length ? ips.map(ip => <code key={ip}>{ip}</code>).reduce((a, b) => <>{a} or {b}</>) : <code>this computer's IP</code>}, port <code>{port}</code>.
            </li>
            <li>
              On the device, open{' '}
              {ips.length ? <code>http://{ips[0]}:{port}/</code> : <code>http://&lt;this-ip&gt;:{port}/</code>} in the browser and install the CA certificate.
            </li>
            <li><b>iOS:</b> Settings → General → VPN & Device Management → install the profile, then Settings → General → About → Certificate Trust Settings → enable full trust.</li>
            <li><b>Android:</b> Settings → Security → Install certificate → CA certificate. Apps only trust user CAs if they opt in (debug builds with a network security config).</li>
            <li><b>Desktop browsers / CLI:</b> import the .pem into the OS trust store, or use <code>curl --proxy http://{ips[0] || 'IP'}:{port} --cacert httpmonitor-ca.pem https://…</code>.</li>
          </ol>
          <h3>Plain HTTP from every device behind the gateway</h3>
          <p>No device setup is needed. Start the <b>gateway capture</b> and all unencrypted HTTP passing through the gateway appears live. HTTPS from those devices shows as 🔒 connections (hostname, TLS version, bytes).</p>
          <p className="muted">Why a CA can't decrypt the passive capture: modern TLS uses ephemeral (forward-secret) keys, so captured packets can't be decrypted afterwards, even with a certificate's private key. Decryption only works when traffic flows through the proxy.</p>
        </div>
      )}
    </Modal>
  )
}

function headersToText(hs?: Header[]) {
  return (hs || []).filter(h => !h.name.startsWith(':') && h.name.toLowerCase() !== 'content-length').map(h => `${h.name}: ${h.value}`).join('\n')
}

export function Compose(props: { base?: Flow | null; onClose: () => void; onSent: (id: number) => void; notify: (m: string) => void }) {
  const b = props.base
  const [method, setMethod] = useState(b?.method || 'GET')
  const [url, setUrl] = useState(b?.url || 'https://')
  const [headers, setHeaders] = useState(headersToText(b?.reqHeaders))
  const [body, setBody] = useState(b?.reqBody ? bytesToText(b64ToBytes(b.reqBody)) : '')
  const [busy, setBusy] = useState(false)

  const send = async () => {
    setBusy(true)
    try {
      const hs: Header[] = headers
        .split('\n')
        .map(l => l.trim())
        .filter(Boolean)
        .map(l => {
          const i = l.indexOf(':')
          return { name: l.slice(0, i).trim(), value: l.slice(i + 1).trim() }
        })
        .filter(h => h.name)
      const r = await api.compose({ method, url, headers: hs, body })
      props.onSent(r.id)
      props.onClose()
    } catch (e) {
      props.notify('Error: ' + (e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal title={b ? 'Edit & Repeat' : 'Compose request'} onClose={props.onClose} wide>
      <div className="form">
        <div className="row">
          <select value={method} onChange={e => setMethod(e.target.value)}>
            {['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].map(m => <option key={m}>{m}</option>)}
            {!['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].includes(method) && <option>{method}</option>}
          </select>
          <input className="grow" value={url} onChange={e => setUrl(e.target.value)} onKeyDown={e => e.key === 'Enter' && (e.metaKey || e.ctrlKey) && send()} />
        </div>
        <label>Headers (one per line, <code>Name: value</code>)
          <textarea rows={8} className="mono" value={headers} onChange={e => setHeaders(e.target.value)} />
        </label>
        <label>Body
          <textarea rows={8} className="mono" value={body} onChange={e => setBody(e.target.value)} />
        </label>
        <div className="row">
          <button className="btn primary" disabled={busy} onClick={send}>Send</button>
          <span className="muted">Sent from this computer and recorded as a "compose" flow. Ctrl+Enter in the URL field sends it.</span>
        </div>
      </div>
    </Modal>
  )
}
