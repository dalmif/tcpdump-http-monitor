import type { Flow, Header, ProxyConfig, SniffConfig, Status } from './types'

async function req<T>(method: string, url: string, body?: unknown): Promise<T> {
  const r = await fetch(url, {
    method,
    headers: body !== undefined ? { 'Content-Type': 'application/json' } : undefined,
    body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body),
  })
  const text = await r.text()
  const data = text ? JSON.parse(text) : {}
  if (!r.ok) throw new Error(data.error || r.statusText)
  return data as T
}

export const api = {
  status: () => req<Status>('GET', '/api/status'),
  flow: (id: number) => req<Flow>('GET', `/api/flows/${id}`),
  clear: () => req('POST', '/api/clear'),
  pause: (paused: boolean) => req('POST', '/api/pause', { paused }),
  sniffStart: (cfg: SniffConfig) => req('POST', '/api/sniff/start', cfg),
  sniffStop: () => req('POST', '/api/sniff/stop'),
  proxyConfig: (cfg: ProxyConfig) => req('PUT', '/api/proxy/config', cfg),
  replay: (id: number) => req<{ id: number }>('POST', `/api/flows/${id}/replay`),
  compose: (c: { method: string; url: string; headers: Header[]; body: string }) =>
    req<{ id: number }>('POST', '/api/compose', c),
  uploadCA: (cert: string, key: string) => req('POST', '/api/ca', { cert, key }),
  regenerateCA: () => req('POST', '/api/ca/regenerate'),
  importHAR: (text: string) => req<{ imported: number }>('POST', '/api/import/har', text),
}

export function download(url: string) {
  const a = document.createElement('a')
  a.href = url
  a.download = ''
  document.body.appendChild(a)
  a.click()
  a.remove()
}
