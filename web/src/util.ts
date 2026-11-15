import type { Flow, Header } from './types'

export function fmtBytes(n: number | undefined): string {
  if (!n) return n === 0 ? '0 B' : ''
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`
}

export function fmtDuration(ms: number): string {
  if (!ms) return ''
  if (ms < 1000) return `${Math.round(ms)} ms`
  if (ms < 60000) return `${(ms / 1000).toFixed(2)} s`
  return `${Math.floor(ms / 60000)}m ${Math.round((ms % 60000) / 1000)}s`
}

export function fmtTime(iso: string): string {
  const d = new Date(iso)
  if (isNaN(d.getTime()) || d.getFullYear() < 2000) return ''
  return d.toLocaleTimeString(undefined, { hour12: false }) + '.' + String(d.getMilliseconds()).padStart(3, '0')
}

export function b64ToBytes(b64?: string): Uint8Array {
  if (!b64) return new Uint8Array()
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

const decoder = new TextDecoder('utf-8', { fatal: false })
export function bytesToText(b: Uint8Array): string {
  return decoder.decode(b)
}

export function looksBinary(b: Uint8Array): boolean {
  const n = Math.min(b.length, 4096)
  let bad = 0
  for (let i = 0; i < n; i++) {
    const c = b[i]
    if (c === 0) return true
    if (c < 9 || (c > 13 && c < 32)) bad++
  }
  return n > 0 && bad / n > 0.1
}

export type Category = 'json' | 'xml' | 'html' | 'js' | 'css' | 'image' | 'media' | 'font' | 'form' | 'text' | 'binary' | 'other'

export function category(ct: string | undefined): Category {
  const c = (ct || '').toLowerCase()
  if (!c) return 'other'
  if (c.includes('json')) return 'json'
  if (c.includes('html')) return 'html'
  if (c.includes('xml')) return 'xml'
  if (c.includes('javascript') || c.includes('ecmascript')) return 'js'
  if (c.includes('css')) return 'css'
  if (c.startsWith('image/')) return 'image'
  if (c.startsWith('video/') || c.startsWith('audio/')) return 'media'
  if (c.startsWith('font/') || c.includes('font')) return 'font'
  if (c.includes('x-www-form-urlencoded') || c.includes('multipart/form-data')) return 'form'
  if (c.startsWith('text/')) return 'text'
  if (c.includes('octet-stream') || c.includes('protobuf') || c.includes('grpc')) return 'binary'
  return 'other'
}

export function shortType(ct: string | undefined): string {
  if (!ct) return ''
  const base = ct.split(';')[0].trim()
  const sub = base.split('/')[1] || base
  return sub.replace(/^x-/, '').replace(/\+json$/, '+json')
}

export function hostOf(f: Flow): string {
  return f.host || f.server
}

export function clientIP(f: Flow): string {
  const c = f.client || ''
  if (c.startsWith('[')) return c.slice(1, c.indexOf(']'))
  const i = c.lastIndexOf(':')
  return i > 0 && c.indexOf(':') === i ? c.slice(0, i) : c
}

// ---------- filtering ----------

export interface QuickFilter {
  kind: 'all' | 'http' | 'https' | 'tls'
  type: 'all' | Category | 'errors'
}

function matchStatus(f: Flow, v: string): boolean {
  const s = f.status
  if (/^[1-5]xx$/i.test(v)) return Math.floor(s / 100) === Number(v[0])
  const m = v.match(/^(>=|<=|>|<)?(\d+)$/)
  if (!m) return String(s).includes(v)
  const n = Number(m[2])
  switch (m[1]) {
    case '>=': return s >= n
    case '<=': return s <= n
    case '>': return s > n
    case '<': return s < n
  }
  return s === n
}

function tokenMatch(f: Flow, tok: string): boolean {
  const i = tok.indexOf(':')
  if (i > 0) {
    const key = tok.slice(0, i).toLowerCase()
    const v = tok.slice(i + 1).toLowerCase()
    switch (key) {
      case 'host': case 'domain': return hostOf(f).toLowerCase().includes(v)
      case 'method': return f.method.toLowerCase() === v
      case 'status': return matchStatus(f, v)
      case 'client': case 'device': return f.client.toLowerCase().includes(v)
      case 'source': return f.source === v
      case 'kind': return f.kind === v
      case 'path': return f.path.toLowerCase().includes(v)
      case 'type': return (f.respContentType || '').toLowerCase().includes(v)
    }
  }
  const t = tok.toLowerCase()
  return (
    f.url.toLowerCase().includes(t) ||
    hostOf(f).toLowerCase().includes(t) ||
    f.method.toLowerCase() === t ||
    String(f.status) === t ||
    f.client.includes(t) ||
    (f.error || '').toLowerCase().includes(t)
  )
}

export function parseQuery(q: string): { neg: boolean; tok: string }[] {
  const out: { neg: boolean; tok: string }[] = []
  const re = /(-?)("([^"]*)"|\S+)/g
  let m
  while ((m = re.exec(q))) {
    const tok = m[3] ?? m[2]
    if (tok) out.push({ neg: m[1] === '-', tok })
  }
  return out
}

export function flowMatches(f: Flow, toks: { neg: boolean; tok: string }[], qf: QuickFilter, sel: { host?: string; client?: string; source?: string }): boolean {
  if (qf.kind !== 'all' && f.kind !== qf.kind) return false
  if (qf.type === 'errors') {
    if (!(f.state === 'error' || f.status >= 400)) return false
  } else if (qf.type !== 'all' && category(f.respContentType) !== qf.type) return false
  if (sel.host && hostOf(f) !== sel.host) return false
  if (sel.client && clientIP(f) !== sel.client) return false
  if (sel.source && f.source !== sel.source) return false
  for (const { neg, tok } of toks) {
    if (tokenMatch(f, tok) === neg) return false
  }
  return true
}

// ---------- export helpers ----------

function shq(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`
}

export function toCurl(f: Flow): string {
  const parts = ['curl']
  if (f.method !== 'GET') parts.push('-X', f.method)
  parts.push(shq(f.url))
  for (const h of f.reqHeaders || []) {
    const n = h.name.toLowerCase()
    if (n.startsWith(':') || n === 'host' || n === 'content-length' || n === 'connection') continue
    parts.push('-H', shq(`${h.name}: ${h.value}`))
  }
  const body = b64ToBytes(f.reqBody)
  if (body.length) parts.push('--data-binary', shq(bytesToText(body)))
  if ((f.reqHeaders || []).some(h => h.name.toLowerCase() === 'accept-encoding')) parts.push('--compressed')
  return parts.join(' \\\n  ')
}

export function rawRequest(f: Flow): string {
  const lines = [`${f.method} ${f.path} ${f.proto || 'HTTP/1.1'}`]
  for (const h of f.reqHeaders || []) lines.push(`${h.name}: ${h.value}`)
  return lines.join('\r\n') + '\r\n\r\n' + bodyAsText(f.reqBody)
}

export function rawResponse(f: Flow): string {
  if (!f.status) return ''
  const lines = [`${f.proto || 'HTTP/1.1'} ${f.status} ${f.statusText}`]
  for (const h of f.respHeaders || []) lines.push(`${h.name}: ${h.value}`)
  return lines.join('\r\n') + '\r\n\r\n' + bodyAsText(f.respBody)
}

function bodyAsText(b64?: string): string {
  const b = b64ToBytes(b64)
  if (!b.length) return ''
  if (looksBinary(b)) return `<${b.length} bytes binary>`
  return bytesToText(b)
}

export function headerValue(hs: Header[] | undefined, name: string): string | undefined {
  return hs?.find(h => h.name.toLowerCase() === name.toLowerCase())?.value
}

export function parseCookies(hs: Header[] | undefined, response: boolean): { name: string; value: string; attrs?: string }[] {
  const out: { name: string; value: string; attrs?: string }[] = []
  for (const h of hs || []) {
    const n = h.name.toLowerCase()
    if (response && n === 'set-cookie') {
      const [first, ...rest] = h.value.split(';')
      const i = first.indexOf('=')
      out.push({ name: first.slice(0, i).trim(), value: first.slice(i + 1).trim(), attrs: rest.join(';').trim() })
    } else if (!response && n === 'cookie') {
      for (const part of h.value.split(';')) {
        const i = part.indexOf('=')
        if (i > 0) out.push({ name: part.slice(0, i).trim(), value: part.slice(i + 1).trim() })
      }
    }
  }
  return out
}

export function queryParams(url: string): [string, string][] {
  try {
    return [...new URL(url).searchParams.entries()]
  } catch {
    return []
  }
}

export async function copy(text: string) {
  try {
    await navigator.clipboard.writeText(text)
  } catch {
    const ta = document.createElement('textarea')
    ta.value = text
    document.body.appendChild(ta)
    ta.select()
    document.execCommand('copy')
    ta.remove()
  }
}
