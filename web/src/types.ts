export interface Header { name: string; value: string }

export interface TLSInfo { sni?: string; version?: string; alpn?: string }

export interface Flow {
  id: number
  source: 'sniff' | 'proxy' | 'compose' | 'import'
  kind: 'http' | 'https' | 'tls'
  state: 'pending' | 'done' | 'error'
  startedAt: string
  durationMs: number
  client: string
  server: string
  method: string
  url: string
  scheme: string
  host: string
  path: string
  proto: string
  status: number
  statusText: string
  reqHeaders?: Header[]
  respHeaders?: Header[]
  reqBody?: string // base64
  respBody?: string // base64
  reqSize: number
  respSize: number
  reqTruncated?: boolean
  respTruncated?: boolean
  reqContentType: string
  respContentType: string
  tls?: TLSInfo
  bytesUp?: number
  bytesDown?: number
  error?: string
}

export interface SniffConfig {
  sshHost: string
  remoteCmd: string
  filter: string
  excludeSsh: boolean
  dedup: boolean
}

export interface SniffStatus {
  running: boolean
  config: SniffConfig
  error?: string
  stderr?: string
  packets: number
  bytes: number
  startedAt?: string
  pcapBytes: number
}

export interface ProxyConfig {
  addr: string
  mitm: boolean
  bypass: string[] | null
  insecureUpstream: boolean
}

export interface CAInfo { subject: string; notAfter: string; fingerprint: string; keyType: string }

export interface ProxyStatus {
  config: ProxyConfig
  running: boolean
  error?: string
  localIps: string[] | null
  port: string
  ca: CAInfo
  requests: number
}

export interface Status {
  sniff: SniffStatus
  sniffDefault: SniffConfig
  proxy: ProxyStatus
  paused: boolean
  remoteCmd: string
}

export type FlowEvent = { type: 'add' | 'update'; flow: Flow } | { type: 'clear' }
