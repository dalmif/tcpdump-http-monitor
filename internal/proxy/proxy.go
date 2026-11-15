// Package proxy implements an HTTP/HTTPS intercepting (MITM) proxy that
// records every transaction into the flow store.
package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"

	"httpmonitor/internal/flow"
	"httpmonitor/internal/tlsinfo"
)

type Config struct {
	Addr             string   `json:"addr"`
	MITM             bool     `json:"mitm"`
	Bypass           []string `json:"bypass"` // host globs tunnelled without decryption
	InsecureUpstream bool     `json:"insecureUpstream"`
}

type Status struct {
	Config   Config   `json:"config"`
	Running  bool     `json:"running"`
	Error    string   `json:"error,omitempty"`
	LocalIPs []string `json:"localIps"`
	Port     string   `json:"port"`
	CA       CAInfo   `json:"ca"`
	Requests int64    `json:"requests"`
}

type Proxy struct {
	store *flow.Store
	CA    *CA

	mu        sync.RWMutex
	cfg       Config
	srv       *http.Server
	transport *http.Transport
	running   bool
	lastErr   string
	port      string
	requests  atomic.Int64

	rp *httputil.ReverseProxy
}

type ctxKey struct{}

type recState struct {
	id     int64
	start  time.Time
	scheme string
	host   string // authority to connect to
}

func New(store *flow.Store, ca *CA, cfg Config) *Proxy {
	p := &Proxy{store: store, CA: ca, cfg: cfg}
	p.transport = newTransport(cfg.InsecureUpstream)
	p.rp = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			st := pr.In.Context().Value(ctxKey{}).(*recState)
			pr.Out.URL.Scheme = st.scheme
			pr.Out.URL.Host = st.host
			pr.Out.Host = pr.In.Host
			pr.Out.RequestURI = ""
		},
		Transport:     roundTripper{p},
		FlushInterval: -1,
		ModifyResponse: func(resp *http.Response) error {
			st := resp.Request.Context().Value(ctxKey{}).(*recState)
			p.recordResponse(st, resp)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			st := r.Context().Value(ctxKey{}).(*recState)
			p.store.Update(st.id, func(f *flow.Flow) {
				f.State, f.Error = "error", err.Error()
				f.DurationMs = ms(time.Since(st.start))
				if f.Status == 0 {
					f.Status, f.StatusText = 502, "Bad Gateway"
				}
			})
			if !errors.Is(err, context.Canceled) {
				w.WriteHeader(http.StatusBadGateway)
				fmt.Fprintf(w, "httpmonitor proxy error: %v\n", err)
			}
		},
		ErrorLog: log.New(io.Discard, "", 0),
	}
	return p
}

// roundTripper picks up the current transport (it changes with config).
type roundTripper struct{ p *Proxy }

func (rt roundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	rt.p.mu.RLock()
	t := rt.p.transport
	rt.p.mu.RUnlock()
	return t.RoundTrip(r)
}

func newTransport(insecure bool) *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		DisableCompression:    true,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 2 * time.Minute,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: insecure},
	}
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func (p *Proxy) Config() Config {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.cfg
}

func (p *Proxy) Status() Status {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return Status{Config: p.cfg, Running: p.running, Error: p.lastErr, LocalIPs: localIPs(),
		Port: p.port, CA: p.CA.Info(), Requests: p.requests.Load()}
}

// Apply updates the configuration, restarting the listener if the address
// changed.
func (p *Proxy) Apply(cfg Config) error {
	p.mu.Lock()
	old := p.cfg
	p.cfg = cfg
	if old.InsecureUpstream != cfg.InsecureUpstream {
		p.transport.CloseIdleConnections()
		p.transport = newTransport(cfg.InsecureUpstream)
	}
	running := p.running
	p.mu.Unlock()
	if old.Addr != cfg.Addr || !running {
		p.Stop()
		return p.Start()
	}
	return nil
}

func (p *Proxy) Start() error {
	p.mu.Lock()
	addr := p.cfg.Addr
	p.mu.Unlock()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		p.mu.Lock()
		p.lastErr, p.running = err.Error(), false
		p.mu.Unlock()
		return err
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	srv := &http.Server{Handler: p, ReadHeaderTimeout: 30 * time.Second, ErrorLog: log.New(io.Discard, "", 0)}
	p.mu.Lock()
	p.srv, p.running, p.lastErr, p.port = srv, true, "", port
	p.mu.Unlock()
	log.Printf("proxy: listening on %s", ln.Addr())
	go func() {
		err := srv.Serve(ln)
		p.mu.Lock()
		if p.srv == srv {
			p.running = false
			if !errors.Is(err, http.ErrServerClosed) {
				p.lastErr = err.Error()
			}
		}
		p.mu.Unlock()
	}()
	return nil
}

func (p *Proxy) Stop() {
	p.mu.Lock()
	srv := p.srv
	p.srv, p.running = nil, false
	p.mu.Unlock()
	if srv != nil {
		srv.Close()
	}
}

// Port returns the port the proxy listens on.
func (p *Proxy) Port() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.port
}

func (p *Proxy) bypassed(host string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if !p.cfg.MITM {
		return true
	}
	host = strings.ToLower(host)
	for _, pat := range p.cfg.Bypass {
		pat = strings.ToLower(strings.TrimSpace(pat))
		if pat == "" {
			continue
		}
		if ok, _ := path.Match(pat, host); ok || pat == host {
			return true
		}
		if strings.HasPrefix(pat, "*.") && host == pat[2:] {
			return true
		}
	}
	return false
}

func (p *Proxy) isSelf(hostport string) bool {
	h, port, err := net.SplitHostPort(hostport)
	if err != nil {
		h, port = hostport, "80"
	}
	if port != p.Port() {
		return false
	}
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsUnspecified() {
		return true
	}
	for _, l := range localIPs() {
		if l == ip.String() {
			return true
		}
	}
	return false
}

// ServeHTTP handles proxy requests (absolute-form and CONNECT) as well as
// direct requests to the proxy (the CA download page).
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.requests.Add(1)
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	if !r.URL.IsAbs() || p.isSelf(r.URL.Host) {
		p.serveLocal(w, r)
		return
	}
	host := r.URL.Host
	if !strings.Contains(host, ":") || strings.HasSuffix(host, "]") {
		host = net.JoinHostPort(strings.Trim(host, "[]"), "80")
	}
	p.forward(w, r, "http", r.RemoteAddr, host, nil)
}

func (p *Proxy) serveLocal(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/ca.pem":
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", `attachment; filename="httpmonitor-ca.pem"`)
		w.Write(p.CA.CertPEM())
	case "/ca.crt", "/ssl":
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Header().Set("Content-Disposition", `attachment; filename="httpmonitor-ca.crt"`)
		w.Write(p.CA.CertDER())
	default:
		info := p.CA.Info()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!doctype html><meta name="viewport" content="width=device-width"><title>httpmonitor CA</title>
<body style="font-family:system-ui;max-width:640px;margin:2em auto;padding:0 16px;line-height:1.5">
<h1>httpmonitor proxy</h1><p>Install the CA certificate on this device to let the proxy decrypt HTTPS.</p>
<p><a href="/ca.crt">Download CA (.crt / DER)</a> &middot; <a href="/ca.pem">Download CA (.pem)</a></p>
<p><small>%s<br>SHA-256 %s</small></p>
<h3>iOS</h3><ol><li>Open this page in Safari, download the .crt, then Settings → General → VPN &amp; Device Management → install.</li>
<li>Settings → General → About → Certificate Trust Settings → enable full trust.</li></ol>
<h3>Android</h3><p>Settings → Security → Encryption &amp; credentials → Install a certificate → CA certificate. (Apps must opt in to user CAs.)</p>
<h3>macOS / Windows / Linux</h3><p>Import the CA into the system/browser trust store as a trusted root.</p></body>`, info.Subject, info.Fingerprint)
	}
}

// ---- CONNECT ----

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(b []byte) (int, error) { return c.r.Read(b) }

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	authority := r.Host
	if _, _, err := net.SplitHostPort(authority); err != nil {
		authority = net.JoinHostPort(authority, "443")
	}
	hostname, _, _ := net.SplitHostPort(authority)
	conn, brw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	bc := &bufConn{Conn: conn, r: brw.Reader}
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	first, err := bc.r.Peek(1)
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		return
	}
	switch {
	case first[0] == 0x16 && !p.bypassed(hostname):
		p.mitm(bc, authority, r.RemoteAddr)
	case first[0] == 0x16:
		p.tunnel(bc, authority, r.RemoteAddr)
	case first[0] >= 'A' && first[0] <= 'Z':
		p.serveConn(bc, "http", authority, r.RemoteAddr, nil)
	default:
		p.tunnel(bc, authority, r.RemoteAddr)
	}
}

func (p *Proxy) mitm(bc *bufConn, authority, client string) {
	hostname, _, _ := net.SplitHostPort(authority)
	var sni string
	tc := tls.Server(bc, &tls.Config{
		GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			sni = h.ServerName
			name := h.ServerName
			if name == "" {
				name = hostname
			}
			return p.CA.Leaf(name)
		},
		NextProtos: []string{"h2", "http/1.1"},
	})
	rejected := func(err error) {
		if sni == "" {
			sni = hostname
		}
		p.store.Add(&flow.Flow{
			Source: "proxy", Kind: "tls", State: "error", Client: client, Server: authority,
			Method: "TLS", Scheme: "https", Host: sni, URL: "https://" + sni + "/", Path: "/",
			TLS:   &flow.TLSInfo{SNI: sni},
			Error: "client rejected the proxy certificate (" + err.Error() + "). Install & trust the CA on the device, or add this host to the bypass list if the app pins certificates",
		})
	}
	tc.SetDeadline(time.Now().Add(30 * time.Second))
	if err := tc.Handshake(); err != nil {
		rejected(err)
		return
	}
	// With TLS 1.3 the client verifies our certificate only after the
	// server side of the handshake is complete, and reports a rejection as
	// an alert on the first read. Peek one byte to surface that.
	pc := &peekTLSConn{Conn: tc, r: bufio.NewReader(tc)}
	tc.SetDeadline(time.Now().Add(60 * time.Second))
	if _, err := pc.r.Peek(1); err != nil {
		// A clean EOF is just an idle speculative connection; an alert or
		// an immediate reset means the client refused our certificate.
		if msg := err.Error(); strings.Contains(msg, "remote error") || strings.Contains(msg, "connection reset") {
			rejected(err)
		}
		return
	}
	tc.SetDeadline(time.Time{})
	if sni != "" {
		_, port, _ := net.SplitHostPort(authority)
		authority = net.JoinHostPort(sni, port)
	}
	state := tc.ConnectionState()
	if state.NegotiatedProtocol == "h2" {
		h2 := &http2.Server{IdleTimeout: 2 * time.Minute}
		h2.ServeConn(pc, &http2.ServeConnOpts{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				p.forward(w, r, "https", client, authority, &state)
			}),
		})
		return
	}
	p.serveConn(pc, "https", authority, client, &state)
}

// peekTLSConn lets us peek at a TLS connection's plaintext while still
// exposing ConnectionState (used by the h2 server).
type peekTLSConn struct {
	*tls.Conn
	r *bufio.Reader
}

func (c *peekTLSConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// serveConn runs an HTTP/1.x server on a single connection.
func (p *Proxy) serveConn(c net.Conn, scheme, authority, client string, state *tls.ConnectionState) {
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p.forward(w, r, scheme, client, authority, state)
		}),
		ErrorLog:          log.New(io.Discard, "", 0),
		ReadHeaderTimeout: 60 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	l := newOneConnListener(c)
	srv.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateClosed || st == http.StateHijacked {
			l.finished()
		}
	}
	srv.Serve(l)
}

func (p *Proxy) tunnel(bc *bufConn, authority, client string) {
	var info tlsinfo.HelloInfo
	if hdr, err := bc.r.Peek(5); err == nil && hdr[0] == 0x16 {
		n := 5 + (int(hdr[3])<<8 | int(hdr[4]))
		if rec, err := bc.r.Peek(min(n, bc.r.Size())); err == nil {
			_, info, _ = tlsinfo.ParseHello(rec)
		}
	}
	host := info.SNI
	if host == "" {
		host, _, _ = net.SplitHostPort(authority)
	}
	start := time.Now()
	id := p.store.Add(&flow.Flow{
		Source: "proxy", Kind: "tls", State: "pending", Client: client, Server: authority,
		Method: "TLS", Scheme: "https", Host: host, URL: "https://" + host + "/", Path: "/", StartedAt: start,
		TLS: &flow.TLSInfo{SNI: info.SNI, ALPN: strings.Join(info.ALPN, ",")},
	})
	up, err := net.DialTimeout("tcp", authority, 15*time.Second)
	if err != nil {
		p.store.Update(id, func(f *flow.Flow) { f.State, f.Error = "error", err.Error() })
		return
	}
	defer up.Close()
	var sent, recv int64
	done := make(chan struct{})
	go func() {
		sent, _ = io.Copy(up, bc)
		if tc, ok := up.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		close(done)
	}()
	recv, _ = io.Copy(bc, up)
	bc.Close()
	<-done
	p.store.Update(id, func(f *flow.Flow) {
		f.State, f.BytesUp, f.BytesDown, f.DurationMs = "done", sent, recv, ms(time.Since(start))
	})
}

// ---- forwarding & recording ----

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, scheme, client, authority string, state *tls.ConnectionState) {
	start := time.Now()
	var reqBody []byte
	if r.Body != nil {
		reqBody, _ = io.ReadAll(io.LimitReader(r.Body, 256<<20))
		r.Body.Close()
	}
	r.Body = io.NopCloser(bytes.NewReader(reqBody))
	r.ContentLength = int64(len(reqBody))
	if len(reqBody) == 0 && r.ContentLength == 0 {
		r.Body = http.NoBody
	}

	host := r.Host
	if host == "" {
		host = authority
	}
	// Drop default ports for display.
	displayHost := strings.TrimSuffix(strings.TrimSuffix(host, ":443"), ":80")
	u := scheme + "://" + displayHost + r.URL.RequestURI()
	recBody, _ := flow.Decode(reqBody, r.Header.Get("Content-Encoding"))
	trunc := false
	if len(recBody) > flow.MaxBody {
		recBody, trunc = recBody[:flow.MaxBody], true
	}
	kind := "http"
	if scheme == "https" {
		kind = "https"
	}
	hdrs := flow.HeadersFrom(r.Header)
	if r.ProtoMajor < 2 {
		hdrs = append([]flow.Header{{Name: "Host", Value: r.Host}}, hdrs...)
	} else {
		hdrs = append([]flow.Header{{Name: ":authority", Value: r.Host}}, hdrs...)
	}
	f := &flow.Flow{
		Source: "proxy", Kind: kind, State: "pending", StartedAt: start, Client: client, Server: authority,
		Method: r.Method, URL: u, Scheme: scheme, Host: displayHost, Path: r.URL.RequestURI(), Proto: r.Proto,
		ReqHeaders: hdrs, ReqBody: recBody, ReqSize: int64(len(reqBody)), ReqTrunc: trunc,
		ReqContentType: r.Header.Get("Content-Type"),
	}
	if state == nil {
		state = r.TLS
	}
	if state != nil {
		f.TLS = &flow.TLSInfo{SNI: state.ServerName, Version: tls.VersionName(state.Version), ALPN: state.NegotiatedProtocol}
	}
	id := p.store.Add(f)
	st := &recState{id: id, start: start, scheme: scheme, host: authority}
	r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, st))
	p.rp.ServeHTTP(w, r)
}

func (p *Proxy) recordResponse(st *recState, resp *http.Response) {
	hdrs := flow.HeadersFrom(resp.Header)
	p.store.Update(st.id, func(f *flow.Flow) {
		f.Status, f.StatusText = resp.StatusCode, strings.TrimPrefix(resp.Status, fmt.Sprint(resp.StatusCode)+" ")
		f.RespHeaders = hdrs
		f.RespContentType = resp.Header.Get("Content-Type")
		f.DurationMs = ms(time.Since(st.start))
		if resp.StatusCode == http.StatusSwitchingProtocols {
			f.State = "done"
		}
	})
	if resp.StatusCode == http.StatusSwitchingProtocols {
		return // body is the upgraded connection; leave untouched
	}
	enc := resp.Header.Get("Content-Encoding")
	resp.Body = &recordingBody{rc: resp.Body, done: func(buf []byte, total int64, trunc bool, err error) {
		body, derr := flow.Decode(buf, enc)
		if derr != nil {
			body = buf
		}
		p.store.Update(st.id, func(f *flow.Flow) {
			f.RespBody, f.RespSize, f.RespTrunc = body, total, trunc
			f.DurationMs = ms(time.Since(st.start))
			if err != nil && !errors.Is(err, io.EOF) {
				f.State, f.Error = "error", "response body: "+err.Error()
			} else {
				f.State = "done"
			}
		})
	}}
}

type recordingBody struct {
	rc    io.ReadCloser
	buf   []byte
	total int64
	trunc bool
	once  sync.Once
	done  func(buf []byte, total int64, trunc bool, err error)
}

func (b *recordingBody) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	if n > 0 {
		b.total += int64(n)
		if room := flow.MaxBody - len(b.buf); room > 0 {
			b.buf = append(b.buf, p[:min(n, room)]...)
		}
		if b.total > flow.MaxBody {
			b.trunc = true
		}
	}
	if err != nil {
		b.finish(err)
	}
	return n, err
}

func (b *recordingBody) finish(err error) {
	b.once.Do(func() { b.done(b.buf, b.total, b.trunc, err) })
}

func (b *recordingBody) Close() error {
	err := b.rc.Close()
	b.finish(io.EOF)
	return err
}

// ---- compose / replay ----

// Send issues a request from the proxy (used by "Repeat" and "Compose") and
// records it. It returns the new flow ID immediately.
func (p *Proxy) Send(method, rawURL string, headers []flow.Header, body []byte) (int64, error) {
	req, err := http.NewRequest(method, rawURL, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	for _, h := range headers {
		name := h.Name
		if strings.HasPrefix(name, ":") {
			continue
		}
		switch strings.ToLower(name) {
		case "host":
			req.Host = h.Value
			continue
		case "content-length", "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade":
			continue
		}
		req.Header.Add(name, h.Value)
	}
	start := time.Now()
	kind := "http"
	if req.URL.Scheme == "https" {
		kind = "https"
	}
	recBody, _ := flow.Decode(body, req.Header.Get("Content-Encoding"))
	f := &flow.Flow{
		Source: "compose", Kind: kind, State: "pending", StartedAt: start, Client: "httpmonitor",
		Method: req.Method, URL: req.URL.String(), Scheme: req.URL.Scheme, Host: req.URL.Host,
		Path: req.URL.RequestURI(), Proto: "HTTP/1.1",
		ReqHeaders: flow.HeadersFrom(req.Header, flow.Header{Name: "Host", Value: req.Host}),
		ReqBody:    recBody, ReqSize: int64(len(body)), ReqContentType: req.Header.Get("Content-Type"),
		Server: req.URL.Host,
	}
	id := p.store.Add(f)
	st := &recState{id: id, start: start}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		resp, err := roundTripper{p}.RoundTrip(req.WithContext(ctx))
		if err != nil {
			p.store.Update(id, func(f *flow.Flow) {
				f.State, f.Error, f.DurationMs = "error", err.Error(), ms(time.Since(start))
			})
			return
		}
		p.recordResponse(st, resp)
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()
	return id, nil
}

// ---- helpers ----

type oneConnListener struct {
	c        net.Conn
	once     sync.Once
	doneOnce sync.Once
	done     chan struct{}
}

func newOneConnListener(c net.Conn) *oneConnListener {
	return &oneConnListener{c: c, done: make(chan struct{})}
}

// Accept hands out the connection once (unwrapped, so net/http still sees a
// *tls.Conn and can negotiate h2), then blocks until it is closed.
func (l *oneConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.c })
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}
func (l *oneConnListener) finished()      { l.doneOnce.Do(func() { close(l.done) }) }
func (l *oneConnListener) Close() error   { return nil }
func (l *oneConnListener) Addr() net.Addr { return l.c.LocalAddr() }

func localIPs() []string {
	var out []string
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				out = append(out, ipn.IP.String())
			}
		}
	}
	return out
}
