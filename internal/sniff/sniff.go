// Package sniff captures packets from a remote host via `ssh <host> tcpdump`
// (or a forced-command account that streams pcap), reassembles TCP streams
// and extracts HTTP transactions and TLS connection metadata.
package sniff

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/gopacket/gopacket/tcpassembly"
	"github.com/gopacket/gopacket/tcpassembly/tcpreader"

	"httpmonitor/internal/flow"
	"httpmonitor/internal/tlsinfo"
)

// Config controls how the capture is started.
type Config struct {
	SSHHost string `json:"sshHost"`
	// RemoteCmd is the command run over ssh. {filter} is replaced with the
	// raw BPF filter, {qfilter} with a shell-quoted one. Use just
	// "{filter}" for a forced-command account whose authorized_keys entry
	// runs tcpdump itself and passes $SSH_ORIGINAL_COMMAND as the filter.
	RemoteCmd  string `json:"remoteCmd"`
	Filter     string `json:"filter"`
	ExcludeSSH bool   `json:"excludeSsh"`
	Dedup      bool   `json:"dedup"` // collapse NAT duplicates
}

// Status is reported to the UI.
type Status struct {
	Running   bool      `json:"running"`
	Config    Config    `json:"config"`
	Error     string    `json:"error,omitempty"`
	Stderr    string    `json:"stderr,omitempty"`
	Packets   int64     `json:"packets"`
	Bytes     int64     `json:"bytes"`
	StartedAt time.Time `json:"startedAt,omitempty"`
	PcapBytes int64     `json:"pcapBytes"`
}

type Sniffer struct {
	store *flow.Store

	mu        sync.Mutex
	cfg       Config
	cancel    context.CancelFunc
	running   bool
	lastErr   string
	stderr    *tailBuf
	startedAt time.Time
	done      chan struct{}

	packets, bytes atomic.Int64

	pcapMu    sync.Mutex
	pcapPath  string
	pcapFile  *os.File
	pcapW     *pcapgo.Writer
	pcapLink  layers.LinkType
	pcapBytes int64
}

const maxPcap = 1 << 30 // stop recording raw packets after 1 GiB

func New(store *flow.Store, cfg Config) *Sniffer {
	return &Sniffer{store: store, cfg: cfg, stderr: &tailBuf{max: 4096}}
}

func (s *Sniffer) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pcapMu.Lock()
	pb := s.pcapBytes
	s.pcapMu.Unlock()
	return Status{
		Running: s.running, Config: s.cfg, Error: s.lastErr, Stderr: s.stderr.String(),
		Packets: s.packets.Load(), Bytes: s.bytes.Load(), StartedAt: s.startedAt, PcapBytes: pb,
	}
}

// BuildFilter returns the effective BPF filter.
func BuildFilter(cfg Config) string {
	f := strings.TrimSpace(cfg.Filter)
	if cfg.ExcludeSSH {
		if f == "" {
			return "not port 22"
		}
		return "not port 22 and (" + f + ")"
	}
	return f
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// RemoteCommand returns the command line executed on the remote host.
func RemoteCommand(cfg Config) string {
	tpl := cfg.RemoteCmd
	if strings.TrimSpace(tpl) == "" {
		tpl = "tcpdump -U -s0 -w - {qfilter}"
	}
	f := BuildFilter(cfg)
	tpl = strings.ReplaceAll(tpl, "{qfilter}", shellQuote(f))
	return strings.ReplaceAll(tpl, "{filter}", f)
}

// Start begins capturing with cfg. Any running capture is stopped first.
func (s *Sniffer) Start(cfg Config) error {
	s.Stop()
	if cfg.SSHHost == "" {
		return errors.New("ssh host is required")
	}
	ctx, cancel := context.WithCancel(context.Background())
	remote := RemoteCommand(cfg)
	cmd := exec.CommandContext(ctx, "ssh",
		"-o", "BatchMode=yes", "-o", "ServerAliveInterval=15", "-o", "ConnectTimeout=10",
		cfg.SSHHost, remote)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return err
	}
	s.stderr.Reset()
	cmd.Stderr = s.stderr
	if err := cmd.Start(); err != nil {
		cancel()
		return err
	}
	log.Printf("sniff: started ssh %s %q", cfg.SSHHost, remote)

	s.mu.Lock()
	s.cfg, s.cancel, s.running, s.lastErr = cfg, cancel, true, ""
	s.startedAt = time.Now()
	s.done = make(chan struct{})
	done := s.done
	s.mu.Unlock()
	s.packets.Store(0)
	s.bytes.Store(0)

	go func() {
		defer close(done)
		perr := s.Process(ctx, stdout, cfg.Dedup)
		werr := cmd.Wait()
		s.mu.Lock()
		s.running = false
		if ctx.Err() == nil { // not stopped by user
			msg := ""
			if perr != nil && !errors.Is(perr, io.EOF) {
				msg = perr.Error()
			}
			if werr != nil {
				msg = strings.TrimSpace(msg + " " + werr.Error())
			}
			if msg == "" {
				msg = "capture ended"
			}
			s.lastErr = msg
		}
		s.mu.Unlock()
		log.Printf("sniff: stopped (process=%v, wait=%v)", perr, werr)
	}()
	return nil
}

func (s *Sniffer) Stop() {
	s.mu.Lock()
	cancel, done := s.cancel, s.done
	s.cancel = nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
		if done != nil {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
			}
		}
	}
}

// ResetPcap discards recorded raw packets (used on Clear).
func (s *Sniffer) ResetPcap() {
	s.pcapMu.Lock()
	defer s.pcapMu.Unlock()
	if s.pcapFile != nil {
		s.pcapFile.Close()
		os.Remove(s.pcapPath)
	}
	s.pcapFile, s.pcapW, s.pcapPath, s.pcapBytes = nil, nil, "", 0
}

// WritePcap writes the raw captured packets to w as a pcap file.
func (s *Sniffer) WritePcap(w io.Writer) error {
	s.pcapMu.Lock()
	path := s.pcapPath
	link := s.pcapLink
	if s.pcapFile != nil {
		s.pcapFile.Sync()
	}
	s.pcapMu.Unlock()
	if path == "" {
		pw := pcapgo.NewWriter(w)
		if link == 0 {
			link = layers.LinkTypeEthernet
		}
		return pw.WriteFileHeader(262144, link)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(w, f)
	return err
}

func (s *Sniffer) recordPacket(link layers.LinkType, ci gopacket.CaptureInfo, data []byte) {
	s.pcapMu.Lock()
	defer s.pcapMu.Unlock()
	if s.pcapW == nil || s.pcapLink != link {
		if s.pcapFile != nil {
			s.pcapFile.Close()
			os.Remove(s.pcapPath)
		}
		f, err := os.CreateTemp("", "httpmonitor-*.pcap")
		if err != nil {
			return
		}
		s.pcapFile, s.pcapPath, s.pcapLink, s.pcapBytes = f, f.Name(), link, 24
		s.pcapW = pcapgo.NewWriter(f)
		s.pcapW.WriteFileHeader(262144, link)
	}
	if s.pcapBytes > maxPcap {
		return
	}
	if err := s.pcapW.WritePacket(ci, data); err == nil {
		s.pcapBytes += int64(16 + len(data))
	}
}

// Process reads a pcap stream and feeds the flow store until EOF or ctx is
// cancelled.
func (s *Sniffer) Process(ctx context.Context, r io.Reader, dedup bool) error {
	pr, err := pcapgo.NewReader(bufio.NewReaderSize(r, 1<<20))
	if err != nil {
		return fmt.Errorf("reading pcap header: %w", err)
	}
	link := pr.LinkType()

	fac := &factory{store: s.store, conns: map[string]*pairing{}, dd: newDeduper(dedup)}
	asm := tcpassembly.NewAssembler(tcpassembly.NewStreamPool(fac))
	asm.MaxBufferedPagesTotal = 200000
	asm.MaxBufferedPagesPerConnection = 2000

	type pkt struct {
		data []byte
		ci   gopacket.CaptureInfo
	}
	pkts := make(chan pkt, 4096)
	readErr := make(chan error, 1)
	go func() {
		for {
			data, ci, err := pr.ReadPacketData()
			if err != nil {
				readErr <- err
				close(pkts)
				return
			}
			select {
			case pkts <- pkt{data, ci}:
			case <-ctx.Done():
				readErr <- ctx.Err()
				close(pkts)
				return
			}
		}
	}()

	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	var lastTS time.Time
	var tsOffset time.Duration // wall clock minus packet clock
	for {
		select {
		case p, ok := <-pkts:
			if !ok {
				asm.FlushAll()
				fac.dd.stop()
				return <-readErr
			}
			s.packets.Add(1)
			s.bytes.Add(int64(len(p.data)))
			s.recordPacket(link, p.ci, p.data)
			packet := gopacket.NewPacket(p.data, link, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
			nl := packet.NetworkLayer()
			tl, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
			if nl == nil || tl == nil {
				continue
			}
			lastTS = p.ci.Timestamp
			tsOffset = time.Since(lastTS)
			asm.AssembleWithTimestamp(nl.NetworkFlow(), tl, p.ci.Timestamp)
		case <-tick.C:
			if !lastTS.IsZero() {
				// Flush streams idle for 2 minutes (in packet-clock time).
				asm.FlushOlderThan(time.Now().Add(-tsOffset).Add(-2 * time.Minute))
			}
			fac.gc()
		case <-ctx.Done():
			asm.FlushAll()
			fac.dd.stop()
			return ctx.Err()
		}
	}
}

// ---- stream handling ----

type pairing struct {
	c       *conn
	created time.Time
}

type factory struct {
	store *flow.Store
	dd    *deduper
	seq   uint64 // connections in capture order
	mu    sync.Mutex
	conns map[string]*pairing
}

func (f *factory) gc() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, p := range f.conns {
		if time.Since(p.created) > 5*time.Minute {
			delete(f.conns, k)
		}
	}
}

func (f *factory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	src := net.JoinHostPort(netFlow.Src().String(), tcpFlow.Src().String())
	dst := net.JoinHostPort(netFlow.Dst().String(), tcpFlow.Dst().String())
	key := src + "|" + dst
	if dst < src {
		key = dst + "|" + src
	}
	f.mu.Lock()
	p := f.conns[key]
	if p == nil {
		f.seq++
		p = &pairing{c: &conn{f: f, seq: f.seq, reqs: make(chan *pending, 256)}, created: time.Now()}
		f.conns[key] = p
	} else {
		delete(f.conns, key)
	}
	f.mu.Unlock()
	rs := tcpreader.NewReaderStream()
	go p.c.run(&rs, src, dst)
	return &rs
}

type pending struct {
	id    int64
	start time.Time
	req   *http.Request
}

type conn struct {
	f    *factory
	seq  uint64
	reqs chan *pending

	mu      sync.Mutex
	tlsID   int64
	tlsDown int64
	tlsVer  uint16
	tlsALPN string
	tlsDone int
}

// looksLikeRequestLine reports whether b starts like "METHOD target HTTP/",
// for any method token (GET, NOTIFY, SUBSCRIBE, M-SEARCH, PROPFIND, ...).
func looksLikeRequestLine(b []byte) bool {
	i := 0
	for i < len(b) && i < 20 && (b[i] >= 'A' && b[i] <= 'Z' || b[i] == '-' || b[i] == '_') {
		i++
	}
	if i < 3 || i >= len(b) || b[i] != ' ' {
		return false
	}
	rest := b[i+1:]
	return len(rest) > 0 && (rest[0] == '/' || rest[0] == '*' || bytes.HasPrefix(rest, []byte("http")) ||
		(b[0] == 'C' && bytes.HasPrefix(b, []byte("CONNECT "))))
}

func (c *conn) run(rs *tcpreader.ReaderStream, src, dst string) {
	// Copy the stream into an elastic buffer immediately so that a slow
	// parser (e.g. waiting for its matching request) never blocks the
	// single-threaded TCP assembler and stalls every other connection.
	bp := newBufPipe(64 << 20)
	go func() {
		_, err := io.Copy(bp, rs)
		bp.CloseWithError(err)
	}()
	br := bufio.NewReaderSize(bp, 64<<10)
	defer io.Copy(io.Discard, br)
	head, err := br.Peek(5)
	if err != nil {
		return
	}
	if n := br.Buffered(); n > 5 {
		head, _ = br.Peek(min(n, 32))
	}
	switch {
	case bytes.HasPrefix(head, []byte("HTTP/")):
		c.readResponses(br, dst, src)
	case looksLikeRequestLine(head):
		c.readRequests(br, src, dst)
	case head[0] == 0x16 && head[1] == 3:
		c.readTLS(br, src, dst)
	}
}

// bufPipe is an in-memory pipe whose writer never blocks (up to max bytes;
// beyond that data is dropped and the reader gets an error).
type bufPipe struct {
	mu     sync.Mutex
	cond   *sync.Cond
	buf    []byte
	max    int
	err    error
	closed bool
}

func newBufPipe(max int) *bufPipe {
	p := &bufPipe{max: max}
	p.cond = sync.NewCond(&p.mu)
	return p
}

var errOverflow = errors.New("stream buffer overflow")

func (p *bufPipe) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return len(b), nil // reader gave up; discard
	}
	if len(p.buf)+len(b) > p.max {
		p.err, p.closed = errOverflow, true
		p.buf = nil
		p.cond.Broadcast()
		return len(b), nil
	}
	p.buf = append(p.buf, b...)
	p.cond.Signal()
	return len(b), nil
}

func (p *bufPipe) CloseWithError(err error) {
	p.mu.Lock()
	if err == nil {
		err = io.EOF
	}
	if p.err == nil {
		p.err = err
	}
	p.closed = true
	p.cond.Broadcast()
	p.mu.Unlock()
}

func (p *bufPipe) Read(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for len(p.buf) == 0 && !p.closed {
		p.cond.Wait()
	}
	if len(p.buf) == 0 {
		return 0, p.err
	}
	n := copy(b, p.buf)
	p.buf = p.buf[n:]
	if len(p.buf) == 0 {
		p.buf = nil // release memory
	}
	return n, nil
}

func splitHost(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}

func splitPort(addr string) string {
	_, p, _ := net.SplitHostPort(addr)
	return p
}

func (c *conn) readRequests(br *bufio.Reader, src, dst string) {
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		start := time.Now()
		body, wire, trunc := flow.ReadBody(req.Body, req.Header.Get("Content-Encoding"))
		host := req.Host
		if host == "" {
			host = dst
		}
		u := "http://" + host + req.RequestURI
		if strings.HasPrefix(req.RequestURI, "http://") || strings.HasPrefix(req.RequestURI, "https://") {
			u = req.RequestURI
			if req.URL != nil {
				host = req.URL.Host
			}
		}
		path := req.RequestURI
		if req.URL != nil && req.URL.IsAbs() {
			path = req.URL.RequestURI()
		}
		f := &flow.Flow{
			Source: "sniff", Kind: "http", State: "pending", StartedAt: start,
			Client: src, Server: dst,
			Method: req.Method, URL: u, Scheme: "http", Host: host, Path: path, Proto: req.Proto,
			ReqHeaders: flow.HeadersFrom(req.Header, flow.Header{Name: "Host", Value: req.Host}),
			ReqBody:    body, ReqSize: wire, ReqTrunc: trunc,
			ReqContentType: req.Header.Get("Content-Type"),
		}
		id := c.f.dd.add(dst+"|"+splitPort(src)+"|"+req.Method+" "+u, src, c.seq, c.f.store, f)
		dbg("request %s -> %s %s %s id=%d", src, dst, req.Method, u, id)
		c.reqs <- &pending{id: id, start: start, req: req}
	}
}

func (c *conn) readResponses(br *bufio.Reader, client, server string) {
	defer func() {
		// Anything still queued never got a response.
		for {
			select {
			case p := <-c.reqs:
				c.f.store.Update(p.id, func(f *flow.Flow) {
					f.State, f.Error = "error", "no response captured"
				})
			default:
				return
			}
		}
	}()
	for {
		if _, err := br.Peek(1); err != nil {
			return
		}
		var p *pending
		select {
		case p = <-c.reqs:
		case <-time.After(3 * time.Second):
		}
		dbg("response stream got pending=%v", p != nil)
		var req *http.Request
		if p != nil {
			req = p.req
		}
		for {
			resp, err := http.ReadResponse(br, req)
			if err != nil {
				if p != nil {
					c.f.store.Update(p.id, func(f *flow.Flow) { f.State, f.Error = "error", "bad response: "+err.Error() })
				}
				return
			}
			if resp.StatusCode == 100 || resp.StatusCode == 103 {
				continue // interim response; the real one follows
			}
			body, wire, trunc := flow.ReadBody(resp.Body, resp.Header.Get("Content-Encoding"))
			if p == nil {
				c.f.dd.add(server+"|"+splitPort(client)+"|resp|"+resp.Status, client, c.seq, c.f.store, &flow.Flow{
					Source: "sniff", Kind: "http", State: "done", Method: "?", Proto: resp.Proto,
					Client: client, Server: server, Host: server, Scheme: "http", URL: "http://" + server + "/",
					Status: resp.StatusCode, StatusText: statusText(resp.Status),
					RespHeaders: flow.HeadersFrom(resp.Header), RespBody: body, RespSize: wire, RespTrunc: trunc,
					RespContentType: resp.Header.Get("Content-Type"), Error: "request not captured",
				})
			} else {
				c.f.store.Update(p.id, func(f *flow.Flow) {
					f.State = "done"
					f.DurationMs = float64(time.Since(p.start).Microseconds()) / 1000
					f.Status, f.StatusText = resp.StatusCode, statusText(resp.Status)
					f.RespHeaders = flow.HeadersFrom(resp.Header)
					f.RespBody, f.RespSize, f.RespTrunc = body, wire, trunc
					f.RespContentType = resp.Header.Get("Content-Type")
				})
			}
			if resp.StatusCode == 101 {
				return // protocol switched (e.g. WebSocket)
			}
			break
		}
	}
}

func statusText(status string) string {
	if _, rest, ok := strings.Cut(status, " "); ok {
		return rest
	}
	return status
}

func readRecord(br *bufio.Reader) []byte {
	hdr, err := br.Peek(5)
	if err != nil {
		return nil
	}
	n := 5 + (int(hdr[3])<<8 | int(hdr[4]))
	if n > 5+(1<<14)+2048 {
		return nil
	}
	rec, err := br.Peek(n)
	if err != nil {
		return nil
	}
	return rec
}

func (c *conn) readTLS(br *bufio.Reader, src, dst string) {
	rec := readRecord(br)
	hs, info, _ := tlsinfo.ParseHello(rec)
	switch hs {
	case 1: // ClientHello: this is the client→server direction
		start := time.Now()
		f := &flow.Flow{
			Source: "sniff", Kind: "tls", State: "pending", StartedAt: start,
			Client: src, Server: dst, Method: "TLS", Scheme: "https", Host: info.SNI,
			TLS: &flow.TLSInfo{SNI: info.SNI, ALPN: strings.Join(info.ALPN, ",")},
		}
		if f.Host == "" {
			f.Host = splitHost(dst)
		}
		f.URL = "https://" + f.Host + "/"
		if p := splitPort(dst); p != "443" {
			f.URL = "https://" + f.Host + ":" + p + "/"
		}
		f.Path = "/"
		id := c.f.dd.add(dst+"|"+splitPort(src)+"|tls|"+info.SNI, src, c.seq, c.f.store, f)
		c.mu.Lock()
		c.tlsID = id
		c.mu.Unlock()
		n, _ := io.Copy(io.Discard, br)
		c.finishTLS(func(f *flow.Flow) {
			f.BytesUp = n
			f.DurationMs = float64(time.Since(start).Microseconds()) / 1000
		})
	case 2: // ServerHello
		c.mu.Lock()
		c.tlsVer = info.Version
		if len(info.ALPN) > 0 {
			c.tlsALPN = info.ALPN[0]
		}
		c.mu.Unlock()
		n, _ := io.Copy(io.Discard, br)
		c.finishTLS(func(f *flow.Flow) { f.BytesDown = n })
	}
}

// finishTLS applies fn once the flow ID is known; when both directions are
// done, the flow is marked complete.
func (c *conn) finishTLS(fn func(f *flow.Flow)) {
	// Wait briefly for the client side to register the flow.
	for i := 0; i < 50; i++ {
		c.mu.Lock()
		id := c.tlsID
		c.mu.Unlock()
		if id != 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	c.mu.Lock()
	c.tlsDone++
	id, done, ver, alpn := c.tlsID, c.tlsDone, c.tlsVer, c.tlsALPN
	c.mu.Unlock()
	c.f.store.Update(id, func(f *flow.Flow) {
		fn(f)
		if f.TLS != nil {
			if ver != 0 {
				f.TLS.Version = tlsinfo.VersionName(ver)
			}
			if alpn != "" {
				f.TLS.ALPN = alpn
			}
		}
		if done >= 2 {
			f.State = "done"
		}
	})
}

// ---- NAT duplicate suppression ----

// deduper drops a transaction when the same key was seen within a short
// window from a *different* client IP — that's the same packet observed
// before and after NAT on the gateway. The copy whose connection was seen
// first in the capture (the device side, before NAT) supplies the client
// address, even if the post-NAT copy happened to be parsed first.
type deduper struct {
	on   bool
	mu   sync.Mutex
	seen map[string]dedupEntry
	quit chan struct{}
}

type dedupEntry struct {
	ip  string
	seq uint64
	id  int64
	at  time.Time
}

func newDeduper(on bool) *deduper {
	d := &deduper{on: on, seen: map[string]dedupEntry{}, quit: make(chan struct{})}
	if on {
		go func() {
			t := time.NewTicker(10 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-t.C:
					d.mu.Lock()
					for k, e := range d.seen {
						if time.Since(e.at) > 10*time.Second {
							delete(d.seen, k)
						}
					}
					d.mu.Unlock()
				case <-d.quit:
					return
				}
			}
		}()
	}
	return d
}

func (d *deduper) stop() {
	select {
	case <-d.quit:
	default:
		close(d.quit)
	}
}

// add stores f unless it is a NAT duplicate, returning the new flow ID (0
// for duplicates).
func (d *deduper) add(key, client string, seq uint64, store *flow.Store, f *flow.Flow) int64 {
	if !d.on {
		return store.Add(f)
	}
	ip := splitHost(client)
	d.mu.Lock()
	defer d.mu.Unlock()
	if e, ok := d.seen[key]; ok && e.ip != ip && time.Since(e.at) < 5*time.Second {
		if seq < e.seq {
			store.Update(e.id, func(x *flow.Flow) { x.Client = client })
			e.ip, e.seq = ip, seq
			d.seen[key] = e
		}
		return 0
	}
	id := store.Add(f)
	d.seen[key] = dedupEntry{ip: ip, seq: seq, id: id, at: time.Now()}
	return id
}

// ---- helpers ----

var debug = os.Getenv("HTTPMON_DEBUG") != ""

func dbg(format string, args ...any) {
	if debug {
		log.Printf("sniff: "+format, args...)
	}
}

type tailBuf struct {
	mu  sync.Mutex
	max int
	b   []byte
}

func (t *tailBuf) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.b = append(t.b, p...)
	if len(t.b) > t.max {
		t.b = t.b[len(t.b)-t.max:]
	}
	return len(p), nil
}
func (t *tailBuf) String() string { t.mu.Lock(); defer t.mu.Unlock(); return string(t.b) }
func (t *tailBuf) Reset()         { t.mu.Lock(); t.b = nil; t.mu.Unlock() }
