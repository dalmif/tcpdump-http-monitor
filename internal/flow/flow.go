// Package flow holds captured HTTP transactions in memory and fans out
// change events to subscribers (the web UI).
package flow

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// MaxBody is the maximum number of body bytes kept per message.
const MaxBody = 4 << 20

type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type TLSInfo struct {
	SNI     string `json:"sni,omitempty"`
	Version string `json:"version,omitempty"`
	ALPN    string `json:"alpn,omitempty"`
}

// Flow is one HTTP request/response pair (or an opaque TLS connection when
// the traffic could not be decrypted).
type Flow struct {
	ID         int64     `json:"id"`
	Source     string    `json:"source"` // sniff | proxy | import
	Kind       string    `json:"kind"`   // http | https | tls
	State      string    `json:"state"`  // pending | done | error
	StartedAt  time.Time `json:"startedAt"`
	DurationMs float64   `json:"durationMs"`
	Client     string    `json:"client"`
	Server     string    `json:"server"`

	Method string `json:"method"`
	URL    string `json:"url"`
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
	Path   string `json:"path"`
	Proto  string `json:"proto"`

	Status     int    `json:"status"`
	StatusText string `json:"statusText"`

	ReqHeaders  []Header `json:"reqHeaders,omitempty"`
	RespHeaders []Header `json:"respHeaders,omitempty"`
	ReqBody     []byte   `json:"reqBody,omitempty"`
	RespBody    []byte   `json:"respBody,omitempty"`
	ReqSize     int64    `json:"reqSize"`  // body size on the wire
	RespSize    int64    `json:"respSize"` // body size on the wire
	ReqTrunc    bool     `json:"reqTruncated,omitempty"`
	RespTrunc   bool     `json:"respTruncated,omitempty"`

	ReqContentType  string `json:"reqContentType"`
	RespContentType string `json:"respContentType"`

	TLS       *TLSInfo `json:"tls,omitempty"`
	BytesUp   int64    `json:"bytesUp,omitempty"`
	BytesDown int64    `json:"bytesDown,omitempty"`
	Error     string   `json:"error,omitempty"`
}

// Summary returns a copy without headers and bodies, for list views.
func (f *Flow) Summary() *Flow {
	c := *f
	c.ReqHeaders, c.RespHeaders, c.ReqBody, c.RespBody = nil, nil, nil, nil
	return &c
}

func (f *Flow) clone() *Flow {
	c := *f
	return &c
}

// HeadersFrom converts an http.Header into an ordered list (sorted by name
// since Go maps lose order).
func HeadersFrom(h http.Header, extra ...Header) []Header {
	out := append([]Header{}, extra...)
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sortStrings(keys)
	for _, k := range keys {
		for _, v := range h[k] {
			out = append(out, Header{Name: k, Value: v})
		}
	}
	return out
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// ReadBody reads up to MaxBody bytes from r, drains the rest, and decodes the
// given Content-Encoding. It returns the decoded body, the wire size and
// whether the body was truncated.
func ReadBody(r io.Reader, encoding string) (body []byte, wire int64, trunc bool) {
	if r == nil {
		return nil, 0, false
	}
	raw, _ := io.ReadAll(io.LimitReader(r, MaxBody+1))
	wire = int64(len(raw))
	if len(raw) > MaxBody {
		n, _ := io.Copy(io.Discard, r)
		wire += n
		raw = raw[:MaxBody]
		trunc = true
	}
	if dec, err := Decode(raw, encoding); err == nil {
		return dec, wire, trunc
	}
	return raw, wire, trunc
}

// Decode undoes a Content-Encoding.
func Decode(b []byte, encoding string) ([]byte, error) {
	enc := strings.ToLower(strings.TrimSpace(encoding))
	if len(b) == 0 || enc == "" || enc == "identity" {
		return b, nil
	}
	var r io.Reader
	switch enc {
	case "gzip", "x-gzip":
		gr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		r = gr
	case "deflate":
		r = flate.NewReader(bytes.NewReader(b))
	case "br":
		r = brotli.NewReader(bytes.NewReader(b))
	case "zstd":
		zr, err := zstd.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		r = zr
	default:
		return b, nil
	}
	out, err := io.ReadAll(io.LimitReader(r, 4*MaxBody))
	if err != nil && len(out) == 0 {
		return nil, err
	}
	return out, nil
}

// Event is pushed to subscribers.
type Event struct {
	Type string `json:"type"` // add | update | clear
	Flow *Flow  `json:"flow,omitempty"`
}

// Store is an in-memory ring of flows.
type Store struct {
	mu     sync.RWMutex
	max    int
	nextID int64
	order  []int64
	flows  map[int64]*Flow
	subs   map[chan Event]struct{}
	paused bool
}

func NewStore(max int) *Store {
	return &Store{max: max, flows: map[int64]*Flow{}, subs: map[chan Event]struct{}{}}
}

func (s *Store) SetPaused(p bool) { s.mu.Lock(); s.paused = p; s.mu.Unlock() }
func (s *Store) Paused() bool     { s.mu.RLock(); defer s.mu.RUnlock(); return s.paused }

// Add stores a new flow (assigning its ID) and returns the ID, or 0 if
// recording is paused.
func (s *Store) Add(f *Flow) int64 {
	s.mu.Lock()
	if s.paused {
		s.mu.Unlock()
		return 0
	}
	s.nextID++
	f.ID = s.nextID
	if f.StartedAt.IsZero() {
		f.StartedAt = time.Now()
	}
	s.flows[f.ID] = f
	s.order = append(s.order, f.ID)
	for len(s.order) > s.max {
		delete(s.flows, s.order[0])
		s.order = s.order[1:]
	}
	ev := Event{Type: "add", Flow: f.Summary()}
	s.broadcastLocked(ev)
	s.mu.Unlock()
	return f.ID
}

// Update mutates a stored flow under lock and notifies subscribers.
func (s *Store) Update(id int64, fn func(f *Flow)) {
	if id == 0 {
		return
	}
	s.mu.Lock()
	f, ok := s.flows[id]
	if ok {
		fn(f)
		s.broadcastLocked(Event{Type: "update", Flow: f.Summary()})
	}
	s.mu.Unlock()
}

func (s *Store) Get(id int64) *Flow {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if f, ok := s.flows[id]; ok {
		return f.clone()
	}
	return nil
}

// All returns copies of all flows in capture order.
func (s *Store) All() []*Flow {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Flow, 0, len(s.order))
	for _, id := range s.order {
		out = append(out, s.flows[id].clone())
	}
	return out
}

func (s *Store) Clear() {
	s.mu.Lock()
	s.order = nil
	s.flows = map[int64]*Flow{}
	s.broadcastLocked(Event{Type: "clear"})
	s.mu.Unlock()
}

func (s *Store) Subscribe() (chan Event, func()) {
	ch := make(chan Event, 4096)
	s.mu.Lock()
	s.subs[ch] = struct{}{}
	s.mu.Unlock()
	return ch, func() {
		s.mu.Lock()
		delete(s.subs, ch)
		s.mu.Unlock()
	}
}

func (s *Store) broadcastLocked(ev Event) {
	for ch := range s.subs {
		select {
		case ch <- ev:
		default: // slow consumer; drop
		}
	}
}
