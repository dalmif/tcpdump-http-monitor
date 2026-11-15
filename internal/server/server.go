// Package server exposes the REST/SSE API and serves the embedded web UI.
package server

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"

	"httpmonitor/internal/flow"
	"httpmonitor/internal/proxy"
	"httpmonitor/internal/sniff"
)

type Server struct {
	Store   *flow.Store
	Sniffer *sniff.Sniffer
	Proxy   *proxy.Proxy
	UI      fs.FS // may be nil
	// DefaultSniff is offered to the UI as the initial capture config.
	DefaultSniff sniff.Config
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/status", s.status)
	mux.HandleFunc("GET /api/events", s.events)
	mux.HandleFunc("GET /api/flows", s.listFlows)
	mux.HandleFunc("GET /api/flows/{id}", s.getFlow)
	mux.HandleFunc("GET /api/flows/{id}/body/{part}", s.getBody)
	mux.HandleFunc("POST /api/flows/{id}/replay", s.replay)
	mux.HandleFunc("POST /api/compose", s.compose)
	mux.HandleFunc("POST /api/clear", s.clear)
	mux.HandleFunc("POST /api/pause", s.pause)
	mux.HandleFunc("POST /api/sniff/start", s.sniffStart)
	mux.HandleFunc("POST /api/sniff/stop", s.sniffStop)
	mux.HandleFunc("PUT /api/proxy/config", s.proxyConfig)
	mux.HandleFunc("GET /api/ca.pem", s.caPEM)
	mux.HandleFunc("GET /api/ca.crt", s.caCRT)
	mux.HandleFunc("POST /api/ca", s.caUpload)
	mux.HandleFunc("POST /api/ca/regenerate", s.caRegenerate)
	mux.HandleFunc("GET /api/export/har", s.exportHAR)
	mux.HandleFunc("GET /api/export/pcap", s.exportPcap)
	mux.HandleFunc("POST /api/import/har", s.importHAR)
	if s.UI != nil {
		files := http.FileServerFS(s.UI)
		mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				if _, err := fs.Stat(s.UI, strings.TrimPrefix(r.URL.Path, "/")); err != nil {
					r.URL.Path = "/" // SPA fallback
				}
			}
			files.ServeHTTP(w, r)
		}))
	}
	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func httpErr(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"sniff":        s.Sniffer.Status(),
		"sniffDefault": s.DefaultSniff,
		"proxy":        s.Proxy.Status(),
		"paused":       s.Store.Paused(),
		"remoteCmd":    sniff.RemoteCommand(s.Sniffer.Status().Config),
	})
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", 500)
		return
	}
	ch, unsub := s.Store.Subscribe()
	defer unsub()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")

	all := s.Store.All()
	sums := make([]*flow.Flow, len(all))
	for i, f := range all {
		sums[i] = f.Summary()
	}
	b, _ := json.Marshal(sums)
	fmt.Fprintf(w, "event: snapshot\ndata: %s\n\n", b)
	fl.Flush()

	// Batch events to keep the browser responsive under heavy traffic.
	tick := time.NewTicker(150 * time.Millisecond)
	defer tick.Stop()
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	var batch []flow.Event
	for {
		select {
		case <-r.Context().Done():
			return
		case ev := <-ch:
			batch = append(batch, ev)
		case <-tick.C:
			if len(batch) == 0 {
				continue
			}
			b, _ := json.Marshal(batch)
			batch = batch[:0]
			fmt.Fprintf(w, "event: batch\ndata: %s\n\n", b)
			fl.Flush()
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		}
	}
}

func (s *Server) listFlows(w http.ResponseWriter, r *http.Request) {
	all := s.Store.All()
	for i, f := range all {
		all[i] = f.Summary()
	}
	writeJSON(w, all)
}

func (s *Server) flowFromPath(w http.ResponseWriter, r *http.Request) *flow.Flow {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httpErr(w, 400, err)
		return nil
	}
	f := s.Store.Get(id)
	if f == nil {
		httpErr(w, 404, fmt.Errorf("flow %d not found", id))
		return nil
	}
	return f
}

func (s *Server) getFlow(w http.ResponseWriter, r *http.Request) {
	if f := s.flowFromPath(w, r); f != nil {
		writeJSON(w, f)
	}
}

func (s *Server) getBody(w http.ResponseWriter, r *http.Request) {
	f := s.flowFromPath(w, r)
	if f == nil {
		return
	}
	body, ct, name := f.RespBody, f.RespContentType, "response"
	if r.PathValue("part") == "req" {
		body, ct, name = f.ReqBody, f.ReqContentType, "request"
	}
	if ct == "" {
		ct = http.DetectContentType(body)
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "sandbox")
	if r.URL.Query().Get("download") != "" {
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="flow-%d-%s.bin"`, f.ID, name))
	}
	w.Write(body)
}

func (s *Server) replay(w http.ResponseWriter, r *http.Request) {
	f := s.flowFromPath(w, r)
	if f == nil {
		return
	}
	if f.Kind == "tls" {
		httpErr(w, 400, fmt.Errorf("cannot replay an encrypted TLS connection"))
		return
	}
	id, err := s.Proxy.Send(f.Method, f.URL, f.ReqHeaders, f.ReqBody)
	if err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, map[string]int64{"id": id})
}

type composeReq struct {
	Method  string        `json:"method"`
	URL     string        `json:"url"`
	Headers []flow.Header `json:"headers"`
	Body    string        `json:"body"`
}

func (s *Server) compose(w http.ResponseWriter, r *http.Request) {
	var c composeReq
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		httpErr(w, 400, err)
		return
	}
	if c.Method == "" {
		c.Method = "GET"
	}
	// The body we were given is already decoded, so don't claim an encoding.
	hs := c.Headers[:0]
	for _, h := range c.Headers {
		if !strings.EqualFold(h.Name, "Content-Encoding") {
			hs = append(hs, h)
		}
	}
	id, err := s.Proxy.Send(strings.ToUpper(c.Method), c.URL, hs, []byte(c.Body))
	if err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, map[string]int64{"id": id})
}

func (s *Server) clear(w http.ResponseWriter, r *http.Request) {
	s.Store.Clear()
	s.Sniffer.ResetPcap()
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) pause(w http.ResponseWriter, r *http.Request) {
	var body struct{ Paused bool }
	json.NewDecoder(r.Body).Decode(&body)
	s.Store.SetPaused(body.Paused)
	writeJSON(w, map[string]bool{"paused": body.Paused})
}

func (s *Server) sniffStart(w http.ResponseWriter, r *http.Request) {
	cfg := s.DefaultSniff
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil && err != io.EOF {
		httpErr(w, 400, err)
		return
	}
	if err := s.Sniffer.Start(cfg); err != nil {
		httpErr(w, 500, err)
		return
	}
	writeJSON(w, s.Sniffer.Status())
}

func (s *Server) sniffStop(w http.ResponseWriter, r *http.Request) {
	s.Sniffer.Stop()
	writeJSON(w, s.Sniffer.Status())
}

func (s *Server) proxyConfig(w http.ResponseWriter, r *http.Request) {
	cfg := s.Proxy.Config()
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		httpErr(w, 400, err)
		return
	}
	if err := s.Proxy.Apply(cfg); err != nil {
		httpErr(w, 500, err)
		return
	}
	writeJSON(w, s.Proxy.Status())
}

func (s *Server) caPEM(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="httpmonitor-ca.pem"`)
	w.Write(s.Proxy.CA.CertPEM())
}

func (s *Server) caCRT(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="httpmonitor-ca.crt"`)
	w.Write(s.Proxy.CA.CertDER())
}

// caUpload accepts {"cert": "<PEM>", "key": "<PEM>"}.
func (s *Server) caUpload(w http.ResponseWriter, r *http.Request) {
	var body struct{ Cert, Key string }
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		httpErr(w, 400, err)
		return
	}
	if strings.TrimSpace(body.Key) == "" {
		body.Key = body.Cert // allow a combined PEM
	}
	if err := s.Proxy.CA.Replace([]byte(body.Cert), []byte(body.Key)); err != nil {
		httpErr(w, 400, err)
		return
	}
	writeJSON(w, s.Proxy.CA.Info())
}

func (s *Server) caRegenerate(w http.ResponseWriter, r *http.Request) {
	c, k, err := proxy.GenerateCA("httpmonitor CA")
	if err == nil {
		err = s.Proxy.CA.Replace(c, k)
	}
	if err != nil {
		httpErr(w, 500, err)
		return
	}
	writeJSON(w, s.Proxy.CA.Info())
}

func stamp() string { return time.Now().Format("20060102-150405") }

func (s *Server) exportHAR(w http.ResponseWriter, r *http.Request) {
	flows := s.Store.All()
	if ids := r.URL.Query().Get("ids"); ids != "" {
		want := map[int64]bool{}
		for _, x := range strings.Split(ids, ",") {
			if n, err := strconv.ParseInt(strings.TrimSpace(x), 10, 64); err == nil {
				want[n] = true
			}
		}
		sel := flows[:0]
		for _, f := range flows {
			if want[f.ID] {
				sel = append(sel, f)
			}
		}
		flows = sel
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="httpmonitor-%s.har"`, stamp()))
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(flow.ToHAR(flows))
}

func (s *Server) exportPcap(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="httpmonitor-%s.pcap"`, stamp()))
	s.Sniffer.WritePcap(w)
}

func (s *Server) importHAR(w http.ResponseWriter, r *http.Request) {
	flows, err := flow.FromHAR(io.LimitReader(r.Body, 1<<30))
	if err != nil {
		httpErr(w, 400, fmt.Errorf("invalid HAR: %w", err))
		return
	}
	for _, f := range flows {
		s.Store.Add(f)
	}
	writeJSON(w, map[string]int{"imported": len(flows)})
}
