package proxy

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"httpmonitor/internal/flow"
)

func setup(t *testing.T) (*flow.Store, *Proxy, *x509.CertPool) {
	store := flow.NewStore(100)
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := New(store, ca, Config{Addr: "127.0.0.1:0", MITM: true, InsecureUpstream: true})
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Stop)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM())
	return store, p, pool
}

func client(p *Proxy, pool *x509.CertPool, h2 bool) *http.Client {
	pu, _ := url.Parse("http://127.0.0.1:" + p.Port())
	tr := &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{RootCAs: pool}, ForceAttemptHTTP2: h2}
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

func waitDone(t *testing.T, store *flow.Store, n int) []*flow.Flow {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		all := store.All()
		done := 0
		for _, f := range all {
			if f.State != "pending" {
				done++
			}
		}
		if len(all) >= n && done == len(all) {
			return all
		}
		time.Sleep(20 * time.Millisecond)
	}
	all := store.All()
	for _, f := range all {
		t.Logf("flow %+v", f.Summary())
	}
	t.Fatalf("timed out waiting for %d done flows", n)
	return nil
}

func upstream() *httptest.Server {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "sid=abc; Path=/")
		fmt.Fprintf(w, `{"method":%q,"path":%q,"body":%q,"proto":%q}`, r.Method, r.URL.RequestURI(), b, r.Proto)
	})
	return httptest.NewUnstartedServer(h)
}

func TestMITMHTTPS(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("h2=%v", h2), func(t *testing.T) {
			store, p, pool := setup(t)
			up := upstream()
			up.EnableHTTP2 = true
			up.StartTLS()
			defer up.Close()

			c := client(p, pool, h2)
			// httptest certs are for 127.0.0.1 / example.com; use the IP.
			resp, err := c.Post(up.URL+"/hello?x=1", "text/plain", strings.NewReader("ping"))
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if !bytes.Contains(body, []byte(`"body":"ping"`)) {
				t.Fatalf("unexpected body %s", body)
			}
			wantProto := "HTTP/1.1"
			if h2 {
				wantProto = "HTTP/2.0"
			}
			if resp.Proto != wantProto {
				t.Errorf("client<->proxy proto = %s, want %s", resp.Proto, wantProto)
			}
			fs := waitDone(t, store, 1)
			f := store.Get(fs[0].ID)
			if f.Kind != "https" || f.Method != "POST" || f.Status != 200 || string(f.ReqBody) != "ping" || !bytes.Equal(f.RespBody, body) {
				t.Errorf("bad flow: %+v", f)
			}
			if !strings.HasSuffix(f.URL, "/hello?x=1") || !strings.HasPrefix(f.URL, "https://127.0.0.1:") {
				t.Errorf("bad URL %s", f.URL)
			}
		})
	}
}

func TestPlainHTTPAndGzip(t *testing.T) {
	store, p, pool := setup(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/plain")
		w.Write(gzBytes("decoded text"))
	}))
	defer up.Close()
	c := client(p, pool, false)
	req, _ := http.NewRequest("GET", up.URL+"/g", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := c.Transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Equal(raw, gzBytes("decoded text")) {
		t.Errorf("proxy must pass the encoded body through unchanged")
	}
	fs := waitDone(t, store, 1)
	f := store.Get(fs[0].ID)
	if f.Kind != "http" || string(f.RespBody) != "decoded text" {
		t.Errorf("bad flow %+v body=%q", f, f.RespBody)
	}
}

func TestUntrustedClientAndBypass(t *testing.T) {
	store, p, _ := setup(t)
	up := upstream()
	up.StartTLS()
	defer up.Close()

	// Client that doesn't trust our CA → handshake error flow.
	c := client(p, x509.NewCertPool(), false)
	if _, err := c.Get(up.URL); err == nil {
		t.Fatal("expected TLS error")
	}
	fs := waitDone(t, store, 1)
	if fs[0].Kind != "tls" || fs[0].State != "error" {
		t.Errorf("want tls error flow, got %+v", fs[0])
	}

	// Bypassed host → tunnel; client sees the upstream's real cert.
	store.Clear()
	cfg := p.Config()
	cfg.Bypass = []string{"127.0.0.1"}
	p.Apply(cfg)
	pool := x509.NewCertPool()
	pool.AddCert(up.Certificate())
	c = client(p, pool, false)
	resp, err := c.Get(up.URL + "/tunnel")
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	c.CloseIdleConnections()
	fs = waitDone(t, store, 1)
	if fs[0].Kind != "tls" || fs[0].BytesDown == 0 {
		t.Errorf("want tunnelled tls flow, got %+v", fs[0])
	}
}

func TestComposeAndHAR(t *testing.T) {
	store, p, _ := setup(t)
	up := upstream()
	up.Start()
	defer up.Close()
	id, err := p.Send("PUT", up.URL+"/c", []flow.Header{{Name: "X-Test", Value: "1"}}, []byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	waitDone(t, store, 1)
	f := store.Get(id)
	if f.Status != 200 || !bytes.Contains(f.RespBody, []byte(`"method":"PUT"`)) {
		t.Fatalf("bad compose flow %+v", f)
	}

	har := flow.ToHAR(store.All())
	b, _ := json.Marshal(har)
	back, err := flow.FromHAR(bytes.NewReader(b))
	if err != nil || len(back) != 1 {
		t.Fatalf("HAR roundtrip: %v %d", err, len(back))
	}
	if back[0].Method != "PUT" || string(back[0].ReqBody) != "data" || !bytes.Equal(back[0].RespBody, f.RespBody) || back[0].Status != 200 {
		t.Errorf("HAR roundtrip mismatch: %+v", back[0])
	}
	if len(har.Log.Entries[0].Response.Cookies) != 1 || har.Log.Entries[0].Response.Cookies[0].Name != "sid" {
		t.Errorf("cookies not parsed: %+v", har.Log.Entries[0].Response.Cookies)
	}
}

func TestCAPage(t *testing.T) {
	_, p, _ := setup(t)
	resp, err := http.Get("http://127.0.0.1:" + p.Port() + "/ca.crt")
	if err != nil {
		t.Fatal(err)
	}
	der, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if _, err := x509.ParseCertificate(der); err != nil {
		t.Errorf("CA download not a certificate: %v", err)
	}
}

func TestCAReplaceRejectsMismatch(t *testing.T) {
	c1, _, _ := GenerateCA("a")
	_, k2, _ := GenerateCA("b")
	ca, _ := LoadOrCreateCA(t.TempDir())
	if err := ca.Replace(c1, k2); err == nil {
		t.Error("expected mismatch error")
	}
}

func gzBytes(s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.Bytes()
}
