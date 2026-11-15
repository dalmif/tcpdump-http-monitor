package flow

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

// HAR 1.2 types (http://www.softwareishard.com/blog/har-12-spec/).

type HAR struct {
	Log HARLog `json:"log"`
}

type HARLog struct {
	Version string     `json:"version"`
	Creator HARCreator `json:"creator"`
	Entries []HAREntry `json:"entries"`
}

type HARCreator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type HARNV struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type HAREntry struct {
	StartedDateTime string      `json:"startedDateTime"`
	Time            float64     `json:"time"`
	Request         HARRequest  `json:"request"`
	Response        HARResponse `json:"response"`
	Cache           struct{}    `json:"cache"`
	Timings         HARTimings  `json:"timings"`
	ServerIPAddress string      `json:"serverIPAddress,omitempty"`
	Connection      string      `json:"connection,omitempty"`
	Comment         string      `json:"comment,omitempty"`
	// Custom fields (allowed by spec when prefixed with _).
	Source string `json:"_source,omitempty"`
	Client string `json:"_client,omitempty"`
	Kind   string `json:"_kind,omitempty"`
}

type HARRequest struct {
	Method      string       `json:"method"`
	URL         string       `json:"url"`
	HTTPVersion string       `json:"httpVersion"`
	Cookies     []HARNV      `json:"cookies"`
	Headers     []HARNV      `json:"headers"`
	QueryString []HARNV      `json:"queryString"`
	PostData    *HARPostData `json:"postData,omitempty"`
	HeadersSize int          `json:"headersSize"`
	BodySize    int64        `json:"bodySize"`
}

type HARPostData struct {
	MimeType string  `json:"mimeType"`
	Text     string  `json:"text"`
	Encoding string  `json:"encoding,omitempty"` // non-standard but widely supported
	Params   []HARNV `json:"params,omitempty"`
}

type HARResponse struct {
	Status      int        `json:"status"`
	StatusText  string     `json:"statusText"`
	HTTPVersion string     `json:"httpVersion"`
	Cookies     []HARNV    `json:"cookies"`
	Headers     []HARNV    `json:"headers"`
	Content     HARContent `json:"content"`
	RedirectURL string     `json:"redirectURL"`
	HeadersSize int        `json:"headersSize"`
	BodySize    int64      `json:"bodySize"`
}

type HARContent struct {
	Size     int64  `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`
	Encoding string `json:"encoding,omitempty"`
}

type HARTimings struct {
	Send    float64 `json:"send"`
	Wait    float64 `json:"wait"`
	Receive float64 `json:"receive"`
}

func nv(hs []Header) []HARNV {
	out := make([]HARNV, 0, len(hs))
	for _, h := range hs {
		if strings.HasPrefix(h.Name, ":") {
			continue
		}
		out = append(out, HARNV{h.Name, h.Value})
	}
	return out
}

func headerVal(hs []Header, name string) string {
	for _, h := range hs {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

// IsText reports whether a body should be shown as text.
func IsText(b []byte, contentType string) bool {
	mt, _, _ := mime.ParseMediaType(contentType)
	if strings.HasPrefix(mt, "text/") || strings.Contains(mt, "json") || strings.Contains(mt, "xml") ||
		strings.Contains(mt, "javascript") || strings.Contains(mt, "x-www-form-urlencoded") || strings.Contains(mt, "graphql") {
		return utf8.Valid(b)
	}
	if mt == "" || mt == "application/octet-stream" {
		return utf8.Valid(b) && !strings.ContainsRune(string(b), 0)
	}
	return false
}

func bodyText(b []byte, ct string) (text, encoding string) {
	if len(b) == 0 {
		return "", ""
	}
	if IsText(b, ct) {
		return string(b), ""
	}
	return base64.StdEncoding.EncodeToString(b), "base64"
}

func parseCookies(hs []Header, name string, response bool) []HARNV {
	out := []HARNV{}
	for _, h := range hs {
		if !strings.EqualFold(h.Name, name) {
			continue
		}
		if response {
			first := strings.SplitN(h.Value, ";", 2)[0]
			if k, v, ok := strings.Cut(first, "="); ok {
				out = append(out, HARNV{strings.TrimSpace(k), strings.TrimSpace(v)})
			}
			continue
		}
		for _, part := range strings.Split(h.Value, ";") {
			if k, v, ok := strings.Cut(part, "="); ok {
				out = append(out, HARNV{strings.TrimSpace(k), strings.TrimSpace(v)})
			}
		}
	}
	return out
}

// ToHAR converts flows to a HAR document. Opaque TLS flows are included
// with a CONNECT-style entry so the session context is not lost.
func ToHAR(flows []*Flow) *HAR {
	h := &HAR{Log: HARLog{Version: "1.2", Creator: HARCreator{"httpmonitor", "1.0"}, Entries: []HAREntry{}}}
	for _, f := range flows {
		proto := f.Proto
		if proto == "" {
			proto = "HTTP/1.1"
		}
		e := HAREntry{
			StartedDateTime: f.StartedAt.UTC().Format(time.RFC3339Nano),
			Time:            f.DurationMs,
			Source:          f.Source,
			Client:          f.Client,
			Kind:            f.Kind,
			Timings:         HARTimings{Send: 0, Wait: f.DurationMs, Receive: 0},
		}
		if host, _, ok := strings.Cut(f.Server, ":"); ok {
			e.ServerIPAddress = host
		} else {
			e.ServerIPAddress = f.Server
		}
		u := f.URL
		method := f.Method
		if f.Kind == "tls" {
			method = "CONNECT"
			u = "https://" + f.Host + "/"
			e.Comment = "TLS connection (not decrypted)"
		}
		req := HARRequest{
			Method: method, URL: u, HTTPVersion: proto,
			Cookies: parseCookies(f.ReqHeaders, "Cookie", false), Headers: nv(f.ReqHeaders),
			QueryString: []HARNV{}, HeadersSize: -1, BodySize: f.ReqSize,
		}
		if pu, err := url.Parse(u); err == nil {
			for k, vs := range pu.Query() {
				for _, v := range vs {
					req.QueryString = append(req.QueryString, HARNV{k, v})
				}
			}
		}
		if len(f.ReqBody) > 0 {
			ct := f.ReqContentType
			txt, enc := bodyText(f.ReqBody, ct)
			req.PostData = &HARPostData{MimeType: ct, Text: txt, Encoding: enc}
		}
		resp := HARResponse{
			Status: f.Status, StatusText: f.StatusText, HTTPVersion: proto,
			Cookies: parseCookies(f.RespHeaders, "Set-Cookie", true), Headers: nv(f.RespHeaders),
			RedirectURL: headerVal(f.RespHeaders, "Location"), HeadersSize: -1, BodySize: f.RespSize,
			Content: HARContent{Size: int64(len(f.RespBody)), MimeType: f.RespContentType},
		}
		if f.Kind == "tls" {
			resp.BodySize = f.BytesDown
			req.BodySize = f.BytesUp
		}
		resp.Content.Text, resp.Content.Encoding = bodyText(f.RespBody, f.RespContentType)
		e.Request, e.Response = req, resp
		h.Log.Entries = append(h.Log.Entries, e)
	}
	return h
}

func toHeaders(nvs []HARNV) []Header {
	out := make([]Header, 0, len(nvs))
	for _, x := range nvs {
		out = append(out, Header{x.Name, x.Value})
	}
	return out
}

func harBody(text, enc string) []byte {
	if enc == "base64" {
		b, err := base64.StdEncoding.DecodeString(text)
		if err == nil {
			return b
		}
	}
	return []byte(text)
}

// FromHAR parses a HAR document into flows (IDs unassigned).
func FromHAR(r io.Reader) ([]*Flow, error) {
	var h HAR
	if err := json.NewDecoder(r).Decode(&h); err != nil {
		return nil, err
	}
	out := make([]*Flow, 0, len(h.Log.Entries))
	for _, e := range h.Log.Entries {
		t, _ := time.Parse(time.RFC3339Nano, e.StartedDateTime)
		f := &Flow{
			Source: "import", State: "done", StartedAt: t, DurationMs: e.Time,
			Method: e.Request.Method, URL: e.Request.URL, Proto: e.Request.HTTPVersion,
			Status: e.Response.Status, StatusText: e.Response.StatusText,
			ReqHeaders: toHeaders(e.Request.Headers), RespHeaders: toHeaders(e.Response.Headers),
			Server: e.ServerIPAddress, Client: e.Client, Kind: e.Kind,
			RespContentType: e.Response.Content.MimeType, RespSize: e.Response.BodySize,
			ReqSize: e.Request.BodySize,
		}
		if u, err := url.Parse(e.Request.URL); err == nil {
			f.Scheme, f.Host, f.Path = u.Scheme, u.Host, u.RequestURI()
		}
		if f.Kind == "" {
			f.Kind = "http"
			if f.Scheme == "https" {
				f.Kind = "https"
			}
		}
		if e.Request.Method == "CONNECT" && e.Kind == "tls" {
			f.Host = strings.TrimSuffix(strings.TrimPrefix(e.Request.URL, "https://"), "/")
			f.TLS = &TLSInfo{SNI: f.Host}
		}
		if e.Request.PostData != nil {
			f.ReqBody = harBody(e.Request.PostData.Text, e.Request.PostData.Encoding)
			f.ReqContentType = e.Request.PostData.MimeType
		}
		f.RespBody = harBody(e.Response.Content.Text, e.Response.Content.Encoding)
		out = append(out, f)
	}
	return out, nil
}
