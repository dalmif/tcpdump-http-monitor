package sniff

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"httpmonitor/internal/flow"
)

// tcpConv writes a synthetic TCP conversation to a pcap writer.
type tcpConv struct {
	w            *pcapgo.Writer
	cIP, sIP     net.IP
	cPort, sPort uint16
	cSeq, sSeq   uint32
	ts           time.Time
	t            *testing.T
}

func (c *tcpConv) pkt(fromClient bool, syn, ack, fin bool, payload []byte) {
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{0, 1, 2, 3, 4, 6}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: c.cIP, DstIP: c.sIP}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(c.cPort), DstPort: layers.TCPPort(c.sPort), SYN: syn, ACK: ack, FIN: fin, Window: 65535}
	seq, other := &c.cSeq, &c.sSeq
	if !fromClient {
		ip.SrcIP, ip.DstIP = c.sIP, c.cIP
		tcp.SrcPort, tcp.DstPort = tcp.DstPort, tcp.SrcPort
		seq, other = &c.sSeq, &c.cSeq
	}
	tcp.Seq, tcp.Ack = *seq, *other
	tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		c.t.Fatal(err)
	}
	*seq += uint32(len(payload))
	if syn || fin {
		*seq++
	}
	c.ts = c.ts.Add(time.Millisecond)
	data := buf.Bytes()
	c.w.WritePacket(gopacket.CaptureInfo{Timestamp: c.ts, CaptureLength: len(data), Length: len(data)}, data)
}

func (c *tcpConv) handshake() {
	c.pkt(true, true, false, false, nil)
	c.pkt(false, true, true, false, nil)
	c.pkt(true, false, true, false, nil)
}

func (c *tcpConv) close() {
	c.pkt(true, false, true, true, nil)
	c.pkt(false, false, true, true, nil)
	c.pkt(true, false, true, false, nil)
}

func gz(s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.Bytes()
}

func clientHello(t *testing.T, sni string) []byte {
	a, b := net.Pipe()
	go func() {
		c := tls.Client(a, &tls.Config{ServerName: sni, NextProtos: []string{"h2", "http/1.1"}})
		c.Handshake()
	}()
	buf := make([]byte, 16384)
	b.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := io.ReadAtLeast(b, buf, 5)
	if err != nil {
		t.Fatal(err)
	}
	need := 5 + (int(buf[3])<<8 | int(buf[4]))
	for n < need {
		m, err := b.Read(buf[n:])
		if err != nil {
			t.Fatal(err)
		}
		n += m
	}
	a.Close()
	b.Close()
	return buf[:need]
}

func TestProcessHTTPAndTLS(t *testing.T) {
	var pc bytes.Buffer
	w := pcapgo.NewWriter(&pc)
	w.WriteFileHeader(65535, layers.LinkTypeEthernet)

	req1 := "GET /api/items?q=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n"
	body := gz(`{"items":[1,2,3]}`)
	resp1 := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: " + itoa(len(body)) + "\r\n\r\n" + string(body)
	req2 := "POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello"
	resp2 := "HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"

	// Same conversation seen twice: device side and post-NAT side.
	for _, cip := range []string{"192.0.2.50", "198.51.100.2"} {
		c := &tcpConv{w: w, cIP: net.ParseIP(cip).To4(), sIP: net.ParseIP("203.0.113.34").To4(), cPort: 40000, sPort: 80, cSeq: 1000, sSeq: 5000, ts: time.Now(), t: t}
		c.handshake()
		c.pkt(true, false, true, false, []byte(req1))
		c.pkt(false, false, true, false, []byte(resp1))
		c.pkt(true, false, true, false, []byte(req2))
		c.pkt(false, false, true, false, []byte(resp2))
		c.close()
	}

	// A TLS connection.
	tc := &tcpConv{w: w, cIP: net.ParseIP("192.0.2.50").To4(), sIP: net.ParseIP("203.0.113.4").To4(), cPort: 40001, sPort: 443, cSeq: 1, sSeq: 1, ts: time.Now(), t: t}
	tc.handshake()
	tc.pkt(true, false, true, false, clientHello(t, "secure.example.org"))
	tc.pkt(false, false, true, false, []byte{0x16, 3, 3, 0, 4, 2, 0, 0, 0}) // truncated ServerHello
	tc.close()

	store := flow.NewStore(100)
	s := New(store, Config{})
	if err := s.Process(context.Background(), &pc, true); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond) // let stream goroutines finish

	flows := store.All()
	var http1, http2, tlsF *flow.Flow
	for _, f := range flows {
		switch {
		case f.Path == "/api/items?q=1":
			if http1 != nil {
				t.Errorf("NAT duplicate not suppressed")
			}
			http1 = f
		case f.Path == "/submit":
			http2 = f
		case f.Kind == "tls":
			tlsF = f
		}
	}
	if len(flows) != 3 {
		for _, f := range flows {
			t.Logf("flow: %+v", f.Summary())
		}
		t.Fatalf("want 3 flows, got %d", len(flows))
	}
	if http1 == nil || http1.Status != 200 || string(http1.RespBody) != `{"items":[1,2,3]}` || http1.URL != "http://example.com/api/items?q=1" {
		t.Errorf("bad flow 1: %+v body=%q", http1, http1.RespBody)
	}
	if http1.Client != "192.0.2.50:40000" {
		t.Errorf("expected device-side client, got %s", http1.Client)
	}
	if http2 == nil || http2.Status != 201 || string(http2.ReqBody) != "hello" || string(http2.RespBody) != "abc" {
		t.Errorf("bad flow 2: %+v", http2)
	}
	if tlsF == nil || tlsF.Host != "secure.example.org" || tlsF.TLS.ALPN != "h2,http/1.1" || tlsF.State != "done" {
		t.Errorf("bad tls flow: %+v %+v", tlsF, tlsF.TLS)
	}

	// Raw packets were recorded for pcap export.
	var out bytes.Buffer
	if err := s.WritePcap(&out); err != nil {
		t.Fatal(err)
	}
	r, err := pcapgo.NewReader(&out)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for {
		if _, _, err := r.ReadPacketData(); err != nil {
			break
		}
		n++
	}
	if n != 2*10+8 {
		t.Errorf("pcap export: want 28 packets, got %d", n)
	}
	s.ResetPcap()
}

func itoa(n int) string { return fmtInt(n) }

func fmtInt(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestRemoteCommand(t *testing.T) {
	cfg := Config{Filter: "tcp port 80", ExcludeSSH: true}
	if got := RemoteCommand(cfg); got != "tcpdump -U -s0 -w - 'not port 22 and (tcp port 80)'" {
		t.Errorf("default: got %q", got)
	}
	cfg.RemoteCmd = "{filter}" // forced-command account
	if got := RemoteCommand(cfg); got != "not port 22 and (tcp port 80)" {
		t.Errorf("forced: got %q", got)
	}
	cfg.RemoteCmd = "tcpdump -w - {qfilter}"
	if got := RemoteCommand(cfg); got != "tcpdump -w - 'not port 22 and (tcp port 80)'" {
		t.Errorf("got %q", got)
	}
}

// An orphan response (request not captured) must not stall other streams.
func TestOrphanResponseDoesNotStall(t *testing.T) {
	var pc bytes.Buffer
	w := pcapgo.NewWriter(&pc)
	w.WriteFileHeader(65535, layers.LinkTypeEthernet)
	now := time.Now()

	orphan := &tcpConv{w: w, cIP: net.ParseIP("192.0.2.1").To4(), sIP: net.ParseIP("192.0.2.78").To4(), cPort: 50000, sPort: 49152, cSeq: 1, sSeq: 1, ts: now, t: t}
	orphan.handshake()
	orphan.pkt(true, false, true, false, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}) // non-HTTP request side
	orphan.pkt(false, false, true, false, []byte("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n01234"))
	orphan.pkt(false, false, true, false, []byte("56789"))
	orphan.pkt(false, false, true, false, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))

	sub := &tcpConv{w: w, cIP: net.ParseIP("192.0.2.1").To4(), sIP: net.ParseIP("192.0.2.78").To4(), cPort: 50001, sPort: 49152, cSeq: 1, sSeq: 1, ts: now, t: t}
	sub.handshake()
	sub.pkt(true, false, true, false, []byte("SUBSCRIBE /upnp/event/svc1 HTTP/1.1\r\nHOST: 192.0.2.78:49152\r\nNT: upnp:event\r\n\r\n"))
	sub.pkt(false, false, true, false, []byte("HTTP/1.1 200 OK\r\nSID: uuid:x\r\nContent-Length: 0\r\n\r\n"))
	sub.close()

	store := flow.NewStore(100)
	start := time.Now()
	New(store, Config{}).Process(context.Background(), &pc, true)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		for _, f := range store.All() {
			if f.Method == "SUBSCRIBE" && f.State == "done" {
				if time.Since(start) > 2*time.Second {
					t.Fatalf("SUBSCRIBE flow completed late: %v", time.Since(start))
				}
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, f := range store.All() {
		t.Logf("%+v", f.Summary())
	}
	t.Fatal("SUBSCRIBE flow not completed within 1s (assembler stalled?)")
}

func TestLooksLikeRequestLine(t *testing.T) {
	for s, want := range map[string]bool{
		"GET / HTTP/1.1":          true,
		"NOTIFY /evt HTTP/1.1":    true,
		"M-SEARCH * HTTP/1.1":     true,
		"POST http://x/ HTTP/1.1": true,
		"CONNECT a:443 HTTP/1.1":  true,
		"HTTP/1.1 200 OK":         false,
		"\x16\x03\x01\x02\x00":    false,
		"SSH-2.0-OpenSSH":         false,
	} {
		if got := looksLikeRequestLine([]byte(s)); got != want {
			t.Errorf("%q: got %v want %v", s, got, want)
		}
	}
}
