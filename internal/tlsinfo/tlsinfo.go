// Package tlsinfo parses cleartext TLS handshake messages.
package tlsinfo

import (
	"encoding/binary"
	"fmt"
)

// HelloInfo is what we can learn from cleartext TLS handshake messages.
type HelloInfo struct {
	SNI     string
	ALPN    []string
	Version uint16 // negotiated (ServerHello) version
}

func VersionName(v uint16) string {
	switch v {
	case 0x0304:
		return "TLS 1.3"
	case 0x0303:
		return "TLS 1.2"
	case 0x0302:
		return "TLS 1.1"
	case 0x0301:
		return "TLS 1.0"
	case 0:
		return ""
	}
	return fmt.Sprintf("0x%04x", v)
}

type rd struct {
	b   []byte
	err bool
}

func (r *rd) n(k int) []byte {
	if r.err || len(r.b) < k {
		r.err = true
		return nil
	}
	out := r.b[:k]
	r.b = r.b[k:]
	return out
}
func (r *rd) u8() int {
	b := r.n(1)
	if b == nil {
		return 0
	}
	return int(b[0])
}
func (r *rd) u16() int {
	b := r.n(2)
	if b == nil {
		return 0
	}
	return int(binary.BigEndian.Uint16(b))
}
func (r *rd) u24() int {
	b := r.n(3)
	if b == nil {
		return 0
	}
	return int(b[0])<<16 | int(b[1])<<8 | int(b[2])
}

// ParseHello parses a TLS record containing a ClientHello (type 1) or
// ServerHello (type 2). rec must start at the record header.
func ParseHello(rec []byte) (hs int, info HelloInfo, ok bool) {
	r := &rd{b: rec}
	if r.u8() != 0x16 {
		return 0, info, false
	}
	r.n(2) // record version
	recLen := r.u16()
	body := r.n(min(recLen, len(r.b)))
	if r.err {
		return 0, info, false
	}
	r = &rd{b: body}
	hs = r.u8()
	hlen := r.u24()
	if hs != 1 && hs != 2 {
		return hs, info, false
	}
	if hlen < len(r.b) {
		r.b = r.b[:hlen]
	}
	legacyVer := r.u16()
	r.n(32) // random
	r.n(r.u8())
	if hs == 1 {
		r.n(r.u16()) // cipher suites
		r.n(r.u8())  // compression
	} else {
		r.n(2) // cipher
		r.n(1) // compression
		info.Version = uint16(legacyVer)
	}
	if r.err || len(r.b) < 2 {
		return hs, info, !r.err
	}
	ext := &rd{b: r.n(r.u16())}
	for !ext.err && len(ext.b) >= 4 {
		typ := ext.u16()
		data := &rd{b: ext.n(ext.u16())}
		switch typ {
		case 0: // server_name
			if hs == 1 {
				data.u16()
				if data.u8() == 0 {
					info.SNI = string(data.n(data.u16()))
				}
			}
		case 16: // ALPN
			l := &rd{b: data.n(data.u16())}
			for !l.err && len(l.b) > 0 {
				p := l.n(l.u8())
				if p != nil {
					info.ALPN = append(info.ALPN, string(p))
				}
			}
		case 43: // supported_versions
			if hs == 2 {
				info.Version = uint16(data.u16())
			}
		}
	}
	return hs, info, true
}
