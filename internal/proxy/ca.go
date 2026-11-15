package proxy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CA signs leaf certificates on the fly for MITM.
type CA struct {
	mu      sync.RWMutex
	cert    *x509.Certificate
	certPEM []byte
	key     crypto.Signer
	leafKey *ecdsa.PrivateKey
	cache   map[string]*tls.Certificate
	dir     string
}

// LoadOrCreateCA loads ca.pem/ca-key.pem from dir, generating them if absent.
func LoadOrCreateCA(dir string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	ca := &CA{dir: dir}
	certPEM, err1 := os.ReadFile(filepath.Join(dir, "ca.pem"))
	keyPEM, err2 := os.ReadFile(filepath.Join(dir, "ca-key.pem"))
	if err1 == nil && err2 == nil {
		if err := ca.set(certPEM, keyPEM); err != nil {
			return nil, fmt.Errorf("loading CA from %s: %w", dir, err)
		}
		return ca, nil
	}
	certPEM, keyPEM, err := GenerateCA("httpmonitor CA")
	if err != nil {
		return nil, err
	}
	if err := ca.Replace(certPEM, keyPEM); err != nil {
		return nil, err
	}
	return ca, nil
}

// GenerateCA creates a new self-signed CA certificate and key (PEM).
func GenerateCA(name string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	host, _ := os.Hostname()
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: fmt.Sprintf("%s (%s)", name, host), Organization: []string{"httpmonitor"}},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), nil
}

func parseKey(der []byte) (crypto.Signer, error) {
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if s, ok := k.(crypto.Signer); ok {
			return s, nil
		}
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	return nil, errors.New("unsupported private key format")
}

func (c *CA) set(certPEM, keyPEM []byte) error {
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return errors.New("no PEM certificate found")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return err
	}
	if !cert.IsCA {
		return errors.New("certificate is not a CA (basicConstraints CA:TRUE missing)")
	}
	var key crypto.Signer
	for rest := keyPEM; ; {
		var kb *pem.Block
		kb, rest = pem.Decode(rest)
		if kb == nil {
			break
		}
		if k, err := parseKey(kb.Bytes); err == nil {
			key = k
			break
		}
	}
	if key == nil {
		return errors.New("no usable private key found in key PEM")
	}
	if !publicKeysEqual(cert.PublicKey, key.Public()) {
		return errors.New("private key does not match certificate")
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.cert, c.certPEM, c.key, c.leafKey = cert, pem.EncodeToMemory(cb), key, leafKey
	c.cache = map[string]*tls.Certificate{}
	c.mu.Unlock()
	return nil
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	type eq interface{ Equal(crypto.PublicKey) bool }
	if e, ok := a.(eq); ok {
		return e.Equal(b)
	}
	return false
}

// Replace installs a new CA (cert + key PEM) and persists it.
func (c *CA) Replace(certPEM, keyPEM []byte) error {
	if err := c.set(certPEM, keyPEM); err != nil {
		return err
	}
	if c.dir != "" {
		if err := os.WriteFile(filepath.Join(c.dir, "ca.pem"), certPEM, 0o644); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(c.dir, "ca-key.pem"), keyPEM, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func (c *CA) CertPEM() []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.certPEM
}

func (c *CA) CertDER() []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cert.Raw
}

type CAInfo struct {
	Subject     string    `json:"subject"`
	NotAfter    time.Time `json:"notAfter"`
	Fingerprint string    `json:"fingerprint"`
	KeyType     string    `json:"keyType"`
}

func (c *CA) Info() CAInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	sum := sha256.Sum256(c.cert.Raw)
	kt := "ECDSA"
	if _, ok := c.key.(*rsa.PrivateKey); ok {
		kt = "RSA"
	}
	return CAInfo{Subject: c.cert.Subject.String(), NotAfter: c.cert.NotAfter, Fingerprint: hex.EncodeToString(sum[:]), KeyType: kt}
}

// Leaf returns (and caches) a certificate for host signed by the CA.
func (c *CA) Leaf(host string) (*tls.Certificate, error) {
	c.mu.RLock()
	if lc, ok := c.cache[host]; ok {
		c.mu.RUnlock()
		return lc, nil
	}
	caCert, caKey, leafKey := c.cert, c.key, c.leafKey
	c.mu.RUnlock()

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host, Organization: []string{"httpmonitor"}},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().AddDate(0, 0, 397), // Apple requires <= 398 days
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tpl.IPAddresses = []net.IP{ip}
	} else {
		tpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	lc := &tls.Certificate{Certificate: [][]byte{der, caCert.Raw}, PrivateKey: leafKey}
	c.mu.Lock()
	if len(c.cache) > 5000 {
		c.cache = map[string]*tls.Certificate{}
	}
	c.cache[host] = lc
	c.mu.Unlock()
	return lc, nil
}
