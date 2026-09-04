package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	dohContentType = "application/dns-message"
	dohMaxBody     = 64 << 10 // 64 KiB cap on decoded queries
)

// NewDoHHandler adapts the DNS handler to RFC 8484 HTTP semantics.
func NewDoHHandler(h *Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			h.serveDoHGet(w, r)
		case http.MethodPost:
			h.serveDoHPost(w, r)
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
}

func (h *Handler) serveDoHPost(w http.ResponseWriter, r *http.Request) {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, dohContentType) {
		http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, dohMaxBody+1))
	if err != nil || len(body) == 0 || len(body) > dohMaxBody {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	req := new(dns.Msg)
	if err := req.Unpack(body); err != nil {
		http.Error(w, "malformed DNS message", http.StatusBadRequest)
		return
	}
	h.writeDoHResponse(w, req)
}

func (h *Handler) serveDoHGet(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("dns"))
	if q == "" {
		http.Error(w, "missing dns parameter", http.StatusBadRequest)
		return
	}
	raw, err := base64URLDecode(q)
	if err != nil || len(raw) == 0 {
		http.Error(w, "invalid dns parameter encoding", http.StatusBadRequest)
		return
	}
	if len(raw) > dohMaxBody {
		http.Error(w, "dns parameter too large", http.StatusBadRequest)
		return
	}
	req := new(dns.Msg)
	if err := req.Unpack(raw); err != nil {
		http.Error(w, "malformed DNS message", http.StatusBadRequest)
		return
	}
	h.writeDoHResponse(w, req)
}

// base64URLDecode accepts RFC 4648 §5 base64url, padded or not.
func base64URLDecode(s string) ([]byte, error) {
	if raw, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return raw, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

func (h *Handler) writeDoHResponse(w http.ResponseWriter, req *dns.Msg) {
	var resp *dns.Msg
	if req.Opcode != dns.OpcodeQuery || h.authRequired {
		// Only QUERY rides over DoH; everything else is refused in-band,
		// because DNS errors travel inside the message, not the HTTP status.
		resp = new(dns.Msg)
		resp.SetRcode(req, dns.RcodeRefused)
	} else if len(req.Question) != 1 {
		resp = new(dns.Msg)
		resp.SetRcode(req, dns.RcodeFormatError)
	} else {
		h.metrics.Queries.Add(1)
		resp = h.buildResponse(req)
		if resp.Rcode == dns.RcodeNameError {
			h.metrics.NXDomain.Add(1)
		}
		if opt := req.IsEdns0(); opt != nil {
			reply := new(dns.OPT)
			reply.Hdr.Name = "."
			reply.Hdr.Rrtype = dns.TypeOPT
			reply.SetUDPSize(ourUDPSize)
			if opt.Do() {
				reply.SetDo()
			}
			resp.Extra = append(resp.Extra, reply)
		}
		if h.signer != nil && req.IsEdns0() != nil && req.IsEdns0().Do() {
			resp = h.signer.Sign(req, resp)
		}
	}

	// RFC 8484 §4.1: the HTTP mapping has no need for DNS message IDs.
	resp.Id = 0

	packed, err := resp.Pack()
	if err != nil {
		log.Printf("doh pack: %v", err)
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", dohContentType)
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", h.cfg.TTL))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(packed)
}

// EnsureTLSCert generates a self-signed cert/key at the given paths if they
// don't exist. Returns nil if both files are already present.
func EnsureTLSCert(certPath, keyPath string) error {
	if _, err := os.Stat(certPath); err == nil {
		if _, err2 := os.Stat(keyPath); err2 == nil {
			return nil
		}
	}
	for _, dir := range []string{filepath.Dir(certPath), filepath.Dir(keyPath)} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create tls dir %s: %w", dir, err)
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return fmt.Errorf("generate serial: %w", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "contractdb"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", certPath, err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", keyPath, err)
	}
	return nil
}

// ServeDoH runs an HTTPS DoH server until ctx is done.
func ServeDoH(ctx context.Context, addr, certFile, keyFile string, h *Handler) error {
	if err := EnsureTLSCert(certFile, keyFile); err != nil {
		return fmt.Errorf("ensure tls cert: %w", err)
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           NewDoHHandler(h),
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServeTLS(certFile, keyFile) }()

	log.Printf("contractdb %s serving DoH on https://%s/dns-query", Version, addr)

	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("doh server exited: %w", err)
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return nil
	}
}
