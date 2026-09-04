package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func dohTestHandler() *Handler {
	return NewHandler(NewSampleStore(), Config{
		Zone:   "contractdb.internal.",
		TTL:    5,
		Serial: 100,
	})
}

// dohQuery builds a wire-format QUERY for name/qtype and runs it through the
// DoH handler via POST, returning the decoded response.
func dohPostQuery(t *testing.T, srv *httptest.Server, req *dns.Msg, contentType string) (*http.Response, *dns.Msg) {
	t.Helper()
	packed, err := req.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	httpReq, err := http.NewRequest(http.MethodPost, srv.URL+"/dns-query", bytes.NewReader(packed))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if contentType != "" {
		httpReq.Header.Set("Content-Type", contentType)
	}
	resp, err := srv.Client().Do(httpReq)
	if err != nil {
		t.Fatalf("POST %s: %v", srv.URL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if contentType != dohContentType {
		return resp, nil
	}
	m := new(dns.Msg)
	if err := m.Unpack(body); err != nil {
		t.Fatalf("unpack response: %v", err)
	}
	return resp, m
}

func TestDoHPostRoundTrip(t *testing.T) {
	srv := httptest.NewServer(NewDoHHandler(dohTestHandler()))
	defer srv.Close()

	req := new(dns.Msg)
	req.SetQuestion("user.alice.contractdb.internal.", dns.TypeTXT)
	resp, m := dohPostQuery(t, srv, req, dohContentType)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != dohContentType {
		t.Errorf("content-type = %q, want %q", ct, dohContentType)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "max-age=5" {
		t.Errorf("cache-control = %q, want max-age=5", cc)
	}
	if !m.Authoritative {
		t.Error("response not authoritative")
	}
	var email string
	for _, rr := range m.Answer {
		txt, ok := rr.(*dns.TXT)
		if !ok {
			continue
		}
		email += strings.Join(txt.Txt, "")
	}
	if !strings.Contains(email, "alice@example.com") {
		t.Errorf("TXT answer missing alice's email, got: %.200s", email)
	}
}

func TestDoHGetRoundTrip(t *testing.T) {
	srv := httptest.NewServer(NewDoHHandler(dohTestHandler()))
	defer srv.Close()

	req := new(dns.Msg)
	req.SetQuestion("user.alice.contractdb.internal.", dns.TypeTXT)
	packed, err := req.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	dnsParam := base64.RawURLEncoding.EncodeToString(packed)

	getResp, err := srv.Client().Get(srv.URL + "/dns-query?dns=" + url.QueryEscape(dnsParam))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer getResp.Body.Close()
	body, err := io.ReadAll(getResp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", getResp.StatusCode)
	}
	m := new(dns.Msg)
	if err := m.Unpack(body); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	var blob string
	for _, rr := range m.Answer {
		if txt, ok := rr.(*dns.TXT); ok {
			blob += strings.Join(txt.Txt, "")
		}
	}
	if !strings.Contains(blob, "alice@example.com") {
		t.Errorf("GET answer missing alice's email, got: %.200s", blob)
	}
}

func TestDoHNXDomain(t *testing.T) {
	srv := httptest.NewServer(NewDoHHandler(dohTestHandler()))
	defer srv.Close()

	req := new(dns.Msg)
	req.SetQuestion("user.missing.contractdb.internal.", dns.TypeTXT)
	resp, m := dohPostQuery(t, srv, req, dohContentType)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (DNS errors ride in-band)", resp.StatusCode)
	}
	if m.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %d (%s), want NXDOMAIN(3)", m.Rcode, dns.RcodeToString[m.Rcode])
	}
}

func TestDoHMismatchedIdZeroed(t *testing.T) {
	srv := httptest.NewServer(NewDoHHandler(dohTestHandler()))
	defer srv.Close()

	req := new(dns.Msg)
	req.Id = 0xbeef
	req.SetQuestion("user.alice.contractdb.internal.", dns.TypeTXT)
	_, m := dohPostQuery(t, srv, req, dohContentType)
	if m.Id != 0 {
		t.Errorf("response Id = %d, want 0 per RFC 8484 §4.1", m.Id)
	}
}

func TestDoHMalformedBody(t *testing.T) {
	srv := httptest.NewServer(NewDoHHandler(dohTestHandler()))
	defer srv.Close()

	resp, err := srv.Client().Post(srv.URL+"/dns-query", dohContentType, strings.NewReader("\x00\x01garbage"))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for malformed body", resp.StatusCode)
	}
}

func TestDoHWrongContentType(t *testing.T) {
	srv := httptest.NewServer(NewDoHHandler(dohTestHandler()))
	defer srv.Close()

	req := new(dns.Msg)
	req.SetQuestion("user.alice.contractdb.internal.", dns.TypeTXT)
	resp, _ := dohPostQuery(t, srv, req, "text/plain")

	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want 415 for wrong content type", resp.StatusCode)
	}
}

func TestDoHNonQueryOpcodeRefused(t *testing.T) {
	srv := httptest.NewServer(NewDoHHandler(dohTestHandler()))
	defer srv.Close()

	req := new(dns.Msg)
	req.Opcode = dns.OpcodeStatus
	req.SetQuestion("contractdb.internal.", dns.TypeTXT)
	resp, m := dohPostQuery(t, srv, req, dohContentType)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 for REFUSED-in-band", resp.StatusCode)
	}
	if m.Rcode != dns.RcodeRefused {
		t.Fatalf("rcode = %d, want REFUSED", m.Rcode)
	}
}

func TestDoHEmptyQuestionReturnsFormErr(t *testing.T) {
	srv := httptest.NewServer(NewDoHHandler(dohTestHandler()))
	defer srv.Close()

	req := new(dns.Msg)
	resp, m := dohPostQuery(t, srv, req, dohContentType)
	if resp.StatusCode != http.StatusOK || m.Rcode != dns.RcodeFormatError {
		t.Fatalf("status=%d rcode=%d, want HTTP 200 / FORMERR", resp.StatusCode, m.Rcode)
	}
}

func TestEnsureTLSCert(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	if err := EnsureTLSCert(certPath, keyPath); err != nil {
		t.Fatalf("first call: %v", err)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	keyStat, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if keyStat.Mode().Perm() != 0o600 {
		t.Errorf("key mode = %v, want 0600", keyStat.Mode().Perm())
	}
	certStat, err := os.Stat(certPath)
	if err != nil {
		t.Fatalf("stat cert: %v", err)
	}
	if certStat.Mode().Perm() != 0o644 {
		t.Errorf("cert mode = %v, want 0644", certStat.Mode().Perm())
	}

	// Idempotent second call.
	if err := EnsureTLSCert(certPath, keyPath); err != nil {
		t.Fatalf("second call: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("no PEM block in cert")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	if err := cert.VerifyHostname("localhost"); err != nil {
		t.Errorf("cert does not cover localhost: %v", err)
	}
	if cert.PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("key algorithm = %v, want ECDSA", cert.PublicKeyAlgorithm)
	}
}

func TestServeDoHShutdown(t *testing.T) {
	dir := t.TempDir()
	h := dohTestHandler()
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		errc <- ServeDoH(ctx, "127.0.0.1:0", filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem"), h)
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("ServeDoH: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ServeDoH did not shut down")
	}
}
