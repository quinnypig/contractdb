package main

import (
	"bytes"
	"testing"

	"github.com/miekg/dns"
)

func mustSigner(t *testing.T, keyDir string) *OnlineSigner {
	t.Helper()
	s, err := NewOnlineSigner("contractdb.internal.", keyDir)
	if err != nil {
		t.Fatalf("NewOnlineSigner: %v", err)
	}
	return s
}

func doQuery(name string, qtype uint16, do bool) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion(name, qtype)
	if do {
		req.SetEdns0(1232, true)
	}
	return req
}

func TestKeyPersistence(t *testing.T) {
	dir := t.TempDir()

	s1 := mustSigner(t, dir)
	tag1 := s1.DNSKEY().KeyTag()
	pub1 := s1.DNSKEY().PublicKey

	// Reload from disk: same key material, same tag.
	s2, err := NewOnlineSigner("contractdb.internal.", dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if s2.DNSKEY().KeyTag() != tag1 {
		t.Errorf("key tag changed across reload: %d != %d", s2.DNSKEY().KeyTag(), tag1)
	}
	if s2.DNSKEY().PublicKey != pub1 {
		t.Error("public key bytes changed across reload")
	}
	pubBytes1, err := s1.priv.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	pubBytes2, err := s2.priv.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pubBytes1, pubBytes2) {
		t.Error("EC point mismatch across reload")
	}

	// A second signer on the same dir coexists (loads the same key).
	s3 := mustSigner(t, dir)
	if s3.DNSKEY().KeyTag() != tag1 {
		t.Errorf("third signer tag %d != %d", s3.DNSKEY().KeyTag(), tag1)
	}
}

func signWithHandler(t *testing.T, req *dns.Msg) (*dns.Msg, *OnlineSigner) {
	t.Helper()
	handler := NewHandler(NewSampleStore(), Config{Zone: "contractdb.internal.", TTL: 5, Serial: 100})
	resp := handler.buildResponse(req)
	signer := mustSigner(t, "")
	return signer.Sign(req, resp), signer
}

func findRRSIG(rrs []dns.RR, covered uint16, name string) *dns.RRSIG {
	for _, rr := range rrs {
		sig, ok := rr.(*dns.RRSIG)
		if ok && sig.TypeCovered == covered && sig.Hdr.Name == name {
			return sig
		}
	}
	return nil
}

func collectRRset(rrs []dns.RR, name string, typ uint16) []dns.RR {
	var out []dns.RR
	for _, rr := range rrs {
		h := rr.Header()
		if h.Name == name && h.Rrtype == typ {
			out = append(out, rr)
		}
	}
	return out
}

func TestPositiveSigningVerifies(t *testing.T) {
	req := doQuery("user.alice.contractdb.internal.", dns.TypeTXT, true)
	resp, signer := signWithHandler(t, req)

	name := "user.alice.contractdb.internal."
	txtRRs := collectRRset(resp.Answer, name, dns.TypeTXT)
	if len(txtRRs) == 0 {
		t.Fatal("no TXT records in answer")
	}
	sig := findRRSIG(resp.Answer, dns.TypeTXT, name)
	if sig == nil {
		t.Fatal("no RRSIG over TXT RRset")
	}
	if err := sig.Verify(signer.DNSKEY(), txtRRs); err != nil {
		t.Fatalf("RRSIG does not verify: %v", err)
	}
	if sig.SignerName != "contractdb.internal." || sig.Algorithm != dns.ECDSAP256SHA256 {
		t.Errorf("bad sig fields: signer=%q alg=%d", sig.SignerName, sig.Algorithm)
	}
	if sig.OrigTtl != 5 {
		t.Errorf("OrigTtl = %d, want cfg.TTL 5", sig.OrigTtl)
	}
}

func TestNXDomainHasWraparoundNSEC(t *testing.T) {
	req := doQuery("missing.contractdb.internal.", dns.TypeTXT, true)
	resp, _ := signWithHandler(t, req)

	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %d, want NXDOMAIN", resp.Rcode)
	}
	nsecRRs := collectRRset(resp.Ns, "contractdb.internal.", dns.TypeNSEC)
	if len(nsecRRs) != 1 {
		t.Fatalf("got %d apex NSEC in authority, want 1", len(nsecRRs))
	}
	nsec := nsecRRs[0].(*dns.NSEC)
	if nsec.NextDomain != "contractdb.internal." {
		t.Errorf("NextDomain = %q, want wraparound to apex", nsec.NextDomain)
	}
	hasSOA, hasDNSKEY := false, false
	for _, typ := range nsec.TypeBitMap {
		switch typ {
		case dns.TypeSOA:
			hasSOA = true
		case dns.TypeDNSKEY:
			hasDNSKEY = true
		}
	}
	if !hasSOA || !hasDNSKEY {
		t.Errorf("NSEC bitmap missing SOA/DNSKEY: %v", nsec.TypeBitMap)
	}
	if nsec.Hdr.Ttl != 5 {
		t.Errorf("NSEC TTL = %d, want 5", nsec.Hdr.Ttl)
	}
	if findRRSIG(resp.Ns, dns.TypeNSEC, "contractdb.internal.") == nil {
		t.Error("apex NSEC not signed")
	}
}

func TestNoDataHasQnameNSEC(t *testing.T) {
	req := doQuery("user.alice.contractdb.internal.", dns.TypeA, true)
	resp, _ := signWithHandler(t, req)

	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR", resp.Rcode)
	}
	if len(resp.Answer) != 0 {
		t.Fatalf("expected empty answer for NODATA, got %d RRs", len(resp.Answer))
	}
	qname := "user.alice.contractdb.internal."
	nsecRRs := collectRRset(resp.Ns, qname, dns.TypeNSEC)
	if len(nsecRRs) != 1 {
		t.Fatalf("got %d qname NSEC in authority, want 1", len(nsecRRs))
	}
	nsec := nsecRRs[0].(*dns.NSEC)
	if nsec.NextDomain != "contractdb.internal." {
		t.Errorf("NextDomain = %q, want apex", nsec.NextDomain)
	}
	want := map[uint16]bool{dns.TypeTXT: true, dns.TypeRRSIG: true, dns.TypeNSEC: true}
	for _, typ := range nsec.TypeBitMap {
		if !want[typ] {
			t.Errorf("unexpected type %d in NODATA bitmap", typ)
		}
	}
}

func TestSignIdempotent(t *testing.T) {
	req := doQuery("user.alice.contractdb.internal.", dns.TypeTXT, true)
	handler := NewHandler(NewSampleStore(), Config{Zone: "contractdb.internal.", TTL: 5, Serial: 100})
	resp := handler.buildResponse(req)
	signer := mustSigner(t, "")

	resp = signer.Sign(req, resp)
	first := countType(append(append([]dns.RR{}, resp.Answer...), resp.Ns...), dns.TypeRRSIG)
	resp = signer.Sign(req, resp)
	second := countType(append(append([]dns.RR{}, resp.Answer...), resp.Ns...), dns.TypeRRSIG)

	if first == 0 {
		t.Fatal("first Sign produced no RRSIGs")
	}
	if first != second {
		t.Fatalf("double Sign grew RRSIG count %d -> %d", first, second)
	}
}

func countType(rrs []dns.RR, typ uint16) int {
	n := 0
	for _, rr := range rrs {
		if rr.Header().Rrtype == typ {
			n++
		}
	}
	return n
}

func TestDOBitOffUntouched(t *testing.T) {
	req := doQuery("user.alice.contractdb.internal.", dns.TypeTXT, false)
	handler := NewHandler(NewSampleStore(), Config{Zone: "contractdb.internal.", TTL: 5, Serial: 100})
	before := handler.buildResponse(req)
	resp := mustSigner(t, "").Sign(req, before)

	if resp != before {
		t.Error("Sign returned a different message with DO off")
	}
	if countType(before.Answer, dns.TypeRRSIG)+countType(before.Ns, dns.TypeRRSIG) != 0 {
		t.Error("RRSIGs added without DO bit")
	}
	if countType(before.Ns, dns.TypeNSEC) != 0 {
		t.Error("NSEC added without DO bit")
	}
}
