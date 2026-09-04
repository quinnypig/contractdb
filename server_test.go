package main

import (
	"context"
	"encoding/base32"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func base32EncodeLabel(s string) string {
	return "k-" + strings.ToLower(base32.StdEncoding.EncodeToString([]byte(s)))
}

type mapStore map[string]Item

func (m mapStore) Get(_ context.Context, pk string) (Item, error) {
	if v, ok := m[pk]; ok {
		return v, nil
	}
	return nil, nil
}

func testConfig() Config {
	return Config{
		Zone:        "contractdb.internal.",
		Table:       "contracts",
		PKAttr:      "pk",
		TTL:         5,
		AdvertiseIP: "127.0.0.1",
		Serial:      1,
	}
}

func TestParseKey(t *testing.T) {
	zone := "contractdb.internal."
	tests := []struct {
		qname string
		want  string
		ok    bool
	}{
		{"user.alice." + zone, "user.alice", true},
		{"alice." + zone, "alice", true},
		{"ALICE." + zone, "ALICE", true},
		{"a.b.c.d." + zone, "a.b.c.d", true},
		{zone, "", false},
		{"other.example.", "", false},
	}
	for _, tc := range tests {
		got, ok := parseKey(zone, tc.qname)
		if got != tc.want || ok != tc.ok {
			t.Errorf("parseKey(%q) = %q,%v want %q,%v", tc.qname, got, ok, tc.want, tc.ok)
		}
	}

	// base32 label round-trips arbitrary bytes
	raw := "CaseSensitive Key With Spaces & Symbols!@#"
	enc := base32EncodeLabel(raw)
	got, ok := parseKey(zone, enc+"."+zone)
	if !ok || got != raw {
		t.Errorf("base32 round-trip failed: got %q ok=%v", got, ok)
	}
}

type fakeAddr string

func (a fakeAddr) Network() string { return string(a) }
func (a fakeAddr) String() string  { return string(a) + "-addr" }

type fakeWriter struct {
	proto      string
	wrote      *dns.Msg
	tsigStatus error
}

func (w *fakeWriter) LocalAddr() net.Addr         { return fakeAddr(w.proto) }
func (w *fakeWriter) RemoteAddr() net.Addr        { return fakeAddr(w.proto) }
func (w *fakeWriter) WriteMsg(m *dns.Msg) error   { w.wrote = m; return nil }
func (w *fakeWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *fakeWriter) Close() error                { return nil }
func (w *fakeWriter) TsigStatus() error           { return w.tsigStatus }
func (w *fakeWriter) TsigTimersOnly(bool)         {}
func (w *fakeWriter) Hijack()                     {}

func query(name string, qtype uint16, proto string, ednsSize int) (*fakeWriter, *dns.Msg) {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), qtype)
	req.RecursionDesired = true
	if ednsSize > 0 {
		req.SetEdns0(uint16(ednsSize), false)
	}
	h := &Handler{
		store: mapStore{"user.alice": {"pk": "user.alice", "plan": "enterprise", "notes": bigString(2000)}},
		cfg:   testConfig(),
	}
	w := &fakeWriter{proto: proto}
	h.ServeDNS(w, req)
	return w, req
}

const bigLen = 2000

func bigString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'x'
	}
	return string(b)
}

func TestNotFoundIsNXDomain(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("missing.contractdb.internal.", dns.TypeTXT)
	h := &Handler{store: mapStore{}, cfg: testConfig()}
	w := &fakeWriter{proto: "udp"}
	h.ServeDNS(w, req)
	if w.wrote.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %d, want NXDOMAIN", w.wrote.Rcode)
	}
	if len(w.wrote.Ns) == 0 {
		t.Fatal("expected SOA in authority section")
	}
}

func TestUDPTruncationJoke(t *testing.T) {
	// Plain UDP: response exceeds 512 bytes -> TC set, only what fits is sent.
	w, _ := query("user.alice.contractdb.internal.", dns.TypeTXT, "udp", 0)
	if !w.wrote.Truncated {
		t.Fatal("expected TC bit set on plain UDP response")
	}
	total := 0
	for _, rr := range w.wrote.Answer {
		total += len(rr.(*dns.TXT).Txt[0])
	}
	if total >= bigLen {
		t.Fatalf("expected partial payload under truncation, got %d bytes", total)
	}

	// Client advertises EDNS0 with room to spare -> full answer over UDP.
	w, _ = query("user.alice.contractdb.internal.", dns.TypeTXT, "udp", 4096)
	if w.wrote.Truncated {
		t.Fatal("did not expect TC with EDNS0 4096 advertised")
	}
	if len(w.wrote.Answer) == 0 {
		t.Fatal("expected answers over EDNS0 UDP")
	}
	total = 0
	for _, rr := range w.wrote.Answer {
		for _, chunk := range rr.(*dns.TXT).Txt {
			total += len(chunk)
		}
	}
	if total < bigLen {
		t.Fatalf("expected full %d-byte payload, got %d bytes across %d records", bigLen, total, len(w.wrote.Answer))
	}
}

func TestTCPGetsFullResponse(t *testing.T) {
	w, _ := query("user.alice.contractdb.internal.", dns.TypeTXT, "tcp", 0)
	if w.wrote.Truncated {
		t.Fatal("did not expect TC bit over TCP")
	}
	if len(w.wrote.Answer) == 0 {
		t.Fatal("expected full answers over TCP")
	}
}

func TestChunkBytes(t *testing.T) {
	got := chunkBytes(make([]byte, 600), 255)
	if len(got) != 3 || len(got[0]) != 255 || len(got[1]) != 255 || len(got[2]) != 90 {
		t.Fatalf("chunkBytes(600) = %v chunks", len(got))
	}
}

func TestLargeItemUsesOneMultiStringTXTRecord(t *testing.T) {
	h := NewHandler(mapStore{"big": {"pk": "big", "notes": bigString(1000)}}, testConfig())
	rrs, err := h.itemRRs("big", Item{"pk": "big", "notes": bigString(1000)})
	if err != nil {
		t.Fatal(err)
	}
	if len(rrs) != 1 {
		t.Fatalf("got %d TXT records, want one RR with multiple character strings", len(rrs))
	}
	txt := rrs[0].(*dns.TXT)
	if len(txt.Txt) < 2 {
		t.Fatalf("got %d character strings, want multiple chunks", len(txt.Txt))
	}
	for _, chunk := range txt.Txt {
		if len(chunk) > maxTxtChunk {
			t.Fatalf("TXT chunk is %d bytes, want <= %d", len(chunk), maxTxtChunk)
		}
	}
}

func TestAuthRequiredRejectsUnsignedAndBadTSIG(t *testing.T) {
	provider, err := newHMACProvider(map[string]string{"test-key": "c2VjcmV0"})
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(NewSampleStore(), testConfig())
	h.authRequired = true
	h.tsigProvider = provider

	unsigned := new(dns.Msg)
	unsigned.SetQuestion("user.alice."+testZone, dns.TypeTXT)
	w := &fakeWriter{proto: "udp"}
	h.ServeDNS(w, unsigned)
	if w.wrote == nil || w.wrote.Rcode != dns.RcodeRefused {
		t.Fatalf("unsigned read rcode = %v, want REFUSED", w.wrote)
	}

	signed := new(dns.Msg)
	signed.SetQuestion("user.alice."+testZone, dns.TypeTXT)
	signed.SetTsig("test-key.", dns.HmacSHA256, 300, 1)
	w = &fakeWriter{proto: "udp", tsigStatus: errors.New("bad signature")}
	h.ServeDNS(w, signed)
	if w.wrote == nil || w.wrote.Rcode != dns.RcodeRefused {
		t.Fatalf("bad TSIG read rcode = %v, want REFUSED", w.wrote)
	}
}
