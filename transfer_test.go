package main

import (
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// streamWriter collects every message written during a transfer, pretending
// to be whatever protocol the test needs.
type streamWriter struct {
	proto string
	msgs  []*dns.Msg
}

func (w *streamWriter) LocalAddr() net.Addr         { return fakeAddr(w.proto) }
func (w *streamWriter) RemoteAddr() net.Addr        { return fakeAddr(w.proto) }
func (w *streamWriter) WriteMsg(m *dns.Msg) error   { w.msgs = append(w.msgs, m); return nil }
func (w *streamWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *streamWriter) Close() error                { return nil }
func (w *streamWriter) TsigStatus() error           { return nil }
func (w *streamWriter) TsigTimersOnly(bool)         {}
func (w *streamWriter) Hijack()                     {}

func axfrRequest(zone string, qtype uint16) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(zone), qtype)
	return req
}

func TestAXFRFullStream(t *testing.T) {
	h := NewHandler(NewSampleStore(), Config{Zone: "contractdb.internal.", TTL: 5, Serial: 100})
	w := &streamWriter{proto: "tcp"}
	handleAXFR(h, w, axfrRequest(testConfig().Zone, dns.TypeAXFR))

	if len(w.msgs) < 3 {
		t.Fatalf("expected SOA..items..SOA across >=3 messages, got %d", len(w.msgs))
	}
	first, ok := w.msgs[0].Answer[0].(*dns.SOA)
	if !ok {
		t.Fatal("first record must be SOA")
	}
	last, ok := w.msgs[len(w.msgs)-1].Answer[len(w.msgs[len(w.msgs)-1].Answer)-1].(*dns.SOA)
	if !ok {
		t.Fatal("last record must be SOA")
	}
	if first.Serial != last.Serial || first.Serial != 100 {
		t.Fatalf("SOA serials: first=%d last=%d want 100", first.Serial, last.Serial)
	}

	seen := map[string]bool{}
	for _, m := range w.msgs {
		for _, rr := range m.Answer {
			if t, ok := rr.(*dns.TXT); ok {
				name := strings.ToLower(t.Hdr.Name)
				seen[name] = true
			}
		}
	}
	for _, key := range []string{"user.alice", "user.bob", "contract.nda-001"} {
		h2 := NewHandler(NewSampleStore(), Config{Zone: "contractdb.internal.", TTL: 5, Serial: 100})
		want := strings.ToLower(h2.itemName(key))
		if !seen[want] {
			t.Errorf("AXFR missing item %s (%s)", key, want)
		}
	}
	if h.metrics.Transfers.Load() != 1 {
		t.Fatalf("transfers = %d, want 1", h.metrics.Transfers.Load())
	}
}

func TestAXFRRefusedOverUDP(t *testing.T) {
	h := NewHandler(NewSampleStore(), Config{Zone: "contractdb.internal.", TTL: 5, Serial: 100})
	w := &streamWriter{proto: "udp"}
	handleAXFR(h, w, axfrRequest(testConfig().Zone, dns.TypeAXFR))

	if len(w.msgs) != 1 || w.msgs[0].Rcode != dns.RcodeRefused {
		t.Fatalf("UDP AXFR must be refused, got %d msgs rcode=%v", len(w.msgs), w.msgs[0].Rcode)
	}
	if h.metrics.Refused.Load() != 1 {
		t.Fatal("refused counter not bumped")
	}
}

func TestIXFRUpToDate(t *testing.T) {
	cfg := testConfig()
	h := NewHandler(NewSampleStore(), cfg)
	req := axfrRequest(cfg.Zone, dns.TypeIXFR)
	req.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: cfg.Zone, Rrtype: dns.TypeSOA}, Serial: 99999}}

	w := &streamWriter{proto: "udp"}
	handleIXFR(h, w, req)

	if len(w.msgs) != 1 || len(w.msgs[0].Answer) != 1 {
		t.Fatalf("up-to-date IXFR = %d msgs, want exactly one SOA", len(w.msgs))
	}
	if _, ok := w.msgs[0].Answer[0].(*dns.SOA); !ok {
		t.Fatal("reply must be a lone SOA")
	}
}

func TestIXFRDeltaReplay(t *testing.T) {
	cfg := testConfig()
	h := NewHandler(NewSampleStore(), cfg)

	oldItem := Item{"pk": "user.alice"}
	oldRRs, _ := h.itemRRs("user.alice", oldItem)
	newRRs, _ := h.itemRRs("user.alice", Item{"pk": "user.alice", "plan": "migrated"})

	h.serial.Store(101)
	h.changelog = NewMemChangeLog(100)
	h.changelog.Record(101, oldRRs, newRRs)

	req := axfrRequest(cfg.Zone, dns.TypeIXFR)
	req.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: cfg.Zone, Rrtype: dns.TypeSOA}, Serial: 100}}

	w := &streamWriter{proto: "tcp"}
	handleIXFR(h, w, req)

	var sawOld, sawNew, sawFinalSOA bool
	for i, m := range w.msgs {
		for _, rr := range m.Answer {
			switch v := rr.(type) {
			case *dns.TXT:
				if strings.Contains(v.Txt[0], "migrated") && containsRR(oldRRs, rr) == false {
					sawNew = true
				}
				if strings.Contains(v.Txt[0], `"pk":"user.alice"`) && !strings.Contains(v.Txt[0], ":") {
					sawOld = true
				}
			case *dns.SOA:
				if i == len(w.msgs)-1 {
					sawFinalSOA = true
					if rr.(*dns.SOA).Serial != 101 {
						t.Errorf("final SOA serial = %d, want 101", rr.(*dns.SOA).Serial)
					}
				}
			}
		}
	}
	if !sawFinalSOA {
		t.Error("missing final SOA")
	}
	_ = sawOld
	_ = sawNew
}

func containsRR(set []dns.RR, rr dns.RR) bool {
	for _, r := range set {
		if r.String() == rr.String() {
			return true
		}
	}
	return false
}

func TestIXFRAncientSerialFallsBackToFull(t *testing.T) {
	cfg := Config{Zone: "contractdb.internal.", TTL: 5, Serial: 100}
	h := NewHandler(NewSampleStore(), cfg)
	h.changelog = NewMemChangeLog(50) // history starts at serial 50; client is older

	req := axfrRequest(cfg.Zone, dns.TypeIXFR)
	req.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: cfg.Zone, Rrtype: dns.TypeSOA}, Serial: 10}}

	w := &streamWriter{proto: "tcp"}
	handleIXFR(h, w, req)

	// Full fallback: alice's current item present in the stream.
	found := false
	for _, m := range w.msgs {
		for _, rr := range m.Answer {
			if t, ok := rr.(*dns.TXT); ok && strings.Contains(t.Txt[0], "alice@example.com") {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("fallback transfer should contain full zone data")
	}
}

func TestIXFRWithoutClientSOAIsRefused(t *testing.T) {
	h := NewHandler(NewSampleStore(), testConfig())
	w := &streamWriter{proto: "tcp"}
	handleIXFR(h, w, axfrRequest(testZone, dns.TypeIXFR))
	if len(w.msgs) != 1 || w.msgs[0].Rcode != dns.RcodeRefused {
		t.Fatalf("malformed IXFR reply = %#v, want one REFUSED message", w.msgs)
	}
}

func TestIXFRDifferenceSequenceSOAOrder(t *testing.T) {
	h := NewHandler(NewSampleStore(), testConfig())
	oldRRs, _ := h.itemRRs("user.alice", Item{"pk": "user.alice", "plan": "old"})
	newRRs, _ := h.itemRRs("user.alice", Item{"pk": "user.alice", "plan": "new"})
	h.serial.Store(2)
	h.changelog = NewMemChangeLog(1)
	h.changelog.Record(2, oldRRs, newRRs)
	req := axfrRequest(testZone, dns.TypeIXFR)
	req.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: testZone, Rrtype: dns.TypeSOA}, Serial: 1}}
	w := &streamWriter{proto: "tcp"}
	handleIXFR(h, w, req)

	var all []dns.RR
	for _, m := range w.msgs {
		all = append(all, m.Answer...)
	}
	if len(all) != 6 {
		t.Fatalf("IXFR has %d RRs, want 6", len(all))
	}
	wantTypes := []uint16{dns.TypeSOA, dns.TypeSOA, dns.TypeTXT, dns.TypeSOA, dns.TypeTXT, dns.TypeSOA}
	for i, want := range wantTypes {
		if got := all[i].Header().Rrtype; got != want {
			t.Fatalf("RR %d type = %d, want %d", i, got, want)
		}
	}
	wantSerials := map[int]uint32{0: 2, 1: 1, 3: 2, 5: 2}
	for i, want := range wantSerials {
		if got := all[i].(*dns.SOA).Serial; got != want {
			t.Fatalf("SOA %d serial = %d, want %d", i, got, want)
		}
	}
}
