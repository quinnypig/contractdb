package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const testZone = "contractdb.internal."

func updateHandler(t *testing.T) (*Handler, *sampleStore) {
	t.Helper()
	store, ok := NewSampleStore().(*sampleStore)
	if !ok {
		t.Fatalf("NewSampleStore does not implement Writer")
	}
	h := NewHandler(store, Config{Zone: testZone, TTL: 5, Serial: 100})
	return h, store
}

func newUpdate(zone string) *dns.Msg {
	m := new(dns.Msg)
	m.SetUpdate(zone)
	return m
}

func txtUpdateRR(name string, chunks ...string) *dns.TXT {
	return &dns.TXT{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET},
		Txt: chunks,
	}
}

func anyRR(name string, class uint16) *dns.ANY {
	return &dns.ANY{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeANY, Class: class}}
}

func TestUpdateInsert(t *testing.T) {
	h, store := updateHandler(t)
	m := newUpdate(testZone)
	payload := `{"pk":"user.dave","plan":"free-tier"}`
	m.Insert([]dns.RR{txtUpdateRR("user.dave."+testZone, payload)})

	if rcode := processUpdate(context.Background(), h, m); rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d (%s), want NOERROR", rcode, dns.RcodeToString[rcode])
	}
	item, err := store.Get(context.Background(), "user.dave")
	if err != nil || item == nil {
		t.Fatalf("inserted item missing: %v %v", item, err)
	}
	if item["plan"] != "free-tier" {
		t.Fatalf("plan = %v, want free-tier", item["plan"])
	}
	if got := h.metrics.Updates.Load(); got != 1 {
		t.Fatalf("updates metric = %d, want 1", got)
	}
	if s := h.serial.Load(); s != 101 {
		t.Fatalf("serial = %d, want 101 after one commitWrite", s)
	}
}

func TestUpdateInsertMultiChunkTXT(t *testing.T) {
	h, store := updateHandler(t)
	m := newUpdate(testZone)
	// Two IN TXT RRs at the same owner name concatenate into one payload.
	m.Insert([]dns.RR{
		txtUpdateRR("user.eve."+testZone, `{"pk":"user.eve","`),
		txtUpdateRR("user.eve."+testZone, `plan":"pro"}`),
	})
	if rcode := processUpdate(context.Background(), h, m); rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d (%s), want NOERROR", rcode, dns.RcodeToString[rcode])
	}
	item, err := store.Get(context.Background(), "user.eve")
	if err != nil || item == nil {
		t.Fatalf("inserted item missing: %v %v", item, err)
	}
	if item["plan"] != "pro" {
		t.Fatalf("plan = %v, want pro (chunks must concatenate)", item["plan"])
	}
}

func TestUpdateDelete(t *testing.T) {
	h, store := updateHandler(t)
	m := newUpdate(testZone)
	// ClassNONE + TypeANY removes the whole item (RFC 2136 2.5.3/2.6.2).
	m.Ns = append(m.Ns, anyRR("user.alice."+testZone, dns.ClassNONE))

	if rcode := processUpdate(context.Background(), h, m); rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d (%s), want NOERROR", rcode, dns.RcodeToString[rcode])
	}
	item, _ := store.Get(context.Background(), "user.alice")
	if item != nil {
		t.Fatalf("item still present after delete: %v", item)
	}
}

func TestUpdatePrereqNameInUseViolated(t *testing.T) {
	h, _ := updateHandler(t)
	m := newUpdate(testZone)
	// NameUsed on a name that does NOT exist -> YXDOMAIN.
	m.Answer = append(m.Answer, anyRR("ghost."+testZone, dns.ClassANY))

	if rcode := processUpdate(context.Background(), h, m); rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %d (%s), want NXDOMAIN", rcode, dns.RcodeToString[rcode])
	}
}

func TestUpdatePrereqNameNotInUseViolated(t *testing.T) {
	h, _ := updateHandler(t)
	m := newUpdate(testZone)
	// NameNotUsed on a name that DOES exist -> NXDOMAIN.
	m.Answer = append(m.Answer, anyRR("user.alice."+testZone, dns.ClassNONE))

	if rcode := processUpdate(context.Background(), h, m); rcode != dns.RcodeYXDomain {
		t.Fatalf("rcode = %d (%s), want YXDOMAIN", rcode, dns.RcodeToString[rcode])
	}
}

func TestUpdatePrereqSatisfiedAllowsNoop(t *testing.T) {
	h, _ := updateHandler(t)
	m := newUpdate(testZone)
	// user.bob exists; prereq holds; empty update section is a legal no-op.
	m.Answer = append(m.Answer, anyRR("user.bob."+testZone, dns.ClassANY))

	if rcode := processUpdate(context.Background(), h, m); rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d (%s), want NOERROR", rcode, dns.RcodeToString[rcode])
	}
}

func TestUpdateInvalidJSONRejected(t *testing.T) {
	h, store := updateHandler(t)
	m := newUpdate(testZone)
	m.Insert([]dns.RR{txtUpdateRR("user.frank."+testZone, `{"pk": not json`)})

	if rcode := processUpdate(context.Background(), h, m); rcode != dns.RcodeFormatError {
		t.Fatalf("rcode = %d (%s), want FORMERR", rcode, dns.RcodeToString[rcode])
	}
	item, _ := store.Get(context.Background(), "user.frank")
	if item != nil {
		t.Fatal("invalid JSON must not be written")
	}
}

func TestUpdateNonTXTInsertRefused(t *testing.T) {
	h, store := updateHandler(t)
	m := newUpdate(testZone)
	m.Insert([]dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "user.grace." + testZone, Rrtype: dns.TypeA, Class: dns.ClassINET},
		A:   []byte{127, 0, 0, 1},
	}})

	if rcode := processUpdate(context.Background(), h, m); rcode != dns.RcodeRefused {
		t.Fatalf("rcode = %d (%s), want REFUSED", rcode, dns.RcodeToString[rcode])
	}
	item, _ := store.Get(context.Background(), "user.grace")
	if item != nil {
		t.Fatal("refused insert must not be written")
	}
	_ = store
}

func TestUpdateWrongZoneFormErr(t *testing.T) {
	h, _ := updateHandler(t)
	m := newUpdate("other.example.")
	m.Insert([]dns.RR{txtUpdateRR("x.other.example.", `{}`)})
	if rcode := processUpdate(context.Background(), h, m); rcode != dns.RcodeFormatError {
		t.Fatalf("rcode = %d (%s), want FORMERR", rcode, dns.RcodeToString[rcode])
	}
}

func TestUpdatePrereqCheckedBeforeMutation(t *testing.T) {
	h, store := updateHandler(t)
	m := newUpdate(testZone)
	// Violated prereq AND a delete in the same packet: nothing may mutate.
	m.Answer = append(m.Answer, anyRR("ghost."+testZone, dns.ClassANY))
	m.Ns = append(m.Ns, anyRR("user.alice."+testZone, dns.ClassNONE))
	if rcode := processUpdate(context.Background(), h, m); rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %d (%s), want NXDOMAIN", rcode, dns.RcodeToString[rcode])
	}
	item, _ := store.Get(context.Background(), "user.alice")
	if item == nil {
		t.Fatal("store mutated despite failed prerequisite")
	}
}

func TestWireEncodedUpdateJSONIsDecoded(t *testing.T) {
	h, store := updateHandler(t)
	m := newUpdate(testZone)
	// dns.TXT fields use RFC 1035 presentation escaping. Packing removes one
	// escape layer; unpacking adds it again before processUpdate decodes it.
	m.Insert([]dns.RR{txtUpdateRR("user.wire."+testZone, `\{"pk\":\"user.wire\",\"path\":\"C:\\\\tmp\"}`)})

	packed, err := m.Pack()
	if err != nil {
		t.Fatalf("pack update: %v", err)
	}
	var wireMsg dns.Msg
	if err := wireMsg.Unpack(packed); err != nil {
		t.Fatalf("unpack update: %v", err)
	}
	if rcode := processUpdate(context.Background(), h, &wireMsg); rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[rcode])
	}
	item, err := store.Get(context.Background(), "user.wire")
	if err != nil || item == nil {
		t.Fatalf("wire item missing: %v %v", item, err)
	}
	if item["path"] != `C:\tmp` {
		t.Fatalf("path = %q, want C:\\tmp", item["path"])
	}
}

func TestUnsignedUpdateIsRefused(t *testing.T) {
	h, store := updateHandler(t)
	provider, err := newHMACProvider(map[string]string{"test-key": "c2VjcmV0"})
	if err != nil {
		t.Fatal(err)
	}
	h.tsigProvider = provider
	m := newUpdate(testZone)
	m.Insert([]dns.RR{txtUpdateRR("user.unsigned."+testZone, `{"pk":"user.unsigned"}`)})
	w := &fakeWriter{proto: "udp"}

	handleUpdate(h, w, m)
	if w.wrote == nil || w.wrote.Rcode != dns.RcodeRefused {
		t.Fatalf("unsigned update reply = %v, want REFUSED", w.wrote)
	}
	item, _ := store.Get(context.Background(), "user.unsigned")
	if item != nil {
		t.Fatal("unsigned update mutated the store")
	}
}

func TestStandardRemoveNameDeletesItem(t *testing.T) {
	h, store := updateHandler(t)
	m := newUpdate(testZone)
	m.RemoveName([]dns.RR{txtUpdateRR("user.alice."+testZone, "")})

	if rcode := processUpdate(context.Background(), h, m); rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[rcode])
	}
	item, _ := store.Get(context.Background(), "user.alice")
	if item != nil {
		t.Fatal("RemoveName did not delete item")
	}
}

func TestMultiOwnerUpdateIsRefusedAtomically(t *testing.T) {
	h, store := updateHandler(t)
	m := newUpdate(testZone)
	m.Insert([]dns.RR{
		txtUpdateRR("user.one."+testZone, `{"pk":"user.one"}`),
		txtUpdateRR("user.two."+testZone, `{"pk":"user.two"}`),
	})
	if rcode := processUpdate(context.Background(), h, m); rcode != dns.RcodeRefused {
		t.Fatalf("rcode = %s, want REFUSED", dns.RcodeToString[rcode])
	}
	for _, key := range []string{"user.one", "user.two"} {
		if item, _ := store.Get(context.Background(), key); item != nil {
			t.Fatalf("multi-owner update partially wrote %q", key)
		}
	}
}

func TestSignedWireQueryAndUpdate(t *testing.T) {
	h, store := updateHandler(t)
	provider, err := newHMACProvider(map[string]string{"test-key.": "c2VjcmV0"})
	if err != nil {
		t.Fatal(err)
	}
	h.tsigProvider = provider
	h.authRequired = true

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: packetConn, Handler: h, TsigProvider: provider, MsgAcceptFunc: acceptFunc}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = srv.Shutdown()
		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("DNS server: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("DNS server did not stop")
		}
	})

	client := &dns.Client{TsigProvider: provider, Timeout: 2 * time.Second}
	read := new(dns.Msg)
	read.SetQuestion("user.alice."+testZone, dns.TypeTXT)
	read.SetTsig("test-key.", dns.HmacSHA256, 300, time.Now().Unix())
	resp, _, err := client.Exchange(read, packetConn.LocalAddr().String())
	if err != nil {
		t.Fatalf("signed read: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
		t.Fatalf("signed read rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
	}

	update := newUpdate(testZone)
	update.Insert([]dns.RR{txtUpdateRR("user.signed."+testZone, `{"pk":"user.signed","plan":"pro"}`)})
	update.SetTsig("test-key.", dns.HmacSHA256, 300, time.Now().Unix())
	resp, _, err = client.Exchange(update, packetConn.LocalAddr().String())
	if err != nil {
		t.Fatalf("signed update: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("signed update rcode=%s", dns.RcodeToString[resp.Rcode])
	}
	item, err := store.Get(context.Background(), "user.signed")
	if err != nil || item == nil || item["plan"] != "pro" {
		t.Fatalf("signed update item=%v err=%v", item, err)
	}
}
