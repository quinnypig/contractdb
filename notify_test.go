package main

import (
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func notifyServer(t *testing.T, rcode int) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	serve := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		if req.Opcode != dns.OpcodeNotify {
			t.Errorf("opcode = %d, want NOTIFY(%d)", req.Opcode, dns.OpcodeNotify)
		}
		if len(req.Question) != 1 || req.Question[0].Qtype != dns.TypeSOA || req.Question[0].Name != testZone {
			t.Errorf("question = %v, want SOA %s", req.Question, testZone)
		}
		if req.RecursionDesired {
			t.Error("NOTIFY must not set RD")
		}
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Rcode = rcode
		w.WriteMsg(resp)
	})
	srv := &dns.Server{PacketConn: pc, Handler: serve}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return pc.LocalAddr().String()
}

func TestSendNotifyAcked(t *testing.T) {
	addr := notifyServer(t, dns.RcodeSuccess)
	if err := SendNotify(addr, testZone); err != nil {
		t.Fatalf("SendNotify: %v", err)
	}
}

func TestSendNotifyNotAuthIsError(t *testing.T) {
	addr := notifyServer(t, dns.RcodeNotAuth)
	err := SendNotify(addr, testZone)
	if err == nil {
		t.Fatal("expected error for NOTAUTH reply")
	}
	if !strings.Contains(err.Error(), "NOTAUTH") {
		t.Errorf("error %q should mention the rcode", err)
	}
}

func TestSendNotifyUnreachable(t *testing.T) {
	// Port 1 on loopback: nothing listens; exchange must fail fast.
	if err := SendNotify("127.0.0.1:1", testZone); err == nil {
		t.Fatal("expected error for unreachable address")
	}
}

func TestNotifyAllWaitsAndToleratesFailures(t *testing.T) {
	addr1 := notifyServer(t, dns.RcodeSuccess)
	addr2 := notifyServer(t, dns.RcodeSuccess)
	// A dead peer in the mix must not break the others or hang.
	NotifyAll([]string{addr1, addr2, "127.0.0.1:1"}, testZone)
}
