package main

import (
	"context"
	"log"
	"strings"

	"github.com/miekg/dns"
)

const (
	axfrMaxRRsPerMsg = 500
	axfrMaxBytes     = 1 << 16 // 64KB batches; well under MaxMsgSize
)

func init() {
	registerQueryType(dns.TypeAXFR, handleAXFR)
	registerQueryType(dns.TypeIXFR, handleIXFR)
}

// handleAXFR serves RFC 5936 full zone transfers: the whole table as one
// stream. TCP only — UDP AXFR is a category error and gets REFUSED.
func handleAXFR(h *Handler, w dns.ResponseWriter, req *dns.Msg) bool {
	if !strings.EqualFold(req.Question[0].Name, h.cfg.Zone) {
		refuse(h, w, req)
		return true
	}
	if !streamZone(h, w, req, nil) {
		return true // stream already handled the failure path
	}
	return true
}

// handleIXFR serves RFC 1995 incremental transfers: replay journaled deltas,
// fall back to a full transfer when history doesn't reach back far enough.
func handleIXFR(h *Handler, w dns.ResponseWriter, req *dns.Msg) bool {
	if len(req.Ns) != 1 {
		refuse(h, w, req)
		return true
	}
	clientSOA, ok := req.Ns[0].(*dns.SOA)
	if !ok || !strings.EqualFold(req.Question[0].Name, h.cfg.Zone) {
		refuse(h, w, req)
		return true
	}

	current := h.serial.Load()
	switch {
	case clientSOA.Serial >= current:
		// Zone is up to date: single-SOA reply, small enough for UDP.
		m := new(dns.Msg)
		m.SetReply(req)
		m.Authoritative = true
		m.Answer = []dns.RR{h.soa()}
		h.setupReplyTsig(req, m)
		w.WriteMsg(m)

	default:
		// RFC 1995 permits a UDP IXFR only when the complete response fits in
		// one packet. A lone current SOA tells the client to retry over TCP.
		if w.RemoteAddr().Network() != "tcp" {
			m := new(dns.Msg)
			m.SetReply(req)
			m.Authoritative = true
			m.Answer = []dns.RR{h.soa()}
			h.setupReplyTsig(req, m)
			_ = w.WriteMsg(m)
			return true
		}
		var deltas []Delta
		if h.changelog != nil {
			deltas, _ = h.changelog.Deltas(clientSOA.Serial)
		}
		streamZone(h, w, req, deltas)
	}
	return true
}

// refuse sends a REFUSED reply with metrics.
func refuse(h *Handler, w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeRefused)
	if h.tsigValid(w, req) {
		h.setupReplyTsig(req, m)
	}
	w.WriteMsg(m)
	h.metrics.Refused.Add(1)
}

// udpCap returns this connection's response size ceiling.
func (h *Handler) udpCap(req *dns.Msg) int {
	max := udpDefaultSize
	if opt := req.IsEdns0(); opt != nil {
		if size := int(opt.UDPSize()); size > max {
			max = size
		}
	}
	return max
}

// streamZone writes SOA → RRsets (or delta replay) → SOA. When deltas is nil
// it performs a full transfer by enumerating the store. Returns false if the
// transfer could not even start (unsupported store / transport error).
func streamZone(h *Handler, w dns.ResponseWriter, req *dns.Msg, deltas []Delta) bool {
	isTCP := w.RemoteAddr().Network() == "tcp"

	if req.Question[0].Qtype == dns.TypeAXFR && !isTCP {
		refuse(h, w, req) // AXFR over UDP is refused outright
		return false
	}

	var reader Reader
	if deltas == nil {
		var ok bool
		reader, ok = h.store.(Reader)
		if !ok {
			log.Printf("transfer: store does not support enumeration")
			refuse(h, w, req)
			return false
		}
	}

	capBytes := axfrMaxBytes
	if !isTCP {
		capBytes = min(h.udpCap(req)-overheadPerMsg, axfrMaxBytes)
	}

	send := func(rrs []dns.RR) bool {
		if len(rrs) == 0 {
			return true
		}
		m := new(dns.Msg)
		m.SetReply(req)
		m.Authoritative = true
		m.Answer = rrs
		h.setupReplyTsig(req, m)
		if err := w.WriteMsg(m); err != nil {
			log.Printf("transfer write: %v", err)
			return false
		}
		return true
	}

	// Opening SOA.
	if !send([]dns.RR{h.soa()}) {
		return false
	}

	if deltas != nil {
		for _, d := range deltas {
			// RFC 1995 difference sequence: old SOA, deletions, new SOA,
			// additions. Sequences are sent oldest first.
			rrs := []dns.RR{soaWithSerial(h, d.Serial-1)}
			rrs = append(rrs, d.Removed...)
			rrs = append(rrs, soaWithSerial(h, d.Serial))
			rrs = append(rrs, d.Added...)
			for _, b := range batchRRs(rrs, capBytes) {
				if !send(b) {
					return false
				}
			}
		}
	} else {
		var buf []dns.RR
		bufLen := overheadPerMsg
		flush := func() bool { return send(buf) }
		abort := false
		err := reader.List(context.Background(), func(page []Entry) error {
			for _, e := range page {
				rrs, err := h.itemRRs(e.Key, e.Item)
				if err != nil {
					continue
				}
				for _, rr := range rrs {
					l := dns.Len(rr)
					if len(buf) > 0 && (len(buf)+1 > axfrMaxRRsPerMsg || bufLen+l > capBytes) {
						if !flush() {
							abort = true
							return context.Canceled
						}
						buf = nil
						bufLen = overheadPerMsg
					}
					buf = append(buf, rr)
					bufLen += l
				}
			}
			return nil
		})
		if abort || (err != nil && err != context.Canceled) {
			if err != nil && err != context.Canceled {
				log.Printf("transfer list: %v", err)
			}
			return false
		}
		if !flush() {
			return false
		}
	}

	// Closing SOA.
	if !send([]dns.RR{h.soa()}) {
		return false
	}
	h.metrics.Transfers.Add(1)
	return true
}

func soaWithSerial(h *Handler, serial uint32) *dns.SOA {
	s := h.soa()
	s.Serial = serial
	return s
}

// batchRRs splits rrs into messages under the byte cap.
func batchRRs(rrs []dns.RR, capBytes int) [][]dns.RR {
	var out [][]dns.RR
	var cur []dns.RR
	curLen := overheadPerMsg
	for _, rr := range rrs {
		l := dns.Len(rr)
		if len(cur) > 0 && (len(cur)+1 > axfrMaxRRsPerMsg || curLen+l > capBytes) {
			out = append(out, cur)
			cur = nil
			curLen = overheadPerMsg
		}
		cur = append(cur, rr)
		curLen += l
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

const overheadPerMsg = 512 // header + question + SOA slack
