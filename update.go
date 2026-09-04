package main

import (
	"context"
	"encoding/json"
	"log"
	"sort"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// Section mapping note: RFC 2136 orders sections ZONE, PREREQUISITE, UPDATE,
// ADDITIONAL. miekg/dns carries those in Question, Answer, Ns, Extra
// respectively (see its own update.go helpers), so prerequisites arrive in
// req.Answer and update RRs in req.Ns.

func init() {
	registerOpcode(dns.OpcodeUpdate, handleUpdate)
}

// handleUpdate is the transport-facing entry point. UDP updates are legal per
// RFC 2136 §4.2 when they fit a single packet (nsupdate sends them that way);
// TSIG verification is the actual security boundary, not the transport.
// Updates are always TSIG-authenticated regardless of auth.mode.
func handleUpdate(h *Handler, w dns.ResponseWriter, req *dns.Msg) {
	if !h.tsigValid(w, req) {
		h.metrics.Refused.Add(1)
		resp := new(dns.Msg)
		resp.SetRcode(req, dns.RcodeRefused)
		if err := w.WriteMsg(resp); err != nil {
			log.Printf("update refused reply: %v", err)
		}
		return
	}

	rcode := processUpdate(context.Background(), h, req)
	resp := new(dns.Msg)
	resp.SetRcode(req, rcode)
	resp.Authoritative = true
	if rcode == dns.RcodeSuccess {
		resp.Answer = append(resp.Answer, h.soa())
	}
	h.setupReplyTsig(req, resp)
	if err := w.WriteMsg(resp); err != nil {
		log.Printf("update reply: %v", err)
	}
}

// processUpdate applies an RFC 2136 update to the store; returns a DNS rcode.
func processUpdate(ctx context.Context, h *Handler, req *dns.Msg) int {
	writer, ok := h.store.(Writer)
	if !ok {
		return dns.RcodeRefused
	}

	// ZONE section: exactly one SOA-shaped question naming our zone.
	if len(req.Question) != 1 {
		return dns.RcodeFormatError
	}
	q := req.Question[0]
	if !strings.EqualFold(q.Name, h.cfg.Zone) || q.Qtype != dns.TypeSOA || q.Qclass != dns.ClassINET {
		return dns.RcodeFormatError
	}

	// PREREQUISITE section: evaluate everything before touching the store.
	if rcode := evalPrerequisites(ctx, h, req.Answer); rcode != dns.RcodeSuccess {
		return rcode
	}

	type insertion struct {
		pk   string
		item Item
	}
	var (
		deletes []string
		inserts []insertion
		order   []string
		txBlobs = map[string][]string{} // owner name -> TXT character data chunks, in arrival order
	)

	// UPDATE section, first pass: validate and collect. Deletions apply
	// before insertions regardless of packet order (documented deviation,
	// matches the nsupdate mental model).
	for _, rr := range req.Ns {
		hdr := rr.Header()
		name := strings.ToLower(hdr.Name)

		switch {
		case (hdr.Class == dns.ClassANY && (hdr.Rrtype == dns.TypeANY || hdr.Rrtype == dns.TypeTXT)) ||
			(hdr.Class == dns.ClassNONE && (hdr.Rrtype == dns.TypeANY || hdr.Rrtype == dns.TypeTXT)):
			key, ok := parseKey(h.cfg.Zone, name)
			if !ok {
				return dns.RcodeNotZone
			}
			deletes = append(deletes, key)

		case hdr.Class == dns.ClassINET && hdr.Rrtype == dns.TypeTXT:
			txt, ok := rr.(*dns.TXT)
			if !ok {
				return dns.RcodeRefused
			}
			if !strings.HasSuffix(name, "."+h.cfg.Zone) {
				return dns.RcodeNotZone
			}
			if _, seen := txBlobs[name]; !seen {
				order = append(order, name)
			}
			txBlobs[name] = append(txBlobs[name], txt.Txt...)

		default:
			return dns.RcodeRefused
		}
	}

	inserts = make([]insertion, 0, len(order))
	for _, name := range order {
		key, ok := parseKey(h.cfg.Zone, name)
		if !ok {
			return dns.RcodeRefused
		}
		payload, err := decodeTXTStrings(txBlobs[name])
		if err != nil {
			return dns.RcodeFormatError
		}
		if !json.Valid([]byte(payload)) {
			return dns.RcodeFormatError
		}
		var item Item
		if err := json.Unmarshal([]byte(payload), &item); err != nil {
			return dns.RcodeFormatError
		}
		inserts = append(inserts, insertion{pk: key, item: item})
	}

	// DynamoDB PutItem/DeleteItem are atomic for one item, but this Store
	// interface cannot make a multi-item RFC 2136 transaction atomic. Reject
	// multi-owner packets instead of risking a partially applied update.
	affectedSet := make(map[string]struct{}, len(deletes)+len(inserts))
	for _, key := range deletes {
		affectedSet[key] = struct{}{}
	}
	for _, ins := range inserts {
		affectedSet[ins.pk] = struct{}{}
	}
	if len(affectedSet) > 1 {
		return dns.RcodeRefused
	}
	if len(affectedSet) == 0 {
		return dns.RcodeSuccess
	}

	// Snapshot old state before any mutation so the journal delta is exact.
	affected := make([]string, 0, 1)
	for key := range affectedSet {
		affected = append(affected, key)
	}
	sort.Strings(affected)
	old := make(map[string]Item, len(affected))
	for _, key := range affected {
		item, err := h.store.Get(ctx, key)
		if err != nil {
			log.Printf("update pre-read %q: %v", key, err)
			return dns.RcodeServerFailure
		}
		old[key] = item
	}

	// A put supersedes a delete for the same owner and remains one atomic
	// storage operation. Without a put, delete the single affected owner.
	if len(inserts) > 0 {
		ins := inserts[0]
		if err := writer.Put(ctx, ins.pk, ins.item); err != nil {
			log.Printf("update put %q: %v", ins.pk, err)
			return dns.RcodeServerFailure
		}
	} else if err := writer.Delete(ctx, affected[0]); err != nil {
		log.Printf("update delete %q: %v", affected[0], err)
		return dns.RcodeServerFailure
	}

	// Success: bump serial, journal the delta, fan out NOTIFYs.
	h.metrics.Updates.Add(1)
	var removed, added []dns.RR
	for _, key := range affected {
		if item := old[key]; item != nil {
			rrs, err := h.itemRRs(key, item)
			if err != nil {
				log.Printf("render old item %q: %v", key, err)
				continue
			}
			removed = append(removed, rrs...)
		}
	}
	for _, ins := range inserts {
		rrs, err := h.itemRRs(ins.pk, ins.item)
		if err != nil {
			log.Printf("render new item %q: %v", ins.pk, err)
			continue
		}
		added = append(added, rrs...)
	}
	h.commitWrite(removed, added)

	if len(h.notifiees) > 0 {
		go NotifyAll(h.notifiees, h.cfg.Zone)
	}
	return dns.RcodeSuccess
}

// evalPrerequisites checks every prerequisite RR; returns NOERROR when all
// hold, otherwise the RFC 2136 rcode for the first failure.
func evalPrerequisites(ctx context.Context, h *Handler, prereqs []dns.RR) int {
	for _, rr := range prereqs {
		hdr := rr.Header()
		name := strings.ToLower(hdr.Name)
		key, inZone := parseKey(h.cfg.Zone, name)
		if !inZone || hdr.Ttl != 0 {
			if !inZone {
				return dns.RcodeNotZone
			}
			return dns.RcodeFormatError
		}

		var item Item
		got, err := h.store.Get(ctx, key)
		if err != nil {
			log.Printf("prerequisite get %q: %v", key, err)
			return dns.RcodeServerFailure
		}
		item = got

		switch {
		case hdr.Class == dns.ClassANY && hdr.Rrtype == dns.TypeANY:
			// Name exists (value independent).
			if item == nil {
				return dns.RcodeNameError
			}
		case hdr.Class == dns.ClassNONE && hdr.Rrtype == dns.TypeANY:
			// Name does not exist.
			if item != nil {
				return dns.RcodeYXDomain
			}
		case hdr.Class == dns.ClassANY && hdr.Rrtype == dns.TypeTXT:
			// TXT RRset exists (value independent).
			if item == nil {
				return dns.RcodeNXRrset
			}
		case hdr.Class == dns.ClassNONE && hdr.Rrtype == dns.TypeTXT:
			// TXT RRset does not exist.
			if item != nil {
				return dns.RcodeYXRrset
			}
		case hdr.Class == dns.ClassINET && hdr.Rrtype == dns.TypeTXT:
			// TXT RRset exists and has this value. ContractDB represents an
			// item as one TXT RR containing one or more character strings.
			txt, ok := rr.(*dns.TXT)
			if !ok || item == nil {
				return dns.RcodeNXRrset
			}
			want, err := decodeTXTStrings(txt.Txt)
			if err != nil {
				return dns.RcodeFormatError
			}
			blob, err := json.Marshal(item)
			if err != nil {
				return dns.RcodeServerFailure
			}
			if string(blob) != want {
				return dns.RcodeNXRrset
			}
		default:
			return dns.RcodeFormatError
		}
	}
	return dns.RcodeSuccess
}

// decodeTXTStrings converts miekg/dns's escaped presentation form back to
// the octets carried on the wire. Unpack escapes quotes, backslashes, and
// non-printable bytes so TXT data can round-trip through RR.String().
func decodeTXTStrings(chunks []string) (string, error) {
	var out strings.Builder
	for _, chunk := range chunks {
		for i := 0; i < len(chunk); i++ {
			if chunk[i] != '\\' {
				out.WriteByte(chunk[i])
				continue
			}
			if i+1 == len(chunk) {
				return "", strconv.ErrSyntax
			}
			if i+3 < len(chunk) && chunk[i+1] >= '0' && chunk[i+1] <= '9' &&
				chunk[i+2] >= '0' && chunk[i+2] <= '9' && chunk[i+3] >= '0' && chunk[i+3] <= '9' {
				n, err := strconv.Atoi(chunk[i+1 : i+4])
				if err != nil || n > 255 {
					return "", strconv.ErrSyntax
				}
				out.WriteByte(byte(n))
				i += 3
				continue
			}
			i++
			out.WriteByte(chunk[i])
		}
	}
	return out.String(), nil
}
