package main

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const Version = "0.2.0"

const (
	// Plain UDP DNS responses cap at 512 bytes unless the client advertises
	// more via EDNS0. Past that, the truncate bit does the talking.
	udpDefaultSize = 512
	maxTxtChunk    = 255
	statusName     = "_contractdb"
	// What we advertise as our UDP payload size in EDNS0 replies.
	ourUDPSize = 1232
)

// Config carries everything the handler needs to pretend to be a name server.
type Config struct {
	Zone        string // fqdn, e.g. "contractdb.internal."
	Table       string
	PKAttr      string
	TTL         uint32
	AdvertiseIP string
	Serial      uint32
	GSIs        map[string]string // DNS-facing index name -> GSI partition key attribute
}

type Handler struct {
	store   Store
	cfg     Config
	serial  atomic.Uint32
	metrics Metrics

	// signer optionally DNSSEC-signs responses (engaged when DO bit set).
	signer Signer
	// changelog journals write deltas for IXFR; nil means no history.
	changelog ChangeLog
	// tsigProvider verifies inbound TSIG; also gates response signing.
	tsigProvider dns.TsigProvider
	// authRequired enforces TSIG on every message; writes are always enforced.
	authRequired bool
	// notifiees receive RFC 1996 NOTIFY messages after successful writes.
	notifiees []string
}

// ChangeLog records zone deltas so IXFR clients can catch up incrementally.
// Serial numbers are owned by the Handler; Record is invoked with the serial
// that becomes current once the delta is applied.
type ChangeLog interface {
	Record(serial uint32, removed, added []dns.RR)
	// Deltas returns every delta newer than since, in application order.
	// ok is false when history does not reach back that far.
	Deltas(since uint32) (deltas []Delta, ok bool)
}

// Delta is one committed write: the RRsets removed and added at a serial.
type Delta struct {
	Serial  uint32
	Removed []dns.RR
	Added   []dns.RR
}

// commitWrite bumps the zone serial and journals the delta. Returns the new
// serial. This is the only sanctioned way to make writes visible to IXFR.
func (h *Handler) commitWrite(removed, added []dns.RR) uint32 {
	s := h.serial.Add(1)
	if h.changelog != nil {
		h.changelog.Record(s, removed, added)
	}
	return s
}

// setupReplyTsig arms a response for signing: with a TsigProvider configured,
// miekg/dns signs any outbound message that carries a TSIG RR. Call on every
// reply to an authenticated request, including each message of a stream.
func (h *Handler) setupReplyTsig(req *dns.Msg, resp *dns.Msg) {
	if h.tsigProvider == nil {
		return
	}
	if t := req.IsTsig(); t != nil && resp.IsTsig() == nil {
		resp.SetTsig(t.Hdr.Name, t.Algorithm, 300, time.Now().Unix())
	}
}

func NewHandler(store Store, cfg Config) *Handler {
	h := &Handler{store: store, cfg: cfg}
	h.serial.Store(cfg.Serial)
	return h
}

// Signer adds DNSSEC signatures (RRSIG/NSEC/DNSKEY) to a response.
type Signer interface {
	Sign(req *dns.Msg, resp *dns.Msg) *dns.Msg
}

// opcodeExtensions lets modules register non-QUERY opcodes (e.g. RFC 2136
// UPDATE) without touching this file. Populated via init() in module files.
var opcodeExtensions = map[int]func(*Handler, dns.ResponseWriter, *dns.Msg){}

// registerOpcode is called from init() by extension modules.
func registerOpcode(op int, fn func(*Handler, dns.ResponseWriter, *dns.Msg)) {
	opcodeExtensions[op] = fn
}

// queryExtension handles special query types (AXFR/IXFR) that stream their own
// replies. Returns true if the query was fully handled.
type queryExtensionFunc func(*Handler, dns.ResponseWriter, *dns.Msg) bool

var queryExtensions = map[uint16]queryExtensionFunc{}

func registerQueryType(qtype uint16, fn queryExtensionFunc) {
	queryExtensions[qtype] = fn
}

// parseKey maps a QNAME under the zone back to a partition key.
//
//	user.alice.contractdb.internal -> "user.alice"   (labels rejoin with dots)
//	k-mzxw6ytboji======.contractdb.internal -> any byte sequence (base32 label)
func parseKey(zone, qname string) (string, bool) {
	if !strings.HasSuffix(strings.ToLower(qname), "."+zone) {
		return "", false
	}
	rest := qname[:len(qname)-len(zone)-1]
	if rest == "" {
		return "", false
	}
	labels := strings.Split(rest, ".")
	if strings.HasPrefix(labels[0], "k-") {
		raw := strings.ToUpper(labels[0][2:])
		if pad := len(raw) % 8; pad != 0 {
			raw += strings.Repeat("=", 8-pad)
		}
		decoded, err := base32.StdEncoding.DecodeString(raw)
		if err != nil {
			return "", false
		}
		return string(decoded), true
	}
	return rest, true
}

// itemName maps a partition key back to its owner name inside the zone.
// Keys that survive DNS label rules round-trip as dotted names; anything else
// (case-mixed, spaces, symbols, empty labels) gets the base32 k- form.
func (h *Handler) itemName(key string) string {
	if key == "" {
		return h.cfg.Zone
	}
	safe := true
	for _, part := range strings.Split(key, ".") {
		if part == "" || len(part) > 63 {
			safe = false
			break
		}
		for _, r := range part {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') ||
				part[0] == '-' || part[len(part)-1] == '-' {
				safe = false
				break
			}
		}
		if !safe {
			break
		}
	}
	if safe {
		return key + "." + h.cfg.Zone
	}
	enc := base32.StdEncoding.EncodeToString([]byte(key))
	return "k-" + strings.ToLower(enc) + "." + h.cfg.Zone
}

// itemRRs renders an item as its TXT RRset at its owner name.
func (h *Handler) itemRRs(key string, item Item) ([]dns.RR, error) {
	blob, err := json.Marshal(item)
	if err != nil {
		return nil, err
	}
	name := h.itemName(key)
	chunks := make([]string, 0, (len(blob)+maxTxtChunk-1)/maxTxtChunk)
	for _, chunk := range chunkBytes(blob, maxTxtChunk) {
		chunks = append(chunks, string(chunk))
	}
	return []dns.RR{txtRRChunks(name, h.cfg.TTL, chunks)}, nil
}

func (h *Handler) soa() *dns.SOA {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: h.cfg.Zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: h.cfg.TTL},
		Ns:      "ns1." + h.cfg.Zone,
		Mbox:    "hostmaster." + h.cfg.Zone,
		Serial:  h.serial.Load(),
		Refresh: 7200,
		Retry:   900,
		Expire:  1209600,
		Minttl:  h.cfg.TTL,
	}
}

// tsigValid reports whether the request carries a valid TSIG signature.
// When Server has a TsigProvider configured, miekg/dns verifies incoming
// signatures before ServeDNS runs; the result lands in w.TsigStatus().
func (h *Handler) tsigValid(w dns.ResponseWriter, req *dns.Msg) bool {
	return h.tsigProvider != nil && req.IsTsig() != nil && w.TsigStatus() == nil
}

// authOK enforces the read policy: open reads unless authRequired is set.
func (h *Handler) authOK(w dns.ResponseWriter, req *dns.Msg) bool {
	if !h.authRequired {
		return true
	}
	return h.tsigValid(w, req)
}

// buildResponse produces a full (untruncated) reply for the request.
func (h *Handler) buildResponse(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true

	q := req.Question[0]
	qname := strings.ToLower(q.Name)

	switch {
	case qname == h.cfg.Zone:
		switch q.Qtype {
		case dns.TypeSOA:
			m.Answer = append(m.Answer, h.soa())
		case dns.TypeNS:
			h.addNS(m)
		case dns.TypeANY:
			m.Answer = append(m.Answer, h.soa())
			h.addNS(m)
		default:
			m.Ns = append(m.Ns, h.soa())
		}
		return m

	case qname == statusName+"."+h.cfg.Zone && (q.Qtype == dns.TypeTXT || q.Qtype == dns.TypeANY):
		status, _ := json.Marshal(map[string]any{
			"service": "contractdb",
			"version": Version,
			"table":   h.cfg.Table,
			"pkAttr":  h.cfg.PKAttr,
		})
		m.Answer = append(m.Answer, txtRR(q.Name, h.cfg.TTL, string(status)))
		return m

	case qname == statusName+".health."+h.cfg.Zone && (q.Qtype == dns.TypeTXT || q.Qtype == dns.TypeANY):
		m.Answer = append(m.Answer, txtRR(q.Name, h.cfg.TTL, "UP"))
		return m

	case qname == statusName+".metrics."+h.cfg.Zone && (q.Qtype == dns.TypeTXT || q.Qtype == dns.TypeANY):
		blob, _ := json.Marshal(h.metrics.Snapshot())
		for _, chunk := range chunkBytes(blob, maxTxtChunk) {
			m.Answer = append(m.Answer, txtRR(q.Name, h.cfg.TTL, string(chunk)))
		}
		return m

	case qname == "ns1."+h.cfg.Zone && (q.Qtype == dns.TypeA || q.Qtype == dns.TypeANY):
		ip := net.ParseIP(h.cfg.AdvertiseIP)
		if ip.To4() != nil {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: h.cfg.TTL},
				A:   ip,
			})
		} else {
			m.Answer = append(m.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: h.cfg.TTL},
				AAAA: ip,
			})
		}
		return m
	}

	key, ok := parseKey(h.cfg.Zone, qname)
	if !ok || key == "" {
		return h.nxDomain(m)
	}

	// GSI lookups: <value>.<index-name>.<zone>, e.g. alice.gsi-email.<zone>.
	// The index name is the label immediately above the zone; everything
	// below it rejoins into the attribute value (k- base32 form works too).
	rest := strings.TrimSuffix(qname, "."+h.cfg.Zone)
	if labels := strings.Split(rest, "."); len(labels) >= 2 && h.cfg.GSIs[labels[len(labels)-1]] != "" {
		idx := labels[len(labels)-1]
		value := strings.Join(labels[:len(labels)-1], ".")
		if len(labels) == 2 && strings.HasPrefix(labels[0], "k-") {
			if decoded, ok2 := parseKey(h.cfg.Zone, qname); ok2 {
				value = decoded
			}
		}
		return h.gsiLookup(m, req, idx, value)
	}

	item, err := h.store.Get(context.Background(), key)
	if err != nil {
		log.Printf("store get %q: %v", key, err)
		m.SetRcode(req, dns.RcodeServerFailure)
		return m
	}
	if item == nil {
		return h.nxDomain(m)
	}
	if q.Qtype != dns.TypeTXT && q.Qtype != dns.TypeANY {
		m.Ns = append(m.Ns, h.soa()) // NODATA
		return m
	}

	rrs, err := h.itemRRs(key, item)
	if err != nil {
		log.Printf("marshal %q: %v", key, err)
		m.SetRcode(req, dns.RcodeServerFailure)
		return m
	}
	m.Answer = rrs
	return m
}

// gsiLookup answers <value>.<index-name>.<zone> queries against a secondary
// index. Falls through to SERVFAIL/NXDOMAIN like any other lookup on trouble.
func (h *Handler) gsiLookup(m *dns.Msg, req *dns.Msg, index, value string) *dns.Msg {
	reader, ok := h.store.(Reader)
	if !ok {
		log.Printf("gsi %q: store does not support index queries", index)
		m.SetRcode(req, dns.RcodeServerFailure)
		return m
	}
	entries, err := reader.QueryIndex(context.Background(), index, value)
	if err != nil {
		log.Printf("gsi %q=%q: %v", index, value, err)
		m.SetRcode(req, dns.RcodeServerFailure)
		return m
	}
	if len(entries) == 0 {
		return h.nxDomain(m)
	}
	q := req.Question[0]
	if q.Qtype != dns.TypeTXT && q.Qtype != dns.TypeANY {
		m.Ns = append(m.Ns, h.soa()) // NODATA
		return m
	}
	for _, e := range entries {
		rrs, err := h.itemRRs(e.Key, e.Item)
		if err != nil {
			continue
		}
		m.Answer = append(m.Answer, rrs...)
	}
	return m
}

func (h *Handler) addNS(m *dns.Msg) {
	m.Answer = append(m.Answer, &dns.NS{
		Hdr: dns.RR_Header{Name: h.cfg.Zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: h.cfg.TTL},
		Ns:  "ns1." + h.cfg.Zone,
	})
}

func (h *Handler) nxDomain(m *dns.Msg) *dns.Msg {
	m.Rcode = dns.RcodeNameError
	m.Ns = append(m.Ns, h.soa())
	return m
}

func txtRR(name string, ttl uint32, s string) *dns.TXT {
	return txtRRChunks(name, ttl, []string{s})
}

func txtRRChunks(name string, ttl uint32, chunks []string) *dns.TXT {
	return &dns.TXT{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
		Txt: chunks,
	}
}

func chunkBytes(b []byte, n int) [][]byte {
	var out [][]byte
	for len(b) > 0 {
		c := b
		if len(c) > n {
			c = c[:n]
		}
		out = append(out, c)
		b = b[len(c):]
	}
	return out
}

func (h *Handler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	h.metrics.Queries.Add(1)

	if len(req.Question) == 0 {
		dns.HandleFailed(w, req)
		return
	}

	// Non-QUERY opcodes (RFC 2136 UPDATE etc.) belong to their extensions.
	if req.Opcode != dns.OpcodeQuery {
		if ext, ok := opcodeExtensions[req.Opcode]; ok {
			ext(h, w, req)
			return
		}
		dns.HandleFailed(w, req)
		return
	}

	if !h.authOK(w, req) {
		h.metrics.Refused.Add(1)
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeRefused)
		if err := w.WriteMsg(m); err != nil {
			log.Printf("refused reply: %v", err)
		}
		return
	}

	qtype := req.Question[0].Qtype

	// Streaming types (AXFR/IXFR) manage their own replies entirely.
	if ext, ok := queryExtensions[qtype]; ok {
		// Transfers enumerate the table, so require TSIG even when ordinary
		// point reads are configured as open.
		if !h.tsigValid(w, req) {
			refuse(h, w, req)
			return
		}
		ext(h, w, req)
		return
	}

	resp := h.buildResponse(req)
	switch resp.Rcode {
	case dns.RcodeNameError:
		h.metrics.NXDomain.Add(1)
	case dns.RcodeServerFailure:
	default:
	}

	// The joke, enforced per protocol: plain UDP caps at 512 bytes unless the
	// client advertised a bigger buffer via EDNS0. Overflow sets the TC bit
	// and strips the payload; a well-behaved resolver retries over TCP, where
	// the full item comes through.
	max := dns.MaxMsgSize
	isUDP := w.RemoteAddr().Network() == "udp"
	if isUDP {
		max = udpDefaultSize
		if opt := req.IsEdns0(); opt != nil {
			if size := int(opt.UDPSize()); size > max {
				max = size
			}
		}
	}

	// Echo the client's EDNS0 OPT so DO-bit clients get a proper reply.
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

	// DNSSEC online signing, when enabled and the client asked (DO bit).
	if h.signer != nil && req.IsEdns0() != nil && req.IsEdns0().Do() {
		resp = h.signer.Sign(req, resp)
	}

	if resp.Len() > max {
		log.Printf("response %dB exceeds %dB (%s); setting TC", resp.Len(), max, w.RemoteAddr().Network())
		resp.Truncate(max)
		h.metrics.Truncated.Add(1)
	}

	h.setupReplyTsig(req, resp)
	if err := w.WriteMsg(resp); err != nil {
		log.Printf("write: %v", err)
	}
}

// Run starts UDP+TCP listeners. tsigProvider, when non-nil, enables TSIG
// verification of inbound requests and signing of outbound ones.
// Serve runs UDP+TCP listeners until ctx is done.
func (h *Handler) Serve(ctx context.Context, addr string) error {
	udpServer := &dns.Server{Addr: addr, Net: "udp", Handler: h, TsigProvider: h.tsigProvider, MsgAcceptFunc: acceptFunc}
	tcpServer := &dns.Server{Addr: addr, Net: "tcp", Handler: h, TsigProvider: h.tsigProvider, MsgAcceptFunc: acceptFunc}

	errc := make(chan error, 2)
	go func() { errc <- udpServer.ListenAndServe() }()
	go func() { errc <- tcpServer.ListenAndServe() }()

	log.Printf("contractdb %s serving %s on %s (udp+tcp), table=%q pk=%q",
		Version, h.cfg.Zone, addr, h.cfg.Table, h.cfg.PKAttr)

	select {
	case err := <-errc:
		udpServer.Shutdown()
		tcpServer.Shutdown()
		return fmt.Errorf("server exited: %w", err)
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = udpServer.ShutdownContext(shutdownCtx)
		_ = tcpServer.ShutdownContext(shutdownCtx)
		return nil
	}
}

// Run starts UDP+TCP listeners. tsigProvider, when non-nil, enables TSIG
// verification of inbound requests and signing of outbound ones.
func Run(ctx context.Context, addr string, store Store, cfg Config, opts ...RunOption) error {
	handler := NewHandler(store, cfg)
	for _, o := range opts {
		o(handler)
	}
	return handler.Serve(ctx, addr)
}

// RunOption configures the handler before the sockets come up.
type RunOption func(*Handler)

// acceptFunc mirrors miekg/dns's DefaultMsgAcceptFunc but admits RFC 2136
// UPDATE messages, which the default rejects outright ("don't allow dynamic
// updates"), and NOTIFY, which we answer ourselves. Update sections legitimately
// carry many prerequisite/update RRs, so the RR-count limits only apply to queries.
func acceptFunc(dh dns.Header) dns.MsgAcceptAction {
	const qrBit = 1 << 15
	if dh.Bits&qrBit != 0 {
		return dns.MsgIgnore // never treat responses as queries
	}

	opcode := int(dh.Bits>>11) & 0xF
	switch opcode {
	case dns.OpcodeQuery:
	case dns.OpcodeNotify:
	case dns.OpcodeUpdate:
		if dh.Qdcount != 1 || dh.Arcount > 2 {
			return dns.MsgReject // one zone + TSIG/OPT at most
		}
		return dns.MsgAccept
	default:
		return dns.MsgRejectNotImplemented
	}

	if dh.Qdcount != 1 {
		return dns.MsgReject
	}
	if dh.Nscount > 1 {
		return dns.MsgReject // IXFR may carry exactly one SOA
	}
	if dh.Ancount > 1 && opcode == dns.OpcodeNotify {
		return dns.MsgReject
	}
	if dh.Arcount > 2 {
		return dns.MsgReject
	}
	return dns.MsgAccept
}

func WithSigner(s Signer) RunOption { return func(h *Handler) { h.signer = s } }

func WithAuthRequired() RunOption { return func(h *Handler) { h.authRequired = true } }

func WithTsigProvider(p dns.TsigProvider) RunOption {
	return func(h *Handler) { h.tsigProvider = p }
}

func WithNotifiees(addrs []string) RunOption {
	return func(h *Handler) { h.notifiees = addrs }
}

// Metrics counts the interesting things, served as JSON in a TXT record.
type Metrics struct {
	Queries   atomic.Int64
	NXDomain  atomic.Int64
	Truncated atomic.Int64
	Updates   atomic.Int64
	Transfers atomic.Int64
	Refused   atomic.Int64
}

func (m *Metrics) Snapshot() map[string]int64 {
	return map[string]int64{
		"queries":             m.Queries.Load(),
		"nxdomain":            m.NXDomain.Load(),
		"truncated_responses": m.Truncated.Load(),
		"updates":             m.Updates.Load(),
		"zone_transfers":      m.Transfers.Load(),
		"refused":             m.Refused.Load(),
	}
}
