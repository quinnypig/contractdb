package main

// Minimal online DNSSEC signing: DNSKEY at the apex, RRSIGs over every RRset
// in a response, and NSEC authenticated denial via the online-signer
// wraparound trick (NSEC owner == next domain, proving the name doesn't exist
// without leaking which names do).

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	dnskeyFlagsCSK = 257 // SEP|ZONE: combined signing key
	defaultTTL     = uint32(300)
	inceptionSkew  = time.Hour
	signatureLife  = 7 * 24 * time.Hour
)

// OnlineSigner signs responses on the fly with an ECDSA P-256 CSK.
type OnlineSigner struct {
	zone string
	key  *dns.DNSKEY
	priv *ecdsa.PrivateKey
}

// NewOnlineSigner creates (or loads) the zone's combined signing key.
// keyDir=="" keeps everything in memory; otherwise the private key persists
// as PEM "EC PRIVATE KEY" at <keyDir>/<zone-sanitized>.key mode 0600 and is
// reused across restarts so KeyTag stays stable.
func NewOnlineSigner(zone string, keyDir string) (*OnlineSigner, error) {
	s := &OnlineSigner{zone: dns.Fqdn(strings.ToLower(zone))}
	if keyDir != "" {
		path := filepath.Join(keyDir, sanitizeZone(zone)+".key")
		if data, err := os.ReadFile(path); err == nil {
			if err := s.loadPEM(data); err != nil {
				return nil, err
			}
			return s, nil
		} else if !os.IsNotExist(err) {
			return nil, err
		}
		if err := s.generate(); err != nil {
			return nil, err
		}
		if err := s.savePEM(path); err != nil {
			return nil, err
		}
		return s, nil
	}
	if err := s.generate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *OnlineSigner) generate() error {
	k := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: s.zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET},
		Flags:     dnskeyFlagsCSK,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	priv, err := k.Generate(256)
	if err != nil {
		return err
	}
	ecdsaPriv, ok := priv.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("dnssec: generated unexpected private key type %T", priv)
	}
	s.key = k
	s.priv = ecdsaPriv
	return nil
}

func (s *OnlineSigner) loadPEM(data []byte) error {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return fmt.Errorf("dnssec: %s: not an EC PRIVATE KEY PEM block", s.zone)
	}
	priv, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	if priv.Curve != elliptic.P256() {
		return fmt.Errorf("dnssec: %s: private key is not ECDSA P-256", s.zone)
	}
	s.priv = priv
	s.key = &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: s.zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET},
		Flags:     dnskeyFlagsCSK,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	// PublicKey.Bytes returns SEC1 uncompressed form: 0x04 || X || Y.
	// DNSKEY stores the fixed-width X || Y portion.
	publicBytes, err := priv.PublicKey.Bytes()
	if err != nil {
		return fmt.Errorf("dnssec: %s: encode P-256 public key: %w", s.zone, err)
	}
	if len(publicBytes) != 65 || publicBytes[0] != 4 {
		return fmt.Errorf("dnssec: %s: unexpected P-256 public key encoding", s.zone)
	}
	s.key.PublicKey = base64.StdEncoding.EncodeToString(publicBytes[1:])
	return nil
}

func (s *OnlineSigner) savePEM(path string) error {
	der, err := x509.MarshalECPrivateKey(s.priv)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	return os.WriteFile(path, data, 0o600)
}

func sanitizeZone(zone string) string {
	zone = strings.TrimSuffix(strings.ToLower(zone), ".")
	var b strings.Builder
	for _, r := range zone {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	return b.String()
}

// DNSKEY exposes the apex DNSKEY record (public part only).
func (s *OnlineSigner) DNSKEY() *dns.DNSKEY { return s.key }

// Sign adds DNSSEC records to resp when the request carried the DO bit.
//
// AuthenticatedData is deliberately NOT set: an authoritative server does not
// validate its own answers — AD is a validator-side assertion about recursion,
// and setting it here would be lying by bit flag.
func (s *OnlineSigner) Sign(req *dns.Msg, resp *dns.Msg) *dns.Msg {
	opt := req.IsEdns0()
	if opt == nil || !opt.Do() {
		return resp
	}
	// Idempotent: a second Sign pass must not stack duplicate RRSIGs.
	for _, rr := range append(append([]dns.RR{}, resp.Answer...), resp.Ns...) {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			return resp
		}
	}

	ttl := responseTTL(resp)

	qname := ""
	if len(req.Question) > 0 {
		qname = strings.ToLower(req.Question[0].Name)
	}

	switch {
	case resp.Rcode == dns.RcodeNameError:
		resp.Ns = append(resp.Ns, s.apexNSEC(ttl))
	case resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 0 && len(req.Question) > 0:
		resp.Ns = append(resp.Ns, s.nodataNSEC(req.Question[0].Name, ttl))
	}

	if qname == s.zone && len(req.Question) > 0 {
		k := *s.key
		k.Hdr.Ttl = ttl
		resp.Answer = append(resp.Answer, &k)
	}

	now := time.Now()
	resp.Answer = s.signSection(resp.Answer, now, ttl)
	resp.Ns = s.signSection(resp.Ns, now, ttl)
	return resp
}

// signSection groups RRs into RRsets by (name,type), skips housekeeping types,
// and appends one RRSIG per RRset to the end of the section.
func (s *OnlineSigner) signSection(rrs []dns.RR, now time.Time, ttl uint32) []dns.RR {
	type rrsetKey struct {
		name string
		typ  uint16
	}
	var order []rrsetKey
	groups := map[rrsetKey][]dns.RR{}
	for _, rr := range rrs {
		h := rr.Header()
		switch h.Rrtype {
		case dns.TypeOPT, dns.TypeTSIG, dns.TypeRRSIG:
			continue
		}
		k := rrsetKey{name: strings.ToLower(h.Name), typ: h.Rrtype}
		if _, seen := groups[k]; !seen {
			order = append(order, k)
		}
		groups[k] = append(groups[k], rr)
	}
	for _, k := range order {
		rrset := groups[k]
		sig := &dns.RRSIG{
			TypeCovered: k.typ,
			Algorithm:   dns.ECDSAP256SHA256,
			KeyTag:      s.key.KeyTag(),
			SignerName:  s.zone,
			Inception:   uint32(now.Add(-inceptionSkew).Unix()),
			Expiration:  uint32(now.Add(signatureLife).Unix()),
			OrigTtl:     rrset[0].Header().Ttl,
		}
		if sig.OrigTtl == 0 {
			sig.OrigTtl = ttl
		}
		if err := sig.Sign(crypto.Signer(s.priv), rrset); err != nil {
			continue
		}
		sig.Hdr.Ttl = sig.OrigTtl
		rrs = append(rrs, sig)
	}
	return rrs
}

func (s *OnlineSigner) apexNSEC(ttl uint32) *dns.NSEC {
	return &dns.NSEC{
		Hdr:        dns.RR_Header{Name: s.zone, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: ttl},
		NextDomain: s.zone, // wraparound: apex covers itself, nothing exists below
		// Bitmap must be in ascending type-number order (RFC 4034 §3.1.3).
		TypeBitMap: []uint16{
			dns.TypeNS,
			dns.TypeSOA,
			dns.TypeTXT,
			dns.TypeRRSIG,
			dns.TypeNSEC,
			dns.TypeDNSKEY,
		},
	}
}

func (s *OnlineSigner) nodataNSEC(qname string, ttl uint32) *dns.NSEC {
	return &dns.NSEC{
		Hdr:        dns.RR_Header{Name: qname, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: ttl},
		NextDomain: s.zone,
		TypeBitMap: []uint16{
			dns.TypeTXT,
			dns.TypeRRSIG,
			dns.TypeNSEC,
		},
	}
}

// responseTTL derives cfg.TTL from the SOA already present in the response
// (the handler stamps it with cfg.TTL), falling back to a sane default.
func responseTTL(resp *dns.Msg) uint32 {
	for _, rr := range resp.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			if soa.Minttl > 0 {
				return soa.Minttl
			}
			return soa.Hdr.Ttl
		}
	}
	return defaultTTL
}
