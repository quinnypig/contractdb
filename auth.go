package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"os"
	"strings"

	"github.com/miekg/dns"
)

// hmacProvider verifies inbound and signs outbound TSIG records against a
// fixed set of named secrets ("keyname -> base64 secret"). This is real
// authentication: RFC 8945 HMAC over the wire format, replay-protected by
// the TSIG timestamp and fudge window (the library enforces the clock skew
// after our signature check passes).
type hmacProvider struct {
	keys map[string][]byte // canonical fqdn key name -> raw secret bytes
}

func newHMACProvider(keys map[string]string) (*hmacProvider, error) {
	p := &hmacProvider{keys: make(map[string][]byte, len(keys))}
	for name, secret := range keys {
		raw, err := base64.StdEncoding.DecodeString(secret)
		if err != nil {
			return nil, fmt.Errorf("tsig key %q: bad base64 secret: %w", name, err)
		}
		if len(raw) == 0 {
			return nil, fmt.Errorf("tsig key %q: empty secret", name)
		}
		p.keys[dns.CanonicalName(name)] = raw
	}
	return p, nil
}

// LoadTSIGKeys parses either a file of "name base64-secret" lines (# comments
// ok) or an inline comma-separated "name:secret[,name2:secret2]" spec. An
// existing path always wins over inline parsing; colons never occur in
// base64, so the two forms are unambiguous.
func LoadTSIGKeys(spec string) (map[string]string, error) {
	if strings.Contains(spec, ":") {
		return loadTSIGKeysInline(spec)
	}
	return loadTSIGKeyFile(spec)
}

func loadTSIGKeysInline(spec string) (map[string]string, error) {
	keys := map[string]string{}
	for _, ent := range strings.Split(spec, ",") {
		name, secret, found := strings.Cut(ent, ":")
		if !found || name == "" || secret == "" {
			return nil, fmt.Errorf("malformed key entry %q (want name:secret)", ent)
		}
		keys[strings.TrimSpace(name)] = strings.TrimSpace(secret)
	}
	return keys, nil
}

func loadTSIGKeyFile(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	keys := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("malformed key line %q", line)
		}
		keys[fields[0]] = fields[1]
	}
	return keys, nil
}

func (p *hmacProvider) hashFor(algo string) (func() hash.Hash, error) {
	switch dns.CanonicalName(algo) {
	case dns.HmacSHA1:
		return sha1.New, nil
	case dns.HmacSHA256:
		return sha256.New, nil
	case dns.HmacSHA384:
		return sha512.New384, nil
	case dns.HmacSHA512:
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("unsupported TSIG algorithm %q", algo)
	}
}

// Generate computes the MAC appended to our own outgoing messages.
func (p *hmacProvider) Generate(msg []byte, t *dns.TSIG) ([]byte, error) {
	secret, ok := p.keys[strings.ToLower(t.Hdr.Name)]
	if !ok {
		return nil, fmt.Errorf("unknown tsig key %q", t.Hdr.Name)
	}
	newHash, err := p.hashFor(t.Algorithm)
	if err != nil {
		return nil, err
	}
	h := hmac.New(newHash, secret)
	h.Write(msg)
	return h.Sum(nil), nil
}

// Verify recomputes the expected MAC for an inbound message and compares it
// to the presented one in constant time.
func (p *hmacProvider) Verify(msg []byte, t *dns.TSIG) error {
	mac, err := hex.DecodeString(t.MAC)
	if err != nil {
		return fmt.Errorf("bad tsig mac encoding: %w", err)
	}
	expected, err := p.Generate(msg, t)
	if err != nil {
		return err
	}
	if !hmac.Equal(expected, mac) {
		return fmt.Errorf("tsig signature mismatch for %q", t.Hdr.Name)
	}
	return nil
}
