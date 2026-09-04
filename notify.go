package main

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// SendNotify sends an RFC 1996 NOTIFY-SOA for zone to addr ("host:port")
// over UDP and waits briefly for the slave's acknowledgment.
func SendNotify(addr, zone string) error {
	m := new(dns.Msg)
	m.SetQuestion(zone, dns.TypeSOA)
	m.Opcode = dns.OpcodeNotify
	m.RecursionDesired = false

	c := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		return fmt.Errorf("notify %s (%s): %w", addr, zone, err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("notify %s (%s): slave answered %s", addr, zone, dns.RcodeToString[resp.Rcode])
	}
	return nil
}

// NotifyAll notifies every address concurrently, waiting for all
// acknowledgments (or failures) before returning.
func NotifyAll(addrs []string, zone string) {
	var wg sync.WaitGroup
	for _, addr := range addrs {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			if err := SendNotify(addr, zone); err != nil {
				log.Printf("%v", err)
			}
		}(addr)
	}
	wg.Wait()
}
