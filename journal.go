package main

import (
	"sync"

	"github.com/miekg/dns"
)

// MemChangeLog is an in-memory IXFR journal: every committed write appends a
// delta keyed by the serial it produced. History is capped; once pruned,
// clients referencing ancient serials get a full fallback transfer instead.
type MemChangeLog struct {
	mu      sync.Mutex
	oldest  uint32 // lowest serial retained
	latest  uint32 // highest serial recorded
	deltas  map[uint32]Delta
	started bool
}

const memChangeLogCap = 4096

func NewMemChangeLog(startSerial uint32) *MemChangeLog {
	return &MemChangeLog{oldest: startSerial + 1, latest: startSerial}
}

func (c *MemChangeLog) Record(serial uint32, removed, added []dns.RR) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.started {
		// First record defines the baseline if constructed zero-valued.
		if c.oldest == 0 {
			c.oldest = serial
		}
		c.started = true
	}
	if c.deltas == nil {
		c.deltas = make(map[uint32]Delta)
	}
	c.deltas[serial] = Delta{Serial: serial, Removed: removed, Added: added}
	if serial > c.latest {
		c.latest = serial
	}
	// Prune oldest entries beyond the cap.
	for len(c.deltas) > memChangeLogCap {
		delete(c.deltas, c.oldest)
		c.oldest++
	}
}

func (c *MemChangeLog) Deltas(since uint32) ([]Delta, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if since > c.latest || since < c.oldest-1 {
		return nil, false
	}
	out := make([]Delta, 0, c.latest-since)
	for s := since + 1; s <= c.latest; s++ {
		d, ok := c.deltas[s]
		if !ok {
			return nil, false
		}
		out = append(out, d)
	}
	return out, true
}
