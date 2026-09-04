package main

import (
	"testing"

	"github.com/miekg/dns"
)

func TestMemChangeLogRecordAndDeltas(t *testing.T) {
	c := NewMemChangeLog(100)
	if _, ok := c.Deltas(100); !ok {
		t.Fatal("baseline serial should be known (empty delta list)")
	}

	rr := txtRR("a.contractdb.internal.", 5, "x")
	c.Record(101, nil, []dns.RR{rr})
	c.Record(102, []dns.RR{rr}, nil)

	deltas, ok := c.Deltas(100)
	if !ok || len(deltas) != 2 {
		t.Fatalf("Deltas(100) = %v, %v; want 2 deltas", deltas, ok)
	}
	if deltas[0].Serial != 101 || deltas[1].Serial != 102 {
		t.Fatalf("deltas out of order: %d, %d", deltas[0].Serial, deltas[1].Serial)
	}
	if len(deltas[0].Added) != 1 || len(deltas[1].Removed) != 1 {
		t.Fatal("delta contents wrong")
	}

	// Up-to-date client gets nothing but success.
	deltas, ok = c.Deltas(102)
	if !ok || len(deltas) != 0 {
		t.Fatalf("up-to-date client should get empty deltas, got %v %v", deltas, ok)
	}
}

func TestMemChangeLogUnknownSerials(t *testing.T) {
	c := NewMemChangeLog(100)
	c.Record(101, nil, nil)

	if _, ok := c.Deltas(200); ok {
		t.Fatal("future serial must report unknown history")
	}
}

func TestMemChangeLogPruning(t *testing.T) {
	c := NewMemChangeLog(0)
	for i := uint32(1); i <= memChangeLogCap+50; i++ {
		c.Record(i, nil, nil)
	}
	if _, ok := c.Deltas(10); ok {
		t.Fatal("pruned serial must report unknown history")
	}
	deltas, ok := c.Deltas(memChangeLogCap + 45)
	if !ok {
		t.Fatal("recent serials must remain available")
	}
	if uint32(len(deltas)) != 5 {
		t.Fatalf("want 5 deltas, got %d", len(deltas))
	}
}
