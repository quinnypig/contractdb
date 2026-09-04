package main

import (
	"context"
	"sort"
	"strings"
	"sync"
)

// sampleStore backs -demo mode: the whole show, no AWS account required.
type sampleStore struct {
	mu    sync.RWMutex
	items map[string]Item
	gsIs  map[string]func(Item) string // index name -> attribute extractor
}

func NewSampleStore() Store {
	return NewFullSampleStore(nil)
}

// NewFullSampleStore builds a demo store with write, enumeration, and GSI
// support. gsiAttrs maps DNS-facing index names to item attribute names.
func NewFullSampleStore(gsiAttrs map[string]string) FullStore {
	s := &sampleStore{
		items: map[string]Item{},
		gsIs:  map[string]func(Item) string{},
	}
	for name, attr := range gsiAttrs {
		a := attr
		s.gsIs[name] = func(item Item) string {
			v, _ := item[a].(string)
			return v
		}
	}
	for k, v := range demoItems() {
		s.items[k] = v
	}
	return s
}

func (m *sampleStore) Get(_ context.Context, pk string) (Item, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if v, ok := m.items[pk]; ok {
		return v, nil
	}
	return nil, nil
}

func (m *sampleStore) Put(_ context.Context, pk string, item Item) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items[pk] = item
	return nil
}

func (m *sampleStore) Delete(_ context.Context, pk string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.items, pk)
	return nil
}

func (m *sampleStore) List(_ context.Context, fn func([]Entry) error) error {
	m.mu.RLock()
	keys := make([]string, 0, len(m.items))
	for k := range m.items {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	page := make([]Entry, 0, len(keys))
	for _, k := range keys {
		page = append(page, Entry{Key: k, Item: m.items[k]})
	}
	m.mu.RUnlock()
	return fn(page)
}

func (m *sampleStore) QueryIndex(_ context.Context, index, value string) ([]Entry, error) {
	extract, ok := m.gsIs[index]
	if !ok {
		return nil, &unknownIndexError{index: index}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []Entry
	keys := make([]string, 0, len(m.items))
	for k := range m.items {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if extract(m.items[k]) == value {
			out = append(out, Entry{Key: k, Item: m.items[k]})
		}
	}
	return out, nil
}

type unknownIndexError struct{ index string }

func (e *unknownIndexError) Error() string { return "unknown index " + e.index }

func demoItems() map[string]Item {
	return map[string]Item{
		"user.alice": {
			"pk":     "user.alice",
			"plan":   "enterprise",
			"email":  "alice@example.com",
			"limits": map[string]any{"riCoverage": 100.0, "dataTransferBudgetTb": 42.0},
		},
		"user.bob": {
			"pk":    "user.bob",
			"plan":  "free-tier",
			"email": "bob@example.com",
		},
		"user.carol": {
			"pk":    "user.carol",
			"plan":  "enterprise",
			"email": "carol@example.com",
		},
		"contract.nda-001": {
			"pk":        "contract.nda-001",
			"parties":   []any{"Alice LLC", "Bob Corp"},
			"effective": "2026-01-15",
			"clauses": []any{
				"1. The Parties agree that DNS is a database protocol.",
				"2. Queries over UDP exceeding 512 bytes shall set the truncate bit.",
				"3. The receiving client may retry over TCP at its discretion.",
				strings.Repeat("4. This clause exists purely to force truncation. ", 60),
			},
		},
	}
}
