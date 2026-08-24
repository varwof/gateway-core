// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// ConnectionTracker tracks active connection counts by certificate serial number.
type ConnectionTracker struct {
	mu    sync.Mutex
	conns map[string]int64
}

// NewConnectionTracker creates a connection tracker.
func NewConnectionTracker() *ConnectionTracker {
	return &ConnectionTracker{conns: make(map[string]int64)}
}

// Add increments the connection count; returns false if the limit is exceeded.
func (t *ConnectionTracker) Add(serial string, max int64) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if max > 0 && t.conns[serial] >= max {
		return false
	}
	t.conns[serial]++
	return true
}

// Remove decrements the connection count.
func (t *ConnectionTracker) Remove(serial string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conns[serial] <= 0 {
		return
	}
	t.conns[serial]--
	if t.conns[serial] <= 0 {
		delete(t.conns, serial)
	}
}

// Count returns the active connection count for a given certificate.
func (t *ConnectionTracker) Count(serial string) int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.conns[serial]
}

// Total returns the total active connection count across all certificates.
func (t *ConnectionTracker) Total() int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	var n int64
	for _, c := range t.conns {
		n += c
	}
	return n
}

// Snapshot returns a snapshot of the current connections.
func (t *ConnectionTracker) Snapshot() map[string]int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[string]int64, len(t.conns))
	for k, v := range t.conns {
		out[k] = v
	}
	return out
}

// Render outputs connection counts in Prometheus format.
func (t *ConnectionTracker) Render() string {
	t.mu.Lock()
	keys := make([]string, 0, len(t.conns))
	for k := range t.conns {
		keys = append(keys, k)
	}
	t.mu.Unlock()
	sort.Strings(keys)

	var b strings.Builder
	for _, k := range keys {
		t.mu.Lock()
		c := t.conns[k]
		t.mu.Unlock()
		serial := k
		if len(serial) > 16 {
			serial = serial[:16]
		}
		b.WriteString(fmt.Sprintf("cert_%s %d\n", serial, c))
	}
	return b.String()
}
