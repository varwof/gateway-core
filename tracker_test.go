// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"strings"
	"sync"
	"testing"
)

func TestTrackerAddRemove(t *testing.T) {
	tr := NewConnectionTracker()
	if !tr.Add("abc", 0) {
		t.Fatal("Add with no max should succeed")
	}
	if !tr.Add("abc", 0) {
		t.Fatal("second Add should succeed")
	}
	if got := tr.Count("abc"); got != 2 {
		t.Fatalf("Count: expected 2, got %d", got)
	}
	tr.Remove("abc")
	if got := tr.Count("abc"); got != 1 {
		t.Fatalf("Count after remove: expected 1, got %d", got)
	}
	tr.Remove("abc")
	if got := tr.Count("abc"); got != 0 {
		t.Fatalf("Count after remove all: expected 0, got %d", got)
	}
}

func TestTrackerMax(t *testing.T) {
	tr := NewConnectionTracker()
	if !tr.Add("serial1", 2) {
		t.Fatal("first Add should succeed")
	}
	if !tr.Add("serial1", 2) {
		t.Fatal("second Add should succeed")
	}
	if tr.Add("serial1", 2) {
		t.Fatal("third Add with max=2 should fail")
	}
}

func TestTrackerRemoveUnderflow(t *testing.T) {
	tr := NewConnectionTracker()
	tr.Remove("nonexistent")
	got := tr.Total()
	if got != 0 {
		t.Fatalf("Total after underflow remove: expected 0, got %d", got)
	}
}

func TestTrackerTotal(t *testing.T) {
	tr := NewConnectionTracker()
	tr.Add("a", 0)
	tr.Add("a", 0)
	tr.Add("b", 0)
	if got := tr.Total(); got != 3 {
		t.Fatalf("Total: expected 3, got %d", got)
	}
}

func TestTrackerSnapshot(t *testing.T) {
	tr := NewConnectionTracker()
	tr.Add("snap1", 0)
	tr.Add("snap1", 0)
	tr.Add("snap2", 0)
	snap := tr.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("snapshot len: expected 2, got %d", len(snap))
	}
	if snap["snap1"] != 2 {
		t.Fatalf("snap1: expected 2, got %d", snap["snap1"])
	}
}

func TestTrackerRender(t *testing.T) {
	tr := NewConnectionTracker()
	tr.Add("AAAA00000001", 0)
	tr.Add("AAAA00000001", 0)
	output := tr.Render()
	if !strings.HasPrefix(output, "cert_AAAA00000001") {
		t.Fatalf("unexpected render: %s", output)
	}
}

func TestTrackerConcurrentAccess(t *testing.T) {
	tr := NewConnectionTracker()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tr.Add("concurrent", 100)
		}()
	}
	wg.Wait()
	if got := tr.Count("concurrent"); got != 50 {
		t.Fatalf("concurrent Add: expected 50, got %d", got)
	}

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tr.Remove("concurrent")
		}()
	}
	wg.Wait()
	if got := tr.Count("concurrent"); got != 0 {
		t.Fatalf("concurrent Remove: expected 0, got %d", got)
	}
}
