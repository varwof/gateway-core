// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"crypto/rand"
	"testing"
	"time"
)

func TestNonceCache_CheckAndAdd_FirstTime(t *testing.T) {
	nc := NewNonceCache()
	defer nc.Stop()

	nonce := make([]byte, 32)
	rand.Read(nonce)

	if !nc.CheckAndAdd("issuer/1", nonce) {
		t.Fatal("expected true for first-time nonce")
	}
}

func TestNonceCache_CheckAndAdd_SameScopeReuse(t *testing.T) {
	nc := NewNonceCache()
	defer nc.Stop()

	nonce := make([]byte, 32)
	rand.Read(nonce)

	if !nc.CheckAndAdd("issuer/1", nonce) {
		t.Fatal("expected true for first-time nonce")
	}
	if !nc.CheckAndAdd("issuer/1", nonce) {
		t.Fatal("expected true when the same certificate re-presents the same nonce")
	}
}

func TestNonceCache_CheckAndAdd_CrossScopeReplay(t *testing.T) {
	nc := NewNonceCache()
	defer nc.Stop()

	nonce := make([]byte, 32)
	rand.Read(nonce)

	nc.CheckAndAdd("issuer/1", nonce) // first use under cert A
	if nc.CheckAndAdd("issuer/2", nonce) {
		t.Fatal("expected false when a different certificate reuses the same nonce (DA replay)")
	}
}

func TestNonceCache_CheckAndAdd_EmptyNonce(t *testing.T) {
	nc := NewNonceCache()
	defer nc.Stop()

	if nc.CheckAndAdd("issuer/1", nil) {
		t.Fatal("expected false for nil nonce")
	}
	if nc.CheckAndAdd("issuer/1", []byte{}) {
		t.Fatal("expected false for empty nonce")
	}
}

func TestNonceCache_CheckAndAdd_MultipleNonces(t *testing.T) {
	nc := NewNonceCache()
	defer nc.Stop()

	nonces := make([][]byte, 10)
	for i := range nonces {
		nonces[i] = make([]byte, 32)
		rand.Read(nonces[i])
		if !nc.CheckAndAdd("issuer/1", nonces[i]) {
			t.Fatalf("expected true for nonce %d (first time)", i)
		}
	}

	if nc.Len() != 10 {
		t.Fatalf("expected Len=10, got %d", nc.Len())
	}

	// Same scope reuse each one
	for i, n := range nonces {
		if !nc.CheckAndAdd("issuer/1", n) {
			t.Fatalf("expected true for nonce %d (same-scope reuse)", i)
		}
	}

	// Cross-scope replay each one
	for i, n := range nonces {
		if nc.CheckAndAdd("issuer/2", n) {
			t.Fatalf("expected false for nonce %d (cross-scope replay)", i)
		}
	}
}

func TestNonceCache_Cleanup(t *testing.T) {
	nc := NewNonceCache()

	nonce := make([]byte, 32)
	rand.Read(nonce)
	nc.CheckAndAdd("issuer/1", nonce)

	// Manually trigger cleanup with future deadline
	nc.m.Store("stale-key", &nonceEntry{scope: "issuer/old", seen: time.Now().Add(-48 * time.Hour)})
	nc.cleanup()

	if nc.Len() != 1 {
		t.Fatalf("expected 1 entry after cleanup (fresh nonce), got %d", nc.Len())
	}

	nc.Stop()
}

func TestNonceCache_Concurrent(t *testing.T) {
	nc := NewNonceCache()
	defer nc.Stop()

	done := make(chan bool, 20)
	for i := 0; i < 20; i++ {
		go func() {
			nonce := make([]byte, 32)
			rand.Read(nonce)
			nc.CheckAndAdd("issuer/1", nonce)
			done <- true
		}()
	}

	for i := 0; i < 20; i++ {
		<-done
	}

	if nc.Len() != 20 {
		t.Fatalf("expected 20 entries, got %d", nc.Len())
	}
}
