package gw

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"
)

func TestChainRefStoreRecordAndPeerRefs(t *testing.T) {
	s := NewChainRefStore()
	if s.Len() != 0 {
		t.Fatalf("expected empty store, got %d", s.Len())
	}

	s.Record(ChainRef{Peer: "gw1", BatchNumber: 1, Root: "root-a", Previous: "", Size: 10})
	s.Record(ChainRef{Peer: "gw2", BatchNumber: 3, Root: "root-b", Previous: "root-a", Size: 20})

	refs := s.PeerRefs()
	if len(refs) != 2 {
		t.Fatalf("expected 2 refs, got %d", len(refs))
	}

	// Same peer with lower batch must not overwrite higher batch
	s.Record(ChainRef{Peer: "gw1", BatchNumber: 1, Root: "root-x", Previous: "", Size: 5})
	s.Record(ChainRef{Peer: "gw1", BatchNumber: 2, Root: "root-a2", Previous: "root-a", Size: 12})
	refs = s.PeerRefs()
	sort.Slice(refs, func(i, j int) bool { return refs[i].Peer < refs[j].Peer })
	if refs[0].Root != "root-a2" || refs[0].BatchNumber != 2 {
		t.Fatalf("expected latest batch kept, got %+v", refs[0])
	}
	if refs[0].CapturedAt == 0 {
		t.Fatal("captured_at not set")
	}

	// Empty peer is ignored
	s.Record(ChainRef{Peer: "", BatchNumber: 9, Root: "x"})
	if s.Len() != 2 {
		t.Fatalf("empty peer should be ignored, got %d", s.Len())
	}
}

func TestChainRefStoreNilReceiver(t *testing.T) {
	var s *ChainRefStore
	s.Record(ChainRef{Peer: "gw", BatchNumber: 1, Root: "r"})
	if s.Len() != 0 || len(s.PeerRefs()) != 0 {
		t.Fatal("nil receiver should no-op")
	}
	ok, _, _ := s.CompareRef("gw", &SealedTree{BatchNumber: 1, Root: "r"})
	if ok {
		t.Fatal("nil receiver CompareRef should fail")
	}
}

func TestChainRefStoreCompareRef(t *testing.T) {
	s := NewChainRefStore()
	s.Record(ChainRef{Peer: "gw1", BatchNumber: 5, Root: "root-5", Previous: "root-4", Size: 100})

	// Peer batch matches, root matches → match
	ok, _, diff := s.CompareRef("gw1", &SealedTree{BatchNumber: 5, Root: "root-5"})
	if !ok || diff != "match" {
		t.Fatalf("expected match, got ok=%v diff=%q", ok, diff)
	}

	// Peer batch matches, root differs → tamper detection
	ok, _, _ = s.CompareRef("gw1", &SealedTree{BatchNumber: 5, Root: "root-X"})
	if ok {
		t.Fatal("expected mismatch on different root")
	}

	// Peer batch advances → treated as consistent and reference is updated
	ok, _, _ = s.CompareRef("gw1", &SealedTree{BatchNumber: 6, Root: "root-6", Previous: "root-5", Size: 110})
	if !ok {
		t.Fatal("expected match on peer advance")
	}
	refs := s.PeerRefs()
	if len(refs) != 1 || refs[0].BatchNumber != 6 || refs[0].Root != "root-6" {
		t.Fatalf("expected store updated, got %+v", refs)
	}

	// Unknown peer
	ok, _, _ = s.CompareRef("ghost", &SealedTree{BatchNumber: 1, Root: "r"})
	if ok {
		t.Fatal("expected fail for unknown peer")
	}

	// Peer regresses (lower batch) → reject
	ok, _, _ = s.CompareRef("gw1", &SealedTree{BatchNumber: 3, Root: "root-3"})
	if ok {
		t.Fatal("expected reject on peer regression")
	}
}

func TestChainSyncClientFetch(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/gateway/audit/chain" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		got = r.Method
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"local": map[string]interface{}{
				"batch": 7, "timestamp": "1755200000", "previous_root": "prev-6",
				"root": "root-7", "size": 200,
			},
		})
	}))
	defer srv.Close()

	client := ChainSyncClient{
		Peer: "gw2",
		URL:  srv.URL + "/api/v1/gateway/audit/chain",
	}
	st, err := client.Fetch()
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got != http.MethodGet {
		t.Fatalf("expected GET, got %s", got)
	}
	if st.BatchNumber != 7 || st.Root != "root-7" || st.Size != 200 {
		t.Fatalf("unexpected sealed tree: %+v", st)
	}
}

func TestChainSyncClientFetchErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "denied", http.StatusForbidden)
	}))
	defer srv.Close()

	client := ChainSyncClient{Peer: "gw2", URL: srv.URL + "/api/v1/gateway/audit/chain"}
	if _, err := client.Fetch(); err == nil {
		t.Fatal("expected error on 403")
	}

	bad := ChainSyncClient{Peer: "gw2", URL: ""}
	if _, err := bad.Fetch(); err == nil {
		t.Fatal("expected error on empty url")
	}
}

func TestChainSyncerPolling(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"local": map[string]interface{}{
				"batch": 9, "timestamp": "1755200000", "previous_root": "prev-8",
				"root": "root-9", "size": 300,
			},
		})
	}))
	defer srv.Close()

	store := NewChainRefStore()
	syncer := NewChainSyncer(store, []ChainSyncClient{
		{Peer: "gw2", URL: srv.URL + "/api/v1/gateway/audit/chain"},
	}, 10*time.Millisecond)

	syncer.Start()
	defer syncer.Stop()

	deadline := time.Now().Add(2 * time.Second)
	for store.Len() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for chain ref sync")
		}
		time.Sleep(50 * time.Millisecond)
	}
	refs := store.PeerRefs()
	if len(refs) != 1 || refs[0].Peer != "gw2" || refs[0].Root != "root-9" {
		t.Fatalf("unexpected refs: %+v", refs)
	}
}
