package gw

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// ChainRef is a peer gateway audit chain reference snapshot (DAG horizontal anchoring).
// Each gateway locally maintains an AuditChain (vertical hash chain), and periodically
// syncs its local chain head to peer gateways. Peers record received chain heads as
// ChainRefs. During verification, the peer's self-exposed chain head is compared against
// the locally recorded reference (hash anchoring), forming a cross-gateway audit evidence
// DAG — proving that each gateway's chain is temporally anchored to others without
// consensus ordering, and any unilateral tampering would break reference consistency.
type ChainRef struct {
	// Peer is the peer gateway name.
	Peer string `json:"peer"`
	// BatchNumber is the remote's latest sealed batch number.
	BatchNumber int `json:"batch"`
	// Root is the remote's latest batch root hash (hex).
	Root string `json:"root"`
	// Previous is the remote batch's predecessor root hash (hex).
	Previous string `json:"previous_root"`
	// Size is the number of entries in the remote batch.
	Size int `json:"size"`
	// Timestamp is the remote batch timestamp (Unix seconds).
	Timestamp string `json:"timestamp"`
	// CapturedAt is the local time this reference was captured (Unix seconds).
	CapturedAt int64 `json:"captured_at"`
}

// ChainRefStore stores cross-gateway audit chain references.
// Thread-safe, stores the latest chain head reference per peer gateway name.
type ChainRefStore struct {
	mu   sync.RWMutex
	refs map[string]ChainRef
}

// NewChainRefStore creates a cross-gateway audit chain reference store.
func NewChainRefStore() *ChainRefStore {
	return &ChainRefStore{refs: make(map[string]ChainRef)}
}

// Record records the latest chain head reference for a peer gateway. Only the latest batch is kept per peer.
// Safe on nil receiver (no-op)。
func (s *ChainRefStore) Record(ref ChainRef) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ref.Peer == "" {
		return
	}
	cur, ok := s.refs[ref.Peer]
	if ok && cur.BatchNumber >= ref.BatchNumber {
		return
	}
	ref.CapturedAt = time.Now().Unix()
	s.refs[ref.Peer] = ref
}

// PeerRefs returns a snapshot of all peer gateway references (sorted by peer name).
// Safe on nil receiver (returns nil)。
func (s *ChainRefStore) PeerRefs() []ChainRef {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ChainRef, 0, len(s.refs))
	for _, r := range s.refs {
		out = append(out, r)
	}
	return out
}

// Len returns the number of recorded peer gateways. Safe on nil receiver.
func (s *ChainRefStore) Len() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.refs)
}

// CompareRef compares the locally recorded remote reference against the remote's actual
// exposed chain head. Returns (match, remote chain head, difference description).
// When the remote batch number is less than or equal to the local reference batch number,
// their root hashes are compared directly; a newer batch number is treated as consistent
// (normal remote advancement) and updates the local record.
func (s *ChainRefStore) CompareRef(peer string, theirs *SealedTree) (bool, ChainRef, string) {
	if s == nil || theirs == nil {
		return false, ChainRef{}, "missing store or peer chain head"
	}
	s.mu.RLock()
	ref, ok := s.refs[peer]
	s.mu.RUnlock()
	if !ok {
		return false, ChainRef{}, fmt.Sprintf("no recorded reference for peer %q", peer)
	}
	if theirs.BatchNumber < ref.BatchNumber {
		return false, ref, fmt.Sprintf(
			"peer batch %d older than recorded %d", theirs.BatchNumber, ref.BatchNumber)
	}
	if theirs.BatchNumber == ref.BatchNumber {
		if ref.Root != "" && theirs.Root != "" && ref.Root != theirs.Root {
			return false, ref, fmt.Sprintf(
				"root mismatch: recorded %s vs peer %s", ref.Root, theirs.Root)
		}
	} else {
		// Remote advanced to a newer batch: during legitimate advancement, the new chain
		// head's predecessor must be the latest root recorded locally (vertical hash chain
		// continuity), otherwise it is considered tampering or a fork.
		if ref.Root != "" && theirs.Previous != "" && ref.Root != theirs.Previous {
			return false, ref, fmt.Sprintf(
				"chain break: recorded root %s != peer previous %s", ref.Root, theirs.Previous)
		}
	}
	// Remote advanced to a newer batch: local reference lagging behind, within normal sync window, treated as consistent.
	s.Record(ChainRef{
		Peer:        peer,
		BatchNumber: theirs.BatchNumber,
		Root:        theirs.Root,
		Previous:    theirs.Previous,
		Size:        theirs.Size,
		Timestamp:   theirs.Timestamp,
	})
	return true, ref, "match"
}

// ChainPeerConfig is the configuration for a cross-gateway audit chain reference peer node.
type ChainPeerConfig struct {
	// Name is the peer gateway name.
	Name string `json:"name"`
	// URL is the peer gateway management API base URL, e.g. https://gw2:9443.
	// The synchronizer will request <URL>/api/v1/gateway/audit/chain.
	URL string `json:"url"`
	// TLSConfig is the peer gateway mTLS client configuration (reuses the gateway management API client).
	TLSConfig *tls.Config `json:"-"`
}

// NewChainHTTPClient creates an HTTP client for chain reference synchronization based on mTLS configuration.
// Falls back to a default client when tlsConfig is nil.
func NewChainHTTPClient(tlsConfig *tls.Config) *http.Client {
	if tlsConfig == nil {
		return &http.Client{Timeout: 5 * time.Second}
	}
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
		Timeout:   5 * time.Second,
	}
}

// ChainSyncClient fetches chain head references from a peer gateway management API.
// Reuses an mTLS HTTP client to GET /api/v1/gateway/audit/chain from the remote peer.
type ChainSyncClient struct {
	// Peer is the peer gateway name (for local record keeping).
	Peer string
	// URL is the remote management endpoint, e.g. https://host:9443/api/v1/gateway/audit/chain.
	URL string
	// HTTPClient is the HTTP client with mTLS certificates.
	HTTPClient *http.Client
	// Timeout is the per-fetch timeout (default 5s).
	Timeout time.Duration
}

// Fetch retrieves the remote chain head and returns it.
func (c *ChainSyncClient) Fetch() (*SealedTree, error) {
	if c.URL == "" {
		return nil, fmt.Errorf("chain sync: empty peer url")
	}
	hc := c.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	hc.Timeout = timeout
	resp, err := hc.Get(c.URL)
	if err != nil {
		return nil, fmt.Errorf("chain sync: fetch %s: %w", c.URL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("chain sync: %s returned %d", c.URL, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("chain sync: read body: %w", err)
	}
	var payload chainHeadResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("chain sync: decode %s: %w", c.URL, err)
	}
	if payload.Local == nil {
		return nil, fmt.Errorf("chain sync: %s missing local chain head", c.URL)
	}
	return payload.Local, nil
}

// chainHeadResponse represents the local chain head field from the remote /audit/chain response.
type chainHeadResponse struct {
	Local *SealedTree `json:"local"`
}

// ChainSyncer periodically synchronizes peer gateway audit chain references.
// After Start, it polls all peers at Interval and writes the latest chain heads to the store.
type ChainSyncer struct {
	Store    *ChainRefStore
	Peers    []ChainSyncClient
	Interval time.Duration
	stopCh   chan struct{}
}

// NewChainSyncer creates a chain reference synchronizer.
func NewChainSyncer(store *ChainRefStore, peers []ChainSyncClient, interval time.Duration) *ChainSyncer {
	if store == nil {
		store = NewChainRefStore()
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &ChainSyncer{
		Store:    store,
		Peers:    peers,
		Interval: interval,
		stopCh:   make(chan struct{}),
	}
}

// Start starts the background synchronization loop.
func (s *ChainSyncer) Start() {
	if s == nil || len(s.Peers) == 0 {
		return
	}
	go func() {
		s.syncOnce()
		ticker := time.NewTicker(s.Interval)
		defer ticker.Stop()
		for {
			select {
			case <-s.stopCh:
				return
			case <-ticker.C:
				s.syncOnce()
			}
		}
	}()
}

// Stop stops the background synchronization loop.
func (s *ChainSyncer) Stop() {
	if s == nil {
		return
	}
	select {
	case <-s.stopCh:
	default:
		close(s.stopCh)
	}
}

func (s *ChainSyncer) syncOnce() {
	for _, peer := range s.Peers {
		st, err := peer.Fetch()
		if err != nil {
			continue
		}
		s.Store.Record(ChainRef{
			Peer:        peer.Peer,
			BatchNumber: st.BatchNumber,
			Root:        st.Root,
			Previous:    st.Previous,
			Size:        st.Size,
			Timestamp:   st.Timestamp,
		})
	}
}
