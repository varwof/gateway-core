package gw

import (
	"crypto/tls"
	"testing"
	"time"
)

func TestMatchesTags(t *testing.T) {
	if !matchesTags(map[string]string{"a": "1"}, nil) {
		t.Fatal("nil filter should match")
	}
	if !matchesTags(map[string]string{"a": "1"}, map[string]string{}) {
		t.Fatal("empty filter should match")
	}
	if !matchesTags(map[string]string{"a": "1", "b": "2"}, map[string]string{"a": "1"}) {
		t.Fatal("subset filter should match")
	}
	if matchesTags(map[string]string{"a": "1"}, map[string]string{"a": "2"}) {
		t.Fatal("value mismatch should not match")
	}
	if matchesTags(map[string]string{"a": "1"}, map[string]string{"b": "1"}) {
		t.Fatal("missing key should not match")
	}
}

func TestNewMeshManagerDefaults(t *testing.T) {
	m := NewMeshManager(MeshConfig{LocalName: "test"})
	if m.cfg.DialTimeout != 10*time.Second {
		t.Fatalf("expected 10s dial timeout, got %v", m.cfg.DialTimeout)
	}
	if m.cfg.PingInterval != 30*time.Second {
		t.Fatalf("expected 30s ping interval, got %v", m.cfg.PingInterval)
	}
	m.Stop()
}

func TestMeshStartNoPeers(t *testing.T) {
	m := NewMeshManager(MeshConfig{LocalName: "solo"})
	if err := m.Start(); err != nil {
		t.Fatalf("start with no peers: %v", err)
	}
	peers := m.HealthyPeers()
	if len(peers) != 0 {
		t.Fatalf("expected 0 healthy peers, got %d", len(peers))
	}
	m.Stop()
	if err := m.Start(); err == nil {
		t.Fatal("expected error starting after stop")
	}
}

func TestMeshSelectPeerNoPeers(t *testing.T) {
	m := NewMeshManager(MeshConfig{LocalName: "test"})
	p := m.SelectPeer(nil)
	if p != nil {
		t.Fatal("expected nil peer when none available")
	}
}

func TestMeshSelectPeerWeighted(t *testing.T) {
	m := NewMeshManager(MeshConfig{
		LocalName: "test",
		Peers: []MeshPeer{
			{Name: "a", Address: "10.0.0.1:9181", Weight: 10},
			{Name: "b", Address: "10.0.0.2:9181", Weight: 1},
			{Name: "c", Address: "10.0.0.3:9181", Weight: 0},
		},
	})
	// Without real connections, SelectPeer only checks HealthyPeers
	// There are no healthy peers at this point, so it should return nil
	p := m.SelectPeer(nil)
	if p != nil {
		t.Fatal("expected nil since no peers are actually connected")
	}
	_ = p
	// Weight test: manually inject mock connections
	m.mu.Lock()
	m.peers = append(m.peers, newHealthyPeer("a", "a:1", 10, nil))
	m.peers = append(m.peers, newHealthyPeer("b", "b:1", 1, nil))
	m.mu.Unlock()
	counts := map[string]int{}
	for i := 0; i < 1000; i++ {
		p := m.SelectPeer(nil)
		if p != nil {
			counts[p.Name]++
		}
	}
	if counts["a"] < counts["b"]*3 {
		t.Fatalf("expected weighted selection favoring a, got %v", counts)
	}
	m.Stop()
}

func TestMeshSelectPeerTagFilter(t *testing.T) {
	m := NewMeshManager(MeshConfig{LocalName: "test"})
	m.mu.Lock()
	m.peers = append(m.peers, newHealthyPeer("db-east", "east:1", 0, map[string]string{"region": "east", "type": "db"}))
	m.peers = append(m.peers, newHealthyPeer("web-east", "east:2", 0, map[string]string{"region": "east", "type": "web"}))
	m.peers = append(m.peers, newHealthyPeer("db-west", "west:1", 0, map[string]string{"region": "west", "type": "db"}))
	m.mu.Unlock()

	// Filter by type
	p := m.SelectPeer(map[string]string{"type": "db"})
	if p == nil {
		t.Fatal("expected peer with type=db")
	}
	if p.Tags["type"] != "db" {
		t.Fatalf("expected type=db, got %v", p.Tags)
	}

	// Filter by region + type
	p = m.SelectPeer(map[string]string{"region": "west", "type": "db"})
	if p == nil || p.Name != "db-west" {
		t.Fatalf("expected db-west, got %v", p)
	}

	m.Stop()
}

func newHealthyPeer(name, addr string, weight int, tags map[string]string) *peerConn {
	pc := &peerConn{
		peer: MeshPeer{Name: name, Address: addr, Weight: weight, Tags: tags},
	}
	pc.healthy.Store(true)
	return pc
}

func TestMeshStopIdempotent(t *testing.T) {
	m := NewMeshManager(MeshConfig{LocalName: "test"})
	m.Stop()
	m.Stop() // second call should not panic
}

func TestMeshPeerTLSConfig(t *testing.T) {
	// Verify TLS config is passed through (no actual connection test)
	cfg := &tls.Config{
		InsecureSkipVerify: true,
	}
	m := NewMeshManager(MeshConfig{
		LocalName: "test",
		TLSConfig: cfg,
	})
	if m.cfg.TLSConfig != cfg {
		t.Fatal("TLSConfig not preserved")
	}
	m.Stop()
}
