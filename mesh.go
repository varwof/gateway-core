package gw

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// MeshPeer represents a peer gateway node in the mesh.
type MeshPeer struct {
	Name    string            `json:"name"`
	Address string            `json:"address"`
	Weight  int               `json:"weight,omitempty"`
	Tags    map[string]string `json:"tags,omitempty"`
}

// MeshConfig defines the mesh configuration.
type MeshConfig struct {
	// LocalName is the name of this node.
	LocalName string `json:"local_name"`
	// TLSConfig is the mTLS configuration for inter-node communication.
	TLSConfig *tls.Config `json:"-"`
	// Peers is the list of peer node addresses.
	Peers []MeshPeer `json:"peers"`
	// DialTimeout is the connection timeout.
	DialTimeout time.Duration `json:"-"`
	// PingInterval is the health check interval for peers.
	PingInterval time.Duration `json:"-"`
}

// peerConn maintains the connection state to a single peer node.
type peerConn struct {
	peer    MeshPeer
	conn    net.Conn
	tlsConn *tls.Conn
	mu      sync.Mutex
	healthy atomic.Bool
	logger  *slog.Logger
}

// MeshManager manages mesh peer connections and forwarding.
type MeshManager struct {
	cfg     MeshConfig
	peers   []*peerConn
	stopCh  chan struct{}
	stopped atomic.Bool
	mu      sync.RWMutex
	logger  *slog.Logger

	ctrlMu    sync.Mutex
	ctrlSeq   uint64
	ctrlDedup map[string]time.Time
	ctrlFn    ControlHandler
}

// ControlHandler is a callback for handling mesh control plane messages, wired by the gateway
// for revocation evaluation/session management. When it returns an error, MeshManager only
// logs the error and does not block message dispatch.
type ControlHandler func(msg ControlMessage) error

// NewMeshManager creates a mesh manager.
func NewMeshManager(cfg MeshConfig) *MeshManager {
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	if cfg.PingInterval == 0 {
		cfg.PingInterval = 30 * time.Second
	}
	return &MeshManager{
		cfg:       cfg,
		stopCh:    make(chan struct{}),
		logger:    slog.Default().With("component", "mesh", "local", cfg.LocalName),
		ctrlDedup: make(map[string]time.Time),
	}
}

// SetControlHandler registers the control plane message callback. Messages from the same
// source are deduplicated by MsgID, so the handler is not called more than once per message
// (default dedup window is 5 minutes, see ControlDedupWindow).
func (m *MeshManager) SetControlHandler(fn ControlHandler) {
	m.ctrlMu.Lock()
	m.ctrlFn = fn
	m.ctrlMu.Unlock()
}

// nextControlID generates a locally incrementing unique message ID (source + seq, for dedup and loop prevention).
func (m *MeshManager) nextControlID() string {
	m.ctrlMu.Lock()
	defer m.ctrlMu.Unlock()
	m.ctrlSeq++
	return fmt.Sprintf("%s-%d", m.cfg.LocalName, m.ctrlSeq)
}

// dedupSeen returns whether a message has already been processed (dedup and loop prevention).
// First-seen messages are timestamped. Expired entries are periodically cleaned up by StartDedupCleanup.
func (m *MeshManager) dedupSeen(id string) bool {
	if id == "" {
		return false
	}
	m.ctrlMu.Lock()
	defer m.ctrlMu.Unlock()
	if _, ok := m.ctrlDedup[id]; ok {
		return true
	}
	m.ctrlDedup[id] = time.Now()
	return false
}

// Start connects to all peer nodes and starts the health check loop.
func (m *MeshManager) Start() error {
	if m.stopped.Load() {
		return fmt.Errorf("mesh: already stopped")
	}
	if len(m.cfg.Peers) == 0 {
		m.logger.Warn("mesh: no peers configured")
		return nil
	}
	for _, p := range m.cfg.Peers {
		pc := &peerConn{
			peer:   p,
			logger: m.logger.With("peer", p.Name, "address", p.Address),
		}
		if err := m.dialPeer(pc); err != nil {
			m.logger.Warn("mesh: peer dial failed", "peer", p.Name, "error", err)
			// Do not block startup; retry in the background
		} else {
			pc.healthy.Store(true)
		}
		m.mu.Lock()
		m.peers = append(m.peers, pc)
		m.mu.Unlock()
	}
	go m.healthLoop()
	return nil
}

func (m *MeshManager) dialPeer(pc *peerConn) error {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.DialTimeout)
	defer cancel()
	dialer := &tls.Dialer{Config: m.cfg.TLSConfig}
	conn, err := dialer.DialContext(ctx, "tcp", pc.peer.Address)
	if err != nil {
		return fmt.Errorf("dial peer %s: %w", pc.peer.Name, err)
	}
	pc.conn = conn
	pc.tlsConn = conn.(*tls.Conn)
	pc.healthy.Store(true)
	pc.logger.Info("mesh: connected to peer")
	return nil
}

func (m *MeshManager) healthLoop() {
	ticker := time.NewTicker(m.cfg.PingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.checkPeers()
		}
	}
}

func (m *MeshManager) checkPeers() {
	m.mu.RLock()
	peers := make([]*peerConn, len(m.peers))
	copy(peers, m.peers)
	m.mu.RUnlock()
	for _, pc := range peers {
		healthy := pc.healthy.Load()
		if !healthy {
			if err := m.dialPeer(pc); err != nil {
				pc.logger.Warn("mesh: reconnection failed", "error", err)
			}
			continue
		}
		// Quick health check: set a read timeout and attempt a read
		pc.tlsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		// If we can read any data within the ping interval, the connection is alive.
		// Here we only check if the connection has been closed.
		var buf [1]byte
		_, err := pc.tlsConn.Read(buf[:])
		if err != nil {
			pc.logger.Warn("mesh: peer connection lost", "error", err)
			pc.healthy.Store(false)
			pc.conn.Close()
			go func(pc *peerConn) {
				if err := m.dialPeer(pc); err != nil {
					pc.logger.Warn("mesh: reconnection failed", "error", err)
				}
			}(pc)
		}
	}
}

// Forward opens a new mTLS connection to the target peer and pipes data.
func (m *MeshManager) Forward(peerName string, conn net.Conn) error {
	target := m.findPeerConn(peerName)
	if target == nil {
		return fmt.Errorf("mesh: peer %q not connected", peerName)
	}
	// Establish an outbound mTLS connection to the peer
	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.DialTimeout)
	defer cancel()
	dialer := &tls.Dialer{Config: m.cfg.TLSConfig}
	peerConn, err := dialer.DialContext(ctx, "tcp", target.peer.Address)
	if err != nil {
		return fmt.Errorf("mesh: forward dial %s: %w", peerName, err)
	}
	defer peerConn.Close()
	// Bidirectional pipe
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(peerConn, conn)
		peerConn.Close()
	}()
	go func() {
		defer wg.Done()
		io.Copy(conn, peerConn)
		conn.Close()
	}()
	wg.Wait()
	return nil
}

func (m *MeshManager) findPeerConn(name string) *peerConn {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, pc := range m.peers {
		if pc.peer.Name == name && pc.healthy.Load() {
			return pc
		}
	}
	return nil
}

// HealthyPeers returns the list of currently healthy peer connections.
func (m *MeshManager) HealthyPeers() []MeshPeer {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []MeshPeer
	for _, pc := range m.peers {
		if pc.healthy.Load() {
			result = append(result, pc.peer)
		}
	}
	return result
}

// SelectPeer randomly selects a healthy peer by weight.
func (m *MeshManager) SelectPeer(tags map[string]string) *MeshPeer {
	peers := m.HealthyPeers()
	if len(peers) == 0 {
		return nil
	}
	// Filter by tags
	var candidates []MeshPeer
	for _, p := range peers {
		if matchesTags(p.Tags, tags) {
			candidates = append(candidates, p)
		}
	}
	if len(candidates) == 0 {
		candidates = peers
	}
	// Weighted random selection
	var total int
	for _, p := range candidates {
		w := p.Weight
		if w <= 0 {
			w = 1
		}
		total += w
	}
	r := rand.Intn(total)
	for _, p := range candidates {
		w := p.Weight
		if w <= 0 {
			w = 1
		}
		r -= w
		if r < 0 {
			return &p
		}
	}
	return &candidates[0]
}

// Stop closes all mesh connections.
func (m *MeshManager) Stop() {
	if !m.stopped.CompareAndSwap(false, true) {
		return
	}
	close(m.stopCh)
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, pc := range m.peers {
		pc.mu.Lock()
		if pc.conn != nil {
			pc.conn.Close()
		}
		pc.mu.Unlock()
		pc.healthy.Store(false)
	}
	m.peers = nil
	m.logger.Info("mesh: stopped")
}

func matchesTags(a, b map[string]string) bool {
	if len(b) == 0 {
		return true
	}
	for k, v := range b {
		av, ok := a[k]
		if !ok || av != v {
			return false
		}
	}
	return true
}
