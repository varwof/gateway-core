// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"sync"
	"sync/atomic"
	"time"
)

// CloseFunc is a function that closes a single connection.
type CloseFunc func()

// connEntry holds a close function with its identity metadata.
type connEntry struct {
	id           uint64
	agentId      string
	principalUid string
	srcIP        string
	protocol     string
	established  int64
	serial       string
	close        CloseFunc
}

// ConnRegistry maps agent_id and principalUid to close functions.
// It is safe for concurrent use and designed for gateway disconnect APIs.
type ConnRegistry struct {
	mu      sync.RWMutex
	entries []connEntry
	byID    map[string][]uint64
	byUID   map[string][]uint64
	nextID  atomic.Uint64
}

// NewConnRegistry creates a new ConnRegistry.
func NewConnRegistry() *ConnRegistry {
	return &ConnRegistry{
		byID:  make(map[string][]uint64),
		byUID: make(map[string][]uint64),
	}
}

// Register adds a close function associated with the given agentId and
// principalUid. Returns a RemoveFunc that should be called on disconnect.
// Safe to call on a nil receiver (returns noop).
func (r *ConnRegistry) Register(agentId, principalUid string, close CloseFunc) func() {
	return r.RegisterConn(agentId, principalUid, "", "", "", close)
}

// RegisterConn adds a close function associated with the given identity and
// connection metadata (source IP, protocol, certificate serial). Returns a
// RemoveFunc that should be called on disconnect. Safe on a nil receiver.
func (r *ConnRegistry) RegisterConn(agentId, principalUid, srcIP, protocol, serial string, close CloseFunc) func() {
	if r == nil {
		return func() {}
	}
	id := r.nextID.Add(1)
	r.mu.Lock()
	r.entries = append(r.entries, connEntry{
		id: id, agentId: agentId, principalUid: principalUid,
		srcIP: srcIP, protocol: protocol, serial: serial,
		established: time.Now().Unix(), close: close,
	})
	if agentId != "" {
		r.byID[agentId] = append(r.byID[agentId], id)
	}
	if principalUid != "" {
		r.byUID[principalUid] = append(r.byUID[principalUid], id)
	}
	r.mu.Unlock()

	removed := false
	return func() {
		if removed {
			return
		}
		removed = true
		r.mu.Lock()
		r.byID[agentId] = removeID(r.byID[agentId], id)
		r.byUID[principalUid] = removeID(r.byUID[principalUid], id)
		for i, e := range r.entries {
			if e.id == id {
				r.entries = append(r.entries[:i], r.entries[i+1:]...)
				break
			}
		}
		r.mu.Unlock()
	}
}

// DisconnectByAgentId closes all connections for the given agentId.
// Returns the number of connections closed. Safe on nil receiver.
func (r *ConnRegistry) DisconnectByAgentId(agentId string) int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	ids := r.byID[agentId]
	delete(r.byID, agentId)
	var fns []CloseFunc
	for _, id := range ids {
		if e := r.findEntry(id); e != nil {
			fns = append(fns, e.close)
		}
		// Also remove from byUID
		for uid, uidIDs := range r.byUID {
			r.byUID[uid] = removeID(uidIDs, id)
		}
	}
	r.mu.Unlock()
	for _, fn := range fns {
		fn()
	}
	return len(fns)
}

// DisconnectByPrincipalUid closes all connections for the given principalUid.
// Returns the number of connections closed. Safe on nil receiver.
func (r *ConnRegistry) DisconnectByPrincipalUid(principalUid string) int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	ids := r.byUID[principalUid]
	delete(r.byUID, principalUid)
	var fns []CloseFunc
	for _, id := range ids {
		if e := r.findEntry(id); e != nil {
			fns = append(fns, e.close)
		}
		for aid, aidIDs := range r.byID {
			r.byID[aid] = removeID(aidIDs, id)
		}
	}
	r.mu.Unlock()
	for _, fn := range fns {
		fn()
	}
	return len(fns)
}

// Stats returns the number of tracked connections. Safe on nil receiver.
func (r *ConnRegistry) Stats() (total int) {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.entries)
}

// ListByAgentId returns agentId → count for all tracked agents.
func (r *ConnRegistry) ListByAgentId() map[string]int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make(map[string]int, len(r.byID))
	for id, ids := range r.byID {
		result[id] = len(ids)
	}
	return result
}

// ConnectionInfo is a detailed connection entry (real-time traffic/IP access point/agent directory query).
type ConnectionInfo struct {
	// ID is the internal connection registry ID.
	ID uint64 `json:"id"`
	// AgentId is the associated agent identifier.
	AgentId string `json:"agent_id,omitempty"`
	// PrincipalUid is the associated responsible party identifier.
	PrincipalUid string `json:"principal_uid,omitempty"`
	// SrcIP is the connection source IP.
	SrcIP string `json:"src_ip,omitempty"`
	// Protocol is the transport protocol (tcp/http/udp/dtls/quic).
	Protocol string `json:"protocol,omitempty"`
	// Serial is the client certificate serial number.
	Serial string `json:"serial,omitempty"`
	// Established is the connection establishment time (Unix seconds).
	Established int64 `json:"established,omitempty"`
}

// ListConnections returns a snapshot of all active connection details.
// Safe on nil receiver.
func (r *ConnRegistry) ListConnections() []ConnectionInfo {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]ConnectionInfo, 0, len(r.entries))
	for _, e := range r.entries {
		out = append(out, ConnectionInfo{
			ID: e.id, AgentId: e.agentId, PrincipalUid: e.principalUid,
			SrcIP: e.srcIP, Protocol: e.protocol, Serial: e.serial,
			Established: e.established,
		})
	}
	return out
}

// ListByIP returns connection counts aggregated by source IP.
// Safe on nil receiver.
func (r *ConnRegistry) ListByIP() map[string]int {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]int)
	for _, e := range r.entries {
		if e.srcIP != "" {
			out[e.srcIP]++
		}
	}
	return out
}

func (r *ConnRegistry) findEntry(id uint64) *connEntry {
	for i := range r.entries {
		if r.entries[i].id == id {
			return &r.entries[i]
		}
	}
	return nil
}

func removeID(ids []uint64, id uint64) []uint64 {
	for i, v := range ids {
		if v == id {
			return append(ids[:i], ids[i+1:]...)
		}
	}
	return ids
}
