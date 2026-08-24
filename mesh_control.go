// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// ControlMessageType is a control plane message type.
type ControlMessageType string

const (
	// ControlRevoke is a revocation notification: payload contains certificate serial or keyHash/agentId.
	ControlRevoke ControlMessageType = "revoke"
	// ControlDisconnect is a kick notification: payload contains agentId, reason, and source gateway.
	ControlDisconnect ControlMessageType = "disconnect"
	// ControlPeerSync is a state summary sync on peer join (revocation/disconnect record version).
	ControlPeerSync ControlMessageType = "peer_sync"
	// ControlDedupWindow is the control message dedup window (default 5 minutes).
	ControlDedupWindow = 5 * time.Minute
)

// ControlMessage is a control plane message between mesh nodes.
// The channel reuses inter-node mTLS; message integrity and authenticity are guaranteed by the TLS channel.
type ControlMessage struct {
	// Type is the message type (revoke / disconnect / peer_sync).
	Type ControlMessageType `json:"type"`
	// Source is the name of the originating gateway.
	Source string `json:"source"`
	// MsgID is the unique message ID (source + sequence), used for dedup and loop prevention.
	MsgID string `json:"msg_id"`
	// Timestamp is the message timestamp (Unix milliseconds).
	Timestamp int64 `json:"timestamp"`
	// Serial is the certificate serial number (optional for revoke).
	Serial string `json:"serial,omitempty"`
	// KeyHash is the SPKI hash (optional for revoke).
	KeyHash string `json:"key_hash,omitempty"`
	// AgentId is the agent identifier (revoke/disconnect).
	AgentId string `json:"agent_id,omitempty"`
	// Reason is the action reason (disconnect payload).
	Reason string `json:"reason,omitempty"`
	// Version is the state summary version number (peer_sync payload).
	Version uint64 `json:"version,omitempty"`
}

// NewControlMessage constructs a control message, automatically populating source and timestamp.
func (m *MeshManager) NewControlMessage(typ ControlMessageType) ControlMessage {
	return ControlMessage{
		Type:      typ,
		Source:    m.cfg.LocalName,
		MsgID:     m.nextControlID(),
		Timestamp: time.Now().UnixMilli(),
	}
}

// BroadcastRevoke broadcasts a revocation notification to all healthy peers.
// At least one of serial or keyHash must be provided for the remote side to locate the certificate.
func (m *MeshManager) BroadcastRevoke(serial, keyHash string) error {
	msg := m.NewControlMessage(ControlRevoke)
	msg.Serial = serial
	msg.KeyHash = keyHash
	return m.Broadcast(msg)
}

// BroadcastDisconnect broadcasts a kick notification to all healthy peers.
// The remote side matches agentId and disconnects all active sessions.
func (m *MeshManager) BroadcastDisconnect(agentId, reason string) error {
	msg := m.NewControlMessage(ControlDisconnect)
	msg.AgentId = agentId
	msg.Reason = reason
	return m.Broadcast(msg)
}

// BroadcastPeerSync broadcasts a state summary version number to all healthy peers (peer join sync).
func (m *MeshManager) BroadcastPeerSync(version uint64) error {
	msg := m.NewControlMessage(ControlPeerSync)
	msg.Version = version
	return m.Broadcast(msg)
}

// Broadcast sends a control message to all healthy peers. Each message is sent over an
// independent short-lived mTLS connection (separate from the data plane forwarding channel),
// parsed by HandleControlMessage on the remote side.
// A single peer send failure does not block other nodes; the first error is returned.
func (m *MeshManager) Broadcast(msg ControlMessage) error {
	peers := m.HealthyPeers()
	if len(peers) == 0 {
		return nil
	}
	var firstErr error
	for _, p := range peers {
		if err := m.sendControlTo(p.Address, msg); err != nil {
			m.logger.Warn("mesh: control send failed", "peer", p.Name, "type", msg.Type, "error", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// SendControl sends a single control message to a specified peer.
func (m *MeshManager) SendControl(peerName string, msg ControlMessage) error {
	pc := m.findPeerConn(peerName)
	if pc == nil {
		return fmt.Errorf("mesh: peer %q not connected", peerName)
	}
	return m.sendControlTo(pc.peer.Address, msg)
}

func (m *MeshManager) sendControlTo(addr string, msg ControlMessage) error {
	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.DialTimeout)
	defer cancel()
	dialer := &tls.Dialer{Config: m.cfg.TLSConfig}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("mesh: control dial %s: %w", addr, err)
	}
	defer conn.Close()
	if err := conn.SetWriteDeadline(time.Now().Add(m.cfg.DialTimeout)); err != nil {
		return err
	}
	return writeControlMessage(conn, msg)
}

// HandleControlMessage parses and processes a control plane message (receiver side).
// Returns nil if processed or deduplicated; returns an error if frame parsing fails.
// Messages are deduplicated by MsgID before processing; messages originating from this
// node are ignored (loop prevention).
func (m *MeshManager) HandleControlMessage(conn io.ReadWriter) error {
	msg, err := readControlMessage(conn)
	if err != nil {
		return err
	}
	if msg.Source == m.cfg.LocalName {
		m.logger.Debug("mesh: ignore self-origin control message", "type", msg.Type, "msg_id", msg.MsgID)
		return nil
	}
	if m.dedupSeen(msg.MsgID) {
		m.logger.Debug("mesh: duplicate control message ignored", "type", msg.Type, "msg_id", msg.MsgID)
		return nil
	}
	m.logger.Info("mesh: control message received", "type", msg.Type, "source", msg.Source,
		"msg_id", msg.MsgID, "serial", msg.Serial, "agent_id", msg.AgentId)
	m.ctrlMu.Lock()
	fn := m.ctrlFn
	m.ctrlMu.Unlock()
	if fn != nil {
		if err := fn(msg); err != nil {
			m.logger.Warn("mesh: control handler failed", "type", msg.Type, "error", err)
		}
	}
	return nil
}

// StartDedupCleanup periodically cleans up message IDs in the dedup table that exceed the window.
// Exits with Stop after being called. Uses ControlDedupWindow if interval <= 0.
func (m *MeshManager) StartDedupCleanup(interval time.Duration) {
	if interval <= 0 {
		interval = ControlDedupWindow
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-m.stopCh:
				return
			case <-ticker.C:
				cutoff := time.Now().Add(-ControlDedupWindow)
				m.ctrlMu.Lock()
				for id, ts := range m.ctrlDedup {
					if ts.Before(cutoff) {
						delete(m.ctrlDedup, id)
					}
				}
				m.ctrlMu.Unlock()
			}
		}
	}()
}

// writeControlMessage writes a control message: 1-byte type tag + 2-byte length + JSON.
// The type tag distinguishes it from data plane frame headers (data plane uses a 2-byte
// target length header with first byte always 0).
func writeControlMessage(w io.Writer, msg ControlMessage) error {
	payload, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal control message: %w", err)
	}
	// Frame header: magic 0xC0 + 2-byte big-endian length
	header := [3]byte{0xC0}
	binary.BigEndian.PutUint16(header[1:], uint16(len(payload)))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	_, err = w.Write(payload)
	return err
}

// readControlMessage reads a control message from a stream.
func readControlMessage(r io.Reader) (ControlMessage, error) {
	var header [3]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return ControlMessage{}, fmt.Errorf("read control header: %w", err)
	}
	if header[0] != 0xC0 {
		return ControlMessage{}, fmt.Errorf("invalid control magic 0x%02x", header[0])
	}
	length := int(binary.BigEndian.Uint16(header[1:]))
	if length == 0 || length > 1<<20 {
		return ControlMessage{}, fmt.Errorf("invalid control length %d", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return ControlMessage{}, fmt.Errorf("read control payload: %w", err)
	}
	var msg ControlMessage
	if err := json.Unmarshal(payload, &msg); err != nil {
		return ControlMessage{}, fmt.Errorf("unmarshal control message: %w", err)
	}
	if msg.Type == "" || msg.Source == "" {
		return ControlMessage{}, fmt.Errorf("control message missing type or source")
	}
	return msg, nil
}

// ServeControlListener continuously accepts and processes control connections on a listener (receiver entry point).
// Called by the gateway in the control listening goroutine; returns when the listener is closed or Stop is called.
// H3 fix: each control connection's peer certificate must carry an admin role — otherwise
// trust-domain members cannot inject revoke/disconnect messages to kick other agents laterally.
func (m *MeshManager) ServeControlListener(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			if m.stopped.Load() || errors.Is(err, net.ErrClosed) {
				return
			}
			m.logger.Warn("mesh: control accept error", "error", err)
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			tc, ok := c.(*tls.Conn)
			if !ok {
				m.logger.Warn("mesh: control connection is not TLS, rejecting", "remote", c.RemoteAddr())
				return
			}
			if err := tc.Handshake(); err != nil {
				m.logger.Warn("mesh: control handshake failed", "error", err)
				return
			}
			// H3: require admin role on the peer certificate.
			state := tc.ConnectionState()
			if len(state.PeerCertificates) == 0 {
				m.logger.Warn("mesh: control peer sent no certificate, rejecting")
				return
			}
			roles := ExtractRoles(state.PeerCertificates[0])
			if !CheckRole(roles, []string{RoleAdmin}) {
				m.logger.Warn("mesh: control peer lacks admin role, rejecting", "roles", roles)
				return
			}
			_ = m.HandleControlMessage(tc)
		}(conn)
	}
}
