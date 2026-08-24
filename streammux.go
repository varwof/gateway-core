// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	muxStreamNew    = 0xFFFFFFFF // streamID for new stream request
	muxStreamClose  = 0xFFFFFFFE // streamID for stream close notification
	muxFrameMaxSize = 1 << 20    // 1MB max frame size
	muxReadBuffer   = 1 << 16    // 64KB read buffer per stream
	muxWriteBuffer  = 1 << 16    // 64KB write buffer per stream
)

// MuxStream implements net.Conn over a multiplexed mTLS connection.
type MuxStream struct {
	localID  uint32 // locally-assigned ID
	remoteID uint32 // remote-assigned ID (if known)
	mux      *StreamMux
	rbuf     bytes.Buffer
	rmu      sync.Mutex
	rcond    *sync.Cond
	closed   atomic.Bool
}

// LocalID returns the locally-assigned stream identifier.
func (s *MuxStream) LocalID() uint32 { return s.localID }

// RemoteID returns the remote-assigned stream identifier, or 0 if unknown.
func (s *MuxStream) RemoteID() uint32 { return s.remoteID }

// Read reads data from the stream (implements net.Conn).
func (s *MuxStream) Read(b []byte) (int, error) {
	s.rmu.Lock()
	defer s.rmu.Unlock()
	for s.rbuf.Len() == 0 {
		if s.closed.Load() {
			return 0, io.EOF
		}
		s.rcond.Wait()
	}
	return s.rbuf.Read(b)
}

// Write writes data to the stream (implements net.Conn).
func (s *MuxStream) Write(b []byte) (int, error) {
	if s.closed.Load() {
		return 0, io.EOF
	}
	// Use the remote-assigned ID for the remote end
	id := s.remoteID
	if id == 0 {
		id = s.localID
	}
	if err := s.mux.writeFrame(id, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Close closes the stream (implements net.Conn).
func (s *MuxStream) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	s.rcond.Broadcast()
	if s.mux != nil {
		id := s.remoteID
		if id == 0 {
			id = s.localID
		}
		// Non-blocking — send close frame in a goroutine to avoid deadlock
		// when Close holds the lock
		go s.mux.writeFrame(muxStreamClose, uint32ToBytes(id))
	}
	return nil
}

func uint32ToBytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

// LocalAddr returns the local address (implements net.Conn).
func (s *MuxStream) LocalAddr() net.Addr { return s.mux.conn.LocalAddr() }

// RemoteAddr returns the remote address (implements net.Conn).
func (s *MuxStream) RemoteAddr() net.Addr { return s.mux.conn.RemoteAddr() }

// SetDeadline sets the deadline (implements net.Conn, currently a no-op).
func (s *MuxStream) SetDeadline(t time.Time) error { return nil }

// SetReadDeadline sets the read deadline (implements net.Conn, currently a no-op).
func (s *MuxStream) SetReadDeadline(t time.Time) error { return nil }

// SetWriteDeadline sets the write deadline (implements net.Conn, currently a no-op).
func (s *MuxStream) SetWriteDeadline(t time.Time) error { return nil }

// StreamMux manages multiple virtual streams over a single net.Conn.
type StreamMux struct {
	conn      net.Conn
	nextID    uint32
	mu        sync.Mutex
	byLocalID map[uint32]*MuxStream // local ID → stream (outbound mapping)
	byRemID   map[uint32]*MuxStream // remote ID → stream (inbound mapping)
	readBuf   chan frame
	done      chan struct{}
	stopped   atomic.Bool
	logger    *slog.Logger
	// writeMu serializes frame writes so a header+body pair is never
	// interleaved with another frame (data or close) on the shared conn.
	writeMu sync.Mutex
}

type frame struct {
	streamID uint32
	data     []byte
}

// NewStreamMux creates a multiplexer over an existing connection.
func NewStreamMux(conn net.Conn) *StreamMux {
	m := &StreamMux{
		conn:      conn,
		nextID:    1,
		byLocalID: make(map[uint32]*MuxStream),
		byRemID:   make(map[uint32]*MuxStream),
		readBuf:   make(chan frame, 64),
		done:      make(chan struct{}),
		logger:    slog.Default().With("component", "streammux"),
	}
	go m.readLoop()
	return m
}

// Open opens a new virtual stream. Blocks until the remote accepts.
func (m *StreamMux) Open() (*MuxStream, error) {
	if m.stopped.Load() {
		return nil, fmt.Errorf("streammux: stopped")
	}
	m.mu.Lock()
	id := m.nextID
	m.nextID++
	stream := &MuxStream{
		localID: id,
		mux:     m,
	}
	stream.rcond = sync.NewCond(&stream.rmu)
	m.byLocalID[id] = stream
	m.mu.Unlock()

	req := make([]byte, 4)
	binary.BigEndian.PutUint32(req, id)
	if err := m.writeFrame(muxStreamNew, req); err != nil {
		m.removeLocal(id)
		return nil, fmt.Errorf("streammux: send new stream: %w", err)
	}
	return stream, nil
}

// Accept waits for and returns the next incoming virtual stream.
func (m *StreamMux) Accept() (*MuxStream, error) {
	for {
		select {
		case f := <-m.readBuf:
			if f.streamID == muxStreamNew {
				remoteID := binary.BigEndian.Uint32(f.data)
				m.mu.Lock()
				localID := m.nextID
				m.nextID++
				stream := &MuxStream{
					localID:  localID,
					remoteID: remoteID,
					mux:      m,
				}
				stream.rcond = sync.NewCond(&stream.rmu)
				m.byLocalID[localID] = stream
				m.byRemID[remoteID] = stream
				m.mu.Unlock()
				return stream, nil
			}
		case <-m.done:
			return nil, io.EOF
		}
	}
}

func (m *StreamMux) readLoop() {
	defer close(m.done)
	header := make([]byte, 8)
	for {
		if _, err := io.ReadFull(m.conn, header); err != nil {
			m.logger.Warn("streammux: read header failed", "error", err)
			return
		}
		streamID := binary.BigEndian.Uint32(header[:4])
		length := binary.BigEndian.Uint32(header[4:8])
		if length > muxFrameMaxSize {
			m.logger.Warn("streammux: frame too large", "size", length)
			return
		}
		data := make([]byte, length)
		if _, err := io.ReadFull(m.conn, data); err != nil {
			m.logger.Warn("streammux: read data failed", "error", err)
			return
		}

		if streamID == muxStreamNew {
			select {
			case m.readBuf <- frame{streamID: streamID, data: data}:
			default:
				m.logger.Warn("streammux: read buffer full, dropping new stream frame")
			}
			continue
		}
		if streamID == muxStreamClose {
			remID := binary.BigEndian.Uint32(data)
			m.mu.Lock()
			s := m.byRemID[remID]
			m.mu.Unlock()
			if s != nil {
				s.Close()
			}
			continue
		}

		// Dispatch data frames to the corresponding stream by remote ID
		m.mu.Lock()
		stream, ok := m.byRemID[streamID]
		m.mu.Unlock()
		if !ok || stream.closed.Load() {
			continue
		}
		stream.rmu.Lock()
		stream.rbuf.Write(data)
		stream.rmu.Unlock()
		stream.rcond.Broadcast()
	}
}

func (m *StreamMux) writeFrame(streamID uint32, data []byte) error {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	header := make([]byte, 8)
	binary.BigEndian.PutUint32(header[:4], streamID)
	binary.BigEndian.PutUint32(header[4:8], uint32(len(data)))
	if _, err := m.conn.Write(header); err != nil {
		return err
	}
	if _, err := m.conn.Write(data); err != nil {
		return err
	}
	return nil
}

func (m *StreamMux) removeLocal(id uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byLocalID[id]
	if ok {
		delete(m.byLocalID, id)
		if s.remoteID != 0 {
			delete(m.byRemID, s.remoteID)
		}
	}
}

// Close shuts down the multiplexer and all its active streams.
func (m *StreamMux) Close() error {
	if !m.stopped.CompareAndSwap(false, true) {
		return nil
	}
	m.mu.Lock()
	streams := make([]*MuxStream, 0, len(m.byLocalID))
	for _, s := range m.byLocalID {
		streams = append(streams, s)
	}
	m.mu.Unlock()
	for _, s := range streams {
		s.Close()
	}
	return m.conn.Close()
}
