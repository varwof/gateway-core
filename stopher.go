// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import "sync/atomic"

// StopGuard is a unified idempotent shutdown guard.
type StopGuard struct {
	stopped atomic.Bool
	stopCh  chan struct{}
}

// NewStopGuard creates a stop guard.
func NewStopGuard() *StopGuard {
	return &StopGuard{stopCh: make(chan struct{})}
}

// Stop triggers shutdown (idempotent, returns whether it was the first call).
func (s *StopGuard) Stop() bool {
	if s.stopped.Load() {
		return false
	}
	s.stopped.Store(true)
	close(s.stopCh)
	return true
}

// StopChan returns the stop signal channel.
func (s *StopGuard) StopChan() <-chan struct{} {
	return s.stopCh
}

// IsStopped checks whether shutdown has been triggered.
func (s *StopGuard) IsStopped() bool {
	return s.stopped.Load()
}

// Reset resets the stopped state (for testing or post-renewal use only).
func (s *StopGuard) Reset() {
	s.stopped.Store(false)
	s.stopCh = make(chan struct{})
}
