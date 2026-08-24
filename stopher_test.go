// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"testing"
	"time"
)

func TestStopGuardFirstCall(t *testing.T) {
	sg := NewStopGuard()
	if !sg.Stop() {
		t.Error("expected Stop() to return true on first call")
	}
	if !sg.IsStopped() {
		t.Error("expected IsStopped() to return true after Stop()")
	}
}

func TestStopGuardSecondCallReturnsFalse(t *testing.T) {
	sg := NewStopGuard()
	sg.Stop()
	if sg.Stop() {
		t.Error("expected Stop() to return false on second call")
	}
}

func TestStopGuardStopChanClosed(t *testing.T) {
	sg := NewStopGuard()
	ch := sg.StopChan()
	sg.Stop()
	select {
	case <-ch:
	default:
		t.Error("expected StopChan to be closed after Stop()")
	}
}

func TestStopGuardStopChanBlocksBeforeStop(t *testing.T) {
	sg := NewStopGuard()
	ch := sg.StopChan()
	select {
	case <-ch:
		t.Error("expected StopChan to block before Stop()")
	case <-time.After(10 * time.Millisecond):
	}
}

func TestStopGuardNewInstanceNotStopped(t *testing.T) {
	sg := NewStopGuard()
	if sg.IsStopped() {
		t.Error("expected new StopGuard to not be stopped")
	}
}
