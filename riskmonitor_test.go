// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newTestRiskRules() []RiskRule {
	return []RiskRule{
		{
			Name:          "cap-overflow",
			Signals:       []string{"cap_overflow"},
			Threshold:     3,
			WindowSeconds: 60,
			Action:        "revoke",
			Reason:        "capability overflow repeated",
		},
		{
			Name:          "out-of-window",
			Signals:       []string{"out_of_window"},
			Threshold:     1,
			WindowSeconds: 60,
			Action:        "disconnect",
			Reason:        "operation outside time window",
		},
	}
}

func TestRiskMonitorNoRuleNoTrigger(t *testing.T) {
	var fired atomic.Bool
	m := NewRiskMonitor(RiskMonitorConfig{
		Rules: nil,
		OnAction: func(_, _, _ string) {
			fired.Store(true)
		},
	})
	if m.RecordViolation(RiskViolation{AgentId: "a", Signal: "cap_overflow"}) {
		t.Fatal("should not trigger without rules")
	}
	if fired.Load() {
		t.Fatal("onAction should not be called")
	}
}

func TestRiskMonitorThresholdTriggers(t *testing.T) {
	var mu sync.Mutex
	var got []string
	m := NewRiskMonitor(RiskMonitorConfig{
		Rules: newTestRiskRules(),
		OnAction: func(agentId, action, reason string) {
			mu.Lock()
			got = append(got, agentId+":"+action+":"+reason)
			mu.Unlock()
		},
	})
	// 2 cap_overflow below threshold 3
	for i := 0; i < 2; i++ {
		if m.RecordViolation(RiskViolation{AgentId: "a1", Signal: "cap_overflow"}) {
			t.Fatal("should not trigger below threshold")
		}
	}
	if v := m.Violations("a1"); v != 2 {
		t.Fatalf("expected 2 violations, got %d", v)
	}
	// 3rd occurrence triggers revoke
	if !m.RecordViolation(RiskViolation{AgentId: "a1", Signal: "cap_overflow"}) {
		t.Fatal("should trigger at threshold")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0] != "a1:revoke:capability overflow repeated" {
		t.Fatalf("unexpected action: %v", got)
	}
	// Counter resets after trigger
	if v := m.Violations("a1"); v != 0 {
		t.Fatalf("expected reset after trigger, got %d", v)
	}
}

func TestRiskMonitorSingleHitTriggers(t *testing.T) {
	var fired atomic.Int32
	m := NewRiskMonitor(RiskMonitorConfig{
		Rules: newTestRiskRules(),
		OnAction: func(_, _, _ string) {
			fired.Add(1)
		},
	})
	// out_of_window threshold 1 → single occurrence triggers disconnect
	if !m.RecordViolation(RiskViolation{AgentId: "b1", Signal: "out_of_window"}) {
		t.Fatal("threshold 1 should trigger immediately")
	}
	if fired.Load() != 1 {
		t.Fatalf("expected 1 action, got %d", fired.Load())
	}
}

func TestRiskMonitorWindowExpiry(t *testing.T) {
	var fired atomic.Bool
	m := NewRiskMonitor(RiskMonitorConfig{
		Rules: []RiskRule{{
			Name: "slow-burn", Signals: []string{"s"}, Threshold: 2,
			WindowSeconds: 1, Action: "disconnect", Reason: "r",
		}},
		OnAction: func(_, _, _ string) {
			fired.Store(true)
		},
	})
	// 1st at t0
	m.RecordViolation(RiskViolation{AgentId: "c1", Signal: "s", At: time.Now().Unix() - 5})
	// 2nd outside window (>1s later) → old violation expired, below threshold
	m.RecordViolation(RiskViolation{AgentId: "c1", Signal: "s", At: time.Now().Unix()})
	if fired.Load() {
		t.Fatal("expired violations should not accumulate toward threshold")
	}
}

func TestRiskMonitorPerAgentIsolation(t *testing.T) {
	var fired atomic.Int32
	m := NewRiskMonitor(RiskMonitorConfig{
		Rules: newTestRiskRules(),
		OnAction: func(_, _, _ string) {
			fired.Add(1)
		},
	})
	// agent d1 triggers, agent d2 unaffected
	m.RecordViolation(RiskViolation{AgentId: "d1", Signal: "out_of_window"})
	if fired.Load() != 1 {
		t.Fatalf("d1 should trigger")
	}
	if v := m.Violations("d2"); v != 0 {
		t.Fatalf("d2 should have no violations, got %d", v)
	}
}

func TestRiskMonitorSetRulesReset(t *testing.T) {
	var fired atomic.Bool
	m := NewRiskMonitor(RiskMonitorConfig{
		Rules: newTestRiskRules(),
		OnAction: func(_, _, _ string) {
			fired.Store(true)
		},
	})
	m.RecordViolation(RiskViolation{AgentId: "e1", Signal: "cap_overflow"})
	m.RecordViolation(RiskViolation{AgentId: "e1", Signal: "cap_overflow"})
	if m.Violations("e1") != 2 {
		t.Fatalf("expected 2 before reset")
	}
	// Hot-replace rules → counter resets
	m.SetRules([]RiskRule{})
	if v := m.Violations("e1"); v != 0 {
		t.Fatalf("expected reset after SetRules, got %d", v)
	}
	if fired.Load() {
		t.Fatal("no trigger expected")
	}
}

func TestRiskMonitorNilReceiver(t *testing.T) {
	var m *RiskMonitor
	if m.RecordViolation(RiskViolation{AgentId: "x", Signal: "s"}) {
		t.Fatal("nil receiver should not trigger")
	}
	if m.Violations("x") != 0 {
		t.Fatal("nil receiver should return 0")
	}
	if m.Rules() != nil {
		t.Fatal("nil receiver Rules should be nil")
	}
	m.SetRules(nil) // no panic
}
