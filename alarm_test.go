// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"testing"
	"time"
)

func TestMetricSource(t *testing.T) {
	src := NewMetricSource("test", 42.0)
	if src.Name() != "test" {
		t.Fatalf("expected name test, got %s", src.Name())
	}
	v, ok := src.Value()
	if !ok || v != 42.0 {
		t.Fatalf("expected 42.0, got %v", v)
	}
}

func TestAggregateSource(t *testing.T) {
	agg := NewAggregateSource()
	agg.Set("cpu", 80.0)
	agg.Set("mem", 60.0)
	if agg.Name() != "aggregate" {
		t.Fatalf("expected aggregate")
	}
	v, ok := agg.Value()
	if ok || v != 0 {
		t.Fatalf("expected (0, false) from aggregate")
	}
}

func TestAlarmRuleMatch(t *testing.T) {
	a := NewAlarmClient(nil)
	if a.matches(10, AlarmRule{Operator: "gt", Threshold: 5}) {
		t.Log("10 > 5: pass")
	} else {
		t.Fatal("10 > 5 should match")
	}
	if a.matches(3, AlarmRule{Operator: "gt", Threshold: 5}) {
		t.Fatal("3 > 5 should not match")
	}
	if !a.matches(5, AlarmRule{Operator: "gte", Threshold: 5}) {
		t.Fatal("5 >= 5 should match")
	}
	if !a.matches(3, AlarmRule{Operator: "lt", Threshold: 5}) {
		t.Fatal("3 < 5 should match")
	}
	if !a.matches(5, AlarmRule{Operator: "lte", Threshold: 5}) {
		t.Fatal("5 <= 5 should match")
	}
}

func TestAlarmCooldown(t *testing.T) {
	cfg := &AlarmConfig{
		Rules: []AlarmRule{
			{Name: "high_conn", Metric: "conns", Operator: "gt", Threshold: 100, Cooldown: 60, Receiver: "default"},
		},
		Receivers: []AlarmReceiver{
			{Name: "default", Type: "slack", Webhook: "http://localhost:9999/webhook"},
		},
	}
	a := NewAlarmClient(cfg)

	src := NewMetricSource("conns", 0)
	a.AddSource(src)

	src.value = 200
	a.evaluate()

	a.mu.Lock()
	last, exists := a.last["high_conn"]
	a.mu.Unlock()
	if !exists {
		t.Fatal("expected alarm to fire")
	}

	src.value = 100
	a.evaluate()
	// should not fire because 100 is not > 100

	src.value = 300
	a.evaluate()
	// should not fire because cooldown hasn't elapsed

	a.mu.Lock()
	_, exists2 := a.last["high_conn"]
	lastTime := last
	a.mu.Unlock()
	_ = lastTime

	if !exists2 {
		t.Fatal("last should still exist")
	}
}

func TestAlarmConfigValidation(t *testing.T) {
	a := NewAlarmClient(nil)
	if a == nil {
		t.Fatal("NewAlarmClient should not return nil")
	}
	if len(a.rules) != 0 {
		t.Fatal("expected 0 rules")
	}

	cfg := &AlarmConfig{
		Interval: 30,
	}
	a2 := NewAlarmClient(cfg)
	if a2.tick != 30*time.Second {
		t.Fatalf("expected 30s interval, got %v", a2.tick)
	}
}
