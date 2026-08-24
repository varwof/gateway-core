// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"strings"
	"testing"
	"time"
)

func TestCheckDAFreshness(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name    string
		ts      time.Time
		maxAge  time.Duration
		wantErr bool
	}{
		{"zero timestamp", time.Time{}, 0, true},
		{"fresh within default", now.Add(-5 * time.Second), 0, false},
		{"stale beyond default", now.Add(-61 * time.Second), 0, true},
		{"future beyond default", now.Add(61 * time.Second), 0, true},
		{"fresh custom window", now.Add(-40 * time.Second), 60 * time.Second, false},
		{"stale custom window", now.Add(-61 * time.Second), 60 * time.Second, true},
		{"exactly at boundary", now.Add(-30 * time.Second), 30 * time.Second, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := CheckDAFreshness(c.ts, now, c.maxAge)
			if c.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !c.wantErr && err != nil {
				t.Fatalf("expected nil, got %v", err)
			}
		})
	}
}

func TestCheckDAFreshness_ErrorMessages(t *testing.T) {
	if err := CheckDAFreshness(time.Time{}, time.Now(), 0); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("zero timestamp error should mention missing, got %v", err)
	}
	err := CheckDAFreshness(time.Now().Add(-10*time.Minute), time.Now(), 30*time.Second)
	if err == nil || !strings.Contains(err.Error(), "freshness window") {
		t.Fatalf("stale error should mention freshness window, got %v", err)
	}
}
