// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMetricCounter(t *testing.T) {
	c := NewMetricCounter("test_counter", "test help", "label1")
	c.Inc("a")
	c.Inc("a")
	c.Add(3, "b")
	if got := c.counts["a"]; got != 2 {
		t.Fatalf("expected count 2 for a, got %d", got)
	}
	if got := c.counts["b"]; got != 3 {
		t.Fatalf("expected count 3 for b, got %d", got)
	}
}

func TestMetricCounterConcurrent(t *testing.T) {
	c := NewMetricCounter("concurrent", "test")
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Inc("x")
		}()
	}
	wg.Wait()
	if got := c.counts["x"]; got != 100 {
		t.Fatalf("expected 100, got %d", got)
	}
}

func TestMetricGauge(t *testing.T) {
	g := NewMetricGauge("test_gauge", "test help", "label1")
	g.Set(42, "a")
	g.Add(-10, "a")
	if got := g.values["a"]; got != 32 {
		t.Fatalf("expected 32, got %d", got)
	}
}

func TestMetricGaugeConcurrent(t *testing.T) {
	g := NewMetricGauge("concurrent_gauge", "test")
	var wg sync.WaitGroup
	for i := int64(0); i < 100; i++ {
		wg.Add(1)
		go func(delta int64) {
			defer wg.Done()
			g.Add(delta, "x")
		}(i)
	}
	wg.Wait()
	if got := g.values["x"]; got != 4950 {
		t.Fatalf("expected 4950, got %d", got)
	}
}

func TestMetricHistogram(t *testing.T) {
	h := NewMetricHistogram("test_hist", "test help", nil, 0.5, 1.0, 2.0)
	h.Observe(0.3, "a")
	h.Observe(0.8, "a")
	h.Observe(1.5, "a")
	h.Observe(3.0, "a")

	buckets := h.counts["a"]
	if len(buckets) != 3 {
		t.Fatalf("expected 3 buckets, got %d", len(buckets))
	}
	if buckets[0] != 1 {
		t.Fatalf("bucket 0 (0.5): expected 1, got %d", buckets[0])
	}
	if buckets[1] != 2 {
		t.Fatalf("bucket 1 (1.0): expected 2, got %d", buckets[1])
	}
	if buckets[2] != 3 {
		t.Fatalf("bucket 2 (2.0): expected 3, got %d", buckets[2])
	}
	if h.sums["a"] != 5.6 {
		t.Fatalf("sum: expected 5.6, got %g", h.sums["a"])
	}
}

func TestDurationTracker(t *testing.T) {
	d := &DurationTracker{}
	d.Add(100 * time.Millisecond)
	d.Add(200 * time.Millisecond)
	if d.count.Load() != 2 {
		t.Fatalf("expected count 2, got %d", d.count.Load())
	}

	start := time.Now()
	TrackDuration(start, d)
	if d.count.Load() != 3 {
		t.Fatalf("expected count 3 after TrackDuration, got %d", d.count.Load())
	}
}

func TestRenderMetrics(t *testing.T) {
	c := NewMetricCounter("req_total", "total requests", "method")
	c.Inc("GET")
	c.Inc("POST")
	RegisterCounter(c)

	g := NewMetricGauge("conn_active", "active connections", "proto")
	g.Set(5, "tcp")
	RegisterGauge(g)

	h := NewMetricHistogram("latency_ms", "latency in ms", nil, 100, 500)
	h.Observe(50, "")
	RegisterHistogram(h)

	output := RenderMetrics("# BUILD info")

	if !strings.Contains(output, "# HELP req_total") {
		t.Fatal("missing HELP for req_total")
	}
	if !strings.Contains(output, "# TYPE req_total counter") {
		t.Fatal("missing TYPE counter")
	}
	if !strings.Contains(output, `req_total{method="GET"} 1`) {
		t.Fatal("missing GET counter")
	}
	if !strings.Contains(output, `req_total{method="POST"} 1`) {
		t.Fatal("missing POST counter")
	}
	if !strings.Contains(output, `conn_active{proto="tcp"} 5`) {
		t.Fatal("missing gauge value")
	}
	if !strings.Contains(output, "latency_ms_bucket") {
		t.Fatal("missing histogram bucket")
	}
	if !strings.Contains(output, "latency_ms_sum") {
		t.Fatal("missing histogram sum")
	}
	if !strings.Contains(output, "latency_ms_count") {
		t.Fatal("missing histogram count")
	}
}

// TestRenderMetricsMalformedKey verifies L5: a malformed key with too few
// '|'-separated segments must not panic during render; missing labels render
// as "?".
func TestRenderMetricsMalformedKey(t *testing.T) {
	c := NewMetricCounter("bad_total", "bad", "a", "b")
	// key has only one segment but two labels -> out-of-range previously panicked
	c.Inc("onlyone")
	RegisterCounter(c)

	g := NewMetricGauge("badg", "badg", "x", "y")
	g.Set(1, "solo")
	RegisterGauge(g)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("RenderMetrics panicked on malformed key: %v", r)
		}
	}()
	output := RenderMetrics("# BUILD")
	if !strings.Contains(output, `bad_total{a="onlyone",b="?"} 1`) {
		t.Fatalf("malformed-key counter not rendered safely:\n%s", output)
	}
}
