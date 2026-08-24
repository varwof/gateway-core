// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// MetricCounter is a counter metric.
type MetricCounter struct {
	name   string
	help   string
	labels []string
	mu     sync.Mutex
	counts map[string]uint64
}

// NewMetricCounter creates a counter metric.
func NewMetricCounter(name, help string, labels ...string) *MetricCounter {
	return &MetricCounter{name: name, help: help, labels: labels, counts: make(map[string]uint64)}
}

// Inc increments the counter by one.
func (c *MetricCounter) Inc(labelValues ...string) {
	key := strings.Join(labelValues, "|")
	c.mu.Lock()
	c.counts[key]++
	c.mu.Unlock()
}

// Add increments the counter by the specified value.
func (c *MetricCounter) Add(n uint64, labelValues ...string) {
	key := strings.Join(labelValues, "|")
	c.mu.Lock()
	c.counts[key] += n
	c.mu.Unlock()
}

// Count returns the current count for the given label combination (for testing/observation).
func (c *MetricCounter) Count(labelValues ...string) uint64 {
	if c == nil {
		return 0
	}
	key := strings.Join(labelValues, "|")
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counts[key]
}

// MetricGauge is a gauge metric.
type MetricGauge struct {
	name   string
	help   string
	labels []string
	mu     sync.Mutex
	values map[string]int64
}

// NewMetricGauge creates a gauge metric.
func NewMetricGauge(name, help string, labels ...string) *MetricGauge {
	return &MetricGauge{name: name, help: help, labels: labels, values: make(map[string]int64)}
}

// Set sets the gauge value.
func (g *MetricGauge) Set(n int64, labelValues ...string) {
	key := strings.Join(labelValues, "|")
	g.mu.Lock()
	g.values[key] = n
	g.mu.Unlock()
}

// Add increments the gauge by the specified delta.
func (g *MetricGauge) Add(delta int64, labelValues ...string) {
	key := strings.Join(labelValues, "|")
	g.mu.Lock()
	g.values[key] += delta
	g.mu.Unlock()
}

// Value returns the current value for the given label combination (for testing/observation). Returns 0 if not set.
func (g *MetricGauge) Value(labelValues ...string) int64 {
	if g == nil {
		return 0
	}
	key := strings.Join(labelValues, "|")
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.values[key]
}

type bucket struct {
	upper float64
	count uint64
}

// MetricHistogram is a histogram metric.
type MetricHistogram struct {
	name    string
	help    string
	labels  []string
	buckets []bucket
	mu      sync.Mutex
	counts  map[string][]uint64
	sums    map[string]float64
}

// NewMetricHistogram creates a histogram metric.
func NewMetricHistogram(name, help string, labels []string, bounds ...float64) *MetricHistogram {
	b := make([]bucket, len(bounds))
	for i, v := range bounds {
		b[i] = bucket{upper: v}
	}
	return &MetricHistogram{
		name: name, help: help, labels: labels, buckets: b,
		counts: make(map[string][]uint64),
		sums:   make(map[string]float64),
	}
}

// Observe records a histogram observation.
func (h *MetricHistogram) Observe(v float64, labelValues ...string) {
	key := strings.Join(labelValues, "|")
	h.mu.Lock()
	if h.counts[key] == nil {
		h.counts[key] = make([]uint64, len(h.buckets))
	}
	for i, b := range h.buckets {
		if v <= b.upper {
			h.counts[key][i]++
		}
	}
	h.sums[key] += v
	h.mu.Unlock()
}

// DurationTracker tracks durations for latency aggregation.
type DurationTracker struct {
	count atomic.Int64
	total atomic.Int64
}

// Add records a single duration observation.
func (d *DurationTracker) Add(dur time.Duration) {
	d.count.Add(1)
	d.total.Add(dur.Microseconds())
}

// TrackDuration computes elapsed time from a start point and records it.
func TrackDuration(start time.Time, d *DurationTracker) {
	elapsed := time.Since(start)
	d.count.Add(1)
	d.total.Add(elapsed.Microseconds())
}

var registryMu sync.Mutex
var registryCounters []*MetricCounter
var registryGauges []*MetricGauge
var registryHistograms []*MetricHistogram

// RegisterCounter registers a counter in the global metric registry.
func RegisterCounter(m *MetricCounter) {
	registryMu.Lock()
	registryCounters = append(registryCounters, m)
	registryMu.Unlock()
}

// RegisterGauge registers a gauge in the global metric registry.
func RegisterGauge(m *MetricGauge) {
	registryMu.Lock()
	registryGauges = append(registryGauges, m)
	registryMu.Unlock()
}

// RegisterHistogram registers a histogram in the global metric registry.
func RegisterHistogram(m *MetricHistogram) {
	registryMu.Lock()
	registryHistograms = append(registryHistograms, m)
	registryMu.Unlock()
}

func counters() []*MetricCounter {
	registryMu.Lock()
	defer registryMu.Unlock()
	return registryCounters
}

func gauges() []*MetricGauge {
	registryMu.Lock()
	defer registryMu.Unlock()
	return registryGauges
}

func histograms() []*MetricHistogram {
	registryMu.Lock()
	defer registryMu.Unlock()
	return registryHistograms
}

// metricLabel safely returns the i-th label value, guarding against malformed
// keys with too few segments (L5: an out-of-range index previously panicked
// /metrics). Missing segments render as "?" so the export never crashes.
func metricLabel(vals []string, i int) string {
	if i < 0 || i >= len(vals) {
		return "?"
	}
	return vals[i]
}

// RenderMetrics outputs metrics in Prometheus text format.
func RenderMetrics(buildInfo string) string {
	var b strings.Builder
	b.WriteString("# HELP " + buildInfo + "\n")
	b.WriteString(buildInfo + "\n")

	for _, m := range counters() {
		m.mu.Lock()
		keys := make([]string, 0, len(m.counts))
		for k := range m.counts {
			keys = append(keys, k)
		}
		m.mu.Unlock()
		sort.Strings(keys)

		b.WriteString(fmt.Sprintf("# HELP %s %s\n", m.name, m.help))
		b.WriteString(fmt.Sprintf("# TYPE %s counter\n", m.name))
		m.mu.Lock()
		for _, k := range keys {
			vals := strings.Split(k, "|")
			b.WriteString(m.name + "{")
			for i, l := range m.labels {
				if i > 0 {
					b.WriteString(",")
				}
				b.WriteString(fmt.Sprintf("%s=%q", l, metricLabel(vals, i)))
			}
			b.WriteString(fmt.Sprintf("} %d\n", m.counts[k]))
		}
		m.mu.Unlock()
	}

	for _, m := range gauges() {
		m.mu.Lock()
		keys := make([]string, 0, len(m.values))
		for k := range m.values {
			keys = append(keys, k)
		}
		m.mu.Unlock()
		sort.Strings(keys)

		b.WriteString(fmt.Sprintf("# HELP %s %s\n", m.name, m.help))
		b.WriteString(fmt.Sprintf("# TYPE %s gauge\n", m.name))
		m.mu.Lock()
		for _, k := range keys {
			vals := strings.Split(k, "|")
			b.WriteString(m.name + "{")
			for i, l := range m.labels {
				if i > 0 {
					b.WriteString(",")
				}
				b.WriteString(fmt.Sprintf("%s=%q", l, metricLabel(vals, i)))
			}
			b.WriteString(fmt.Sprintf("} %d\n", m.values[k]))
		}
		m.mu.Unlock()
	}

	for _, m := range histograms() {
		m.mu.Lock()
		keys := make([]string, 0, len(m.counts))
		for k := range m.counts {
			keys = append(keys, k)
		}
		m.mu.Unlock()
		sort.Strings(keys)

		b.WriteString(fmt.Sprintf("# HELP %s %s\n", m.name, m.help))
		b.WriteString(fmt.Sprintf("# TYPE %s histogram\n", m.name))
		m.mu.Lock()
		for _, k := range keys {
			vals := strings.Split(k, "|")
			labels := ""
			for i, l := range m.labels {
				if i > 0 {
					labels += ","
				}
				labels += fmt.Sprintf("%s=%q", l, metricLabel(vals, i))
			}
			var cc uint64
			for i, bkt := range m.buckets {
				if i >= len(m.counts[k]) {
					break
				}
				cc += m.counts[k][i]
				b.WriteString(fmt.Sprintf("%s_bucket{%s,le=%q} %d\n", m.name, labels, fmt.Sprintf("%g", bkt.upper), cc))
			}
			b.WriteString(fmt.Sprintf("%s_bucket{%s,le=%q} %d\n", m.name, labels, "+Inf", cc))
			suffix := ""
			if labels != "" {
				suffix = "{" + labels + "}"
			}
			b.WriteString(fmt.Sprintf("%s_sum%s %g\n", m.name, suffix, m.sums[k]))
			b.WriteString(fmt.Sprintf("%s_count%s %d\n", m.name, suffix, cc))
		}
		m.mu.Unlock()
	}

	return b.String()
}

// ── AIC metrics (spec §6.4) ──

// AIC metric declarations (spec §6.4).
var (
	MetricAICAdmissionTotal    = NewMetricCounter("aic_admission_total", "Total AIC admission checks", "decision")
	MetricAICActiveAgents      = NewMetricGauge("aic_active_agents", "Currently active AIC agents")
	MetricAICCertIssuedTotal   = NewMetricCounter("aic_cert_issued_total", "Total AIC certificates issued")
	MetricAICCertRevokedTotal  = NewMetricCounter("aic_cert_revoked_total", "Total AIC certificates revoked")
	MetricAICRenewalTotal      = NewMetricCounter("aic_renewal_total", "Total AIC certificate renewals")
	MetricAICAdmissionDuration = NewMetricHistogram("aic_admission_duration_ms", "AIC admission check duration in milliseconds", []string{}, 1, 5, 10, 25, 50, 100, 250, 500, 1000)
	MetricAICBufferQueueDepth  = NewMetricGauge("aic_buffer_queue_depth", "Current AIC capability buffer queue depth")
)

func init() {
	RegisterCounter(MetricAICAdmissionTotal)
	RegisterCounter(MetricAICCertIssuedTotal)
	RegisterCounter(MetricAICCertRevokedTotal)
	RegisterCounter(MetricAICRenewalTotal)
	RegisterGauge(MetricAICActiveAgents)
	RegisterGauge(MetricAICBufferQueueDepth)
	RegisterHistogram(MetricAICAdmissionDuration)
}
