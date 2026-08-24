package gw

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// AlarmRule defines a single alarm rule.
type AlarmRule struct {
	// Name is the rule name.
	Name string `json:"name"`
	// Metric is the monitoring metric name.
	Metric string `json:"metric"`
	// Operator is the threshold comparison operator (> / < / >= / <=).
	Operator string `json:"operator"`
	// Threshold is the alarm threshold value.
	Threshold float64 `json:"threshold"`
	// Cooldown is the alarm cooldown duration.
	Cooldown int `json:"cooldown_sec,omitempty"`
	// Receiver is the alarm receiver name.
	Receiver string `json:"receiver"`
}

// AlarmReceiver defines an alarm receiver.
type AlarmReceiver struct {
	// Name is the receiver name.
	Name string `json:"name"`
	// Type is the notification type (e.g., webhook).
	Type string `json:"type"`
	// Webhook is the webhook callback URL.
	Webhook string `json:"webhook"`
	// Secret is the webhook signing secret (masked).
	Secret string `json:"secret,omitempty"`
}

// AlarmConfig is the alarm configuration.
type AlarmConfig struct {
	// Rules is the list of alarm rules.
	Rules []AlarmRule `json:"rules"`
	// Receivers is the list of alarm receivers.
	Receivers []AlarmReceiver `json:"receivers"`
	// Interval is the alarm check interval.
	Interval int `json:"interval_sec,omitempty"`
}

// AlarmClient is the alarm client that periodically checks rules and sends notifications.
type AlarmClient struct {
	mu      sync.Mutex
	rules   []AlarmRule
	rcvrs   map[string]AlarmReceiver
	last    map[string]time.Time
	tick    time.Duration
	stopCh  chan struct{}
	client  *http.Client
	sources []AlarmSource
}

// AlarmSource is the alarm data source interface that provides metric names and values.
type AlarmSource interface {
	Name() string
	Value() (float64, bool)
}

// NewAlarmClient creates an AlarmClient instance.
func NewAlarmClient(cfg *AlarmConfig) *AlarmClient {
	interval := 60
	if cfg != nil && cfg.Interval > 0 {
		interval = cfg.Interval
	}
	ac := &AlarmClient{
		rcvrs:  make(map[string]AlarmReceiver),
		last:   make(map[string]time.Time),
		tick:   time.Duration(interval) * time.Second,
		stopCh: make(chan struct{}),
		client: &http.Client{Timeout: 10 * time.Second},
	}
	if cfg != nil {
		ac.rules = cfg.Rules
		for _, r := range cfg.Receivers {
			ac.rcvrs[r.Name] = r
		}
	}
	return ac
}

// AddSource registers an alarm data source.
func (a *AlarmClient) AddSource(s AlarmSource) {
	a.mu.Lock()
	a.sources = append(a.sources, s)
	a.mu.Unlock()
}

// Start starts the alarm check loop.
func (a *AlarmClient) Start(stopCh chan struct{}) {
	go func() {
		ticker := time.NewTicker(a.tick)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				a.evaluate()
			case <-stopCh:
				return
			case <-a.stopCh:
				return
			}
		}
	}()
}

// Stop stops the alarm check loop.
func (a *AlarmClient) Stop() {
	close(a.stopCh)
}

func (a *AlarmClient) evaluate() {
	a.mu.Lock()
	rules := a.rules
	sources := a.sources
	a.mu.Unlock()

	vals := make(map[string]float64)
	for _, src := range sources {
		v, ok := src.Value()
		if ok {
			vals[src.Name()] = v
		}
	}

	now := time.Now()
	a.mu.Lock()
	for _, rule := range rules {
		v, ok := vals[rule.Metric]
		if !ok {
			continue
		}
		if !a.matches(v, rule) {
			continue
		}
		key := rule.Name
		if last, ok := a.last[key]; ok && now.Sub(last) < time.Duration(rule.Cooldown)*time.Second {
			continue
		}
		a.last[key] = now

		rcv, ok := a.rcvrs[rule.Receiver]
		if !ok {
			continue
		}
		go a.send(rcv, rule, v)
	}
	a.mu.Unlock()
}

func (a *AlarmClient) matches(v float64, rule AlarmRule) bool {
	switch rule.Operator {
	case "gt":
		return v > rule.Threshold
	case "lt":
		return v < rule.Threshold
	case "gte":
		return v >= rule.Threshold
	case "lte":
		return v <= rule.Threshold
	default:
		return false
	}
}

func (a *AlarmClient) send(rcv AlarmReceiver, rule AlarmRule, val float64) {
	title := fmt.Sprintf("PKI Gateway Alert: %s", rule.Name)
	text := fmt.Sprintf("**Rule**: %s\n**Metric**: %s\n**Threshold**: %v\n**Current**: %v",
		rule.Name, rule.Metric, rule.Threshold, val)

	var body []byte
	switch rcv.Type {
	case "dingtalk":
		payload := map[string]interface{}{
			"msgtype": "markdown",
			"markdown": map[string]string{
				"title": title,
				"text":  "## " + title + "\n\n" + text,
			},
		}
		body, _ = json.Marshal(payload)
	case "slack":
		payload := map[string]string{
			"text": title + "\n\n" + text,
		}
		body, _ = json.Marshal(payload)
	case "feishu":
		payload := map[string]interface{}{
			"msg_type": "interactive",
			"card": map[string]interface{}{
				"header": map[string]interface{}{
					"title": map[string]string{"tag": "plain_text", "content": title},
				},
				"elements": []map[string]string{
					{"tag": "markdown", "content": text},
				},
			},
		}
		body, _ = json.Marshal(payload)
	default:
		log.Printf("alarm: unknown receiver type %q", rcv.Type)
		return
	}

	resp, err := a.client.Post(rcv.Webhook, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("alarm: send to %s (%s): %v", rcv.Name, rcv.Type, err)
		return
	}
	resp.Body.Close()
}

// MetricSource is a simple metric data source that stores a single name and value.
type MetricSource struct {
	name  string
	value float64
}

// Name returns the metric name.
func (m *MetricSource) Name() string { return m.name }

// Value returns the metric value.
func (m *MetricSource) Value() (float64, bool) { return m.value, true }

// NewMetricSource creates a simple metric data source.
func NewMetricSource(name string, val float64) *MetricSource {
	return &MetricSource{name: name, value: val}
}

// AggregateSource is an aggregated metric data source that manages multiple sub-metrics.
type AggregateSource struct {
	mu       sync.Mutex
	children []*MetricSource
}

// NewAggregateSource creates an aggregated metric data source.
func NewAggregateSource() *AggregateSource {
	return &AggregateSource{}
}

// Set sets or updates the value of a sub-metric.
func (a *AggregateSource) Set(name string, val float64) {
	a.mu.Lock()
	for _, c := range a.children {
		if c.name == name {
			c.value = val
			a.mu.Unlock()
			return
		}
	}
	a.children = append(a.children, NewMetricSource(name, val))
	a.mu.Unlock()
}

// Name returns the aggregate source name.
func (a *AggregateSource) Name() string { return "aggregate" }

// Value returns the aggregate source value (always returns false).
func (a *AggregateSource) Value() (float64, bool) { return 0, false }

// SnapshotSource is a snapshot metric data source that retrieves metric values via a callback function.
type SnapshotSource struct {
	mu       sync.Mutex
	snapshot func() map[string]float64
}

// NewSnapshotSource creates a snapshot metric data source.
func NewSnapshotSource(fn func() map[string]float64) *SnapshotSource {
	return &SnapshotSource{snapshot: fn}
}

// Name returns the snapshot source name.
func (s *SnapshotSource) Name() string { return "snapshot" }

// Value returns the connection metric value from the snapshot source.
func (s *SnapshotSource) Value() (float64, bool) {
	if s.snapshot == nil {
		return 0, false
	}
	vals := s.snapshot()
	for k, v := range vals {
		if strings.HasPrefix(k, "connections_") {
			return v, true
		}
	}
	return 0, false
}
