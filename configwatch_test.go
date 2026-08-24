package gw

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewConfigWatcherDefaults(t *testing.T) {
	w := NewConfigWatcher("http://example.com/config", nil, 0, nil)
	if w.interval != 60*time.Second {
		t.Fatalf("expected 60s interval, got %v", w.interval)
	}
	w.Stop()
}

func TestConfigWatcherFromCLI_Empty(t *testing.T) {
	w := ConfigWatcherFromCLI("", nil, nil)
	if w != nil {
		t.Fatal("expected nil for empty URL")
	}
}

func TestConfigWatcherFromCLI_NonEmpty(t *testing.T) {
	w := ConfigWatcherFromCLI("http://core/config", nil, nil)
	if w == nil {
		t.Fatal("expected non-nil watcher")
	}
	w.Stop()
}

func TestConfigWatcherFetch(t *testing.T) {
	applied := make(chan []byte, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"key": "value"}`))
	}))
	defer server.Close()

	w := NewConfigWatcher(server.URL, nil, time.Hour, func(data []byte) error {
		applied <- data
		return nil
	})

	w.fetch()
	select {
	case data := <-applied:
		var result map[string]string
		if err := json.Unmarshal(data, &result); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if result["key"] != "value" {
			t.Fatalf("expected value, got %s", result["key"])
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for config apply")
	}
	w.Stop()
}

func TestConfigWatcherNotModified(t *testing.T) {
	calls := atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Write([]byte(`{"version": 1}`))
	}))
	defer server.Close()

	applied := make(chan []byte, 2)
	w := NewConfigWatcher(server.URL, nil, time.Hour, func(data []byte) error {
		applied <- data
		return nil
	})

	w.fetch()
	<-applied
	if calls.Load() != 1 {
		t.Fatalf("expected 1 call, got %d", calls.Load())
	}

	w.fetch()
	select {
	case <-applied:
		t.Fatal("should not apply on 304")
	case <-time.After(100 * time.Millisecond):
	}
	if calls.Load() != 2 {
		t.Fatalf("expected 2 calls, got %d", calls.Load())
	}

	w.Stop()
}

func TestConfigWatcherInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`not json`))
	}))
	defer server.Close()

	applied := make(chan []byte, 1)
	w := NewConfigWatcher(server.URL, nil, time.Hour, func(data []byte) error {
		applied <- data
		return nil
	})

	w.fetch()
	select {
	case <-applied:
		t.Fatal("should not apply invalid JSON")
	case <-time.After(100 * time.Millisecond):
	}
	w.Stop()
}

func TestConfigWatcherServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	applied := make(chan []byte, 1)
	w := NewConfigWatcher(server.URL, nil, time.Hour, func(data []byte) error {
		applied <- data
		return nil
	})

	w.fetch()
	select {
	case <-applied:
		t.Fatal("should not apply on server error")
	case <-time.After(100 * time.Millisecond):
	}
	w.Stop()
}

func TestConfigWatcherOnChangeError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"key": "value"}`))
	}))
	defer server.Close()

	w := NewConfigWatcher(server.URL, nil, time.Hour, func(data []byte) error {
		return fmt.Errorf("simulated error")
	})
	w.fetch()
	w.Stop()
}

func TestConfigWatcherStopIdempotent(t *testing.T) {
	w := NewConfigWatcher("http://example.com/config", nil, time.Hour, nil)
	w.Stop()
	w.Stop()
}

func TestTruncate(t *testing.T) {
	if truncate("hello", 3) != "hel..." {
		t.Fatalf("expected hel..., got %s", truncate("hello", 3))
	}
	if truncate("hi", 3) != "hi" {
		t.Fatalf("expected hi, got %s", truncate("hi", 3))
	}
}

func TestApplyJSONConfig(t *testing.T) {
	var cfg struct {
		Name string `json:"name"`
		Port int    `json:"port"`
	}
	apply := ApplyJSONConfig(&cfg)
	if err := apply([]byte(`{"name": "test", "port": 8080}`)); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if cfg.Name != "test" || cfg.Port != 8080 {
		t.Fatalf("expected {test 8080}, got {%s %d}", cfg.Name, cfg.Port)
	}
}

func TestApplyJSONConfig_Invalid(t *testing.T) {
	var cfg struct{ Name string }
	apply := ApplyJSONConfig(&cfg)
	if err := apply([]byte(`{bad}`)); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestConfigWatcherTLSConfig(t *testing.T) {
	cfg := &tls.Config{InsecureSkipVerify: true}
	w := NewConfigWatcher("https://example.com/config", cfg, time.Hour, nil)
	if w.client == nil {
		t.Fatal("expected non-nil client")
	}
	w.Stop()
}
