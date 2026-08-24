// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"
)

// ConfigWatcher polls a remote endpoint for configuration changes.
// Suitable for scenarios where varwof-core pushes configuration.
type ConfigWatcher struct {
	url      string
	client   *http.Client
	interval time.Duration
	onChange func([]byte) error
	lastEtag string
	stopped  atomic.Bool
	stopCh   chan struct{}
	logger   *slog.Logger
}

// NewConfigWatcher creates a configuration watcher.
// url: configuration API endpoint (e.g. https://varwof-core:4433/api/v1/gateway/config)
// tlsConfig: mTLS client certificate (for gateway→core authentication)
// interval: polling interval
// onChange: callback when configuration changes, parameter is the full configuration JSON
func NewConfigWatcher(url string, tlsConfig *tls.Config, interval time.Duration, onChange func([]byte) error) *ConfigWatcher {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
		Timeout:   30 * time.Second,
	}
	return &ConfigWatcher{
		url:      url,
		client:   client,
		interval: interval,
		onChange: onChange,
		stopCh:   make(chan struct{}),
		logger:   slog.Default().With("component", "configwatcher", "url", url),
	}
}

// Start begins polling for configuration.
func (w *ConfigWatcher) Start() {
	if w.stopped.Load() {
		return
	}
	go w.loop()
}

func (w *ConfigWatcher) loop() {
	// Initial immediate fetch
	w.fetch()
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-w.stopCh:
			return
		case <-ticker.C:
			w.fetch()
		}
	}
}

// fetch retrieves configuration and invokes the callback on changes.
func (w *ConfigWatcher) fetch() {
	req, err := http.NewRequest("GET", w.url, nil)
	if err != nil {
		w.logger.Warn("fetch: create request failed", "error", err)
		return
	}
	if w.lastEtag != "" {
		req.Header.Set("If-None-Match", w.lastEtag)
	}
	resp, err := w.client.Do(req)
	if err != nil {
		w.logger.Warn("fetch: request failed", "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		w.logger.Warn("fetch: unexpected status", "status", resp.StatusCode, "body", truncate(string(body), 200))
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		w.logger.Warn("fetch: read body failed", "error", err)
		return
	}

	// Validate that body is valid JSON
	if !json.Valid(body) {
		w.logger.Warn("fetch: invalid JSON response")
		return
	}

	etag := resp.Header.Get("ETag")
	if etag != "" {
		w.lastEtag = etag
	}

	if w.onChange != nil {
		if err := w.onChange(body); err != nil {
			w.logger.Warn("fetch: onChange callback failed", "error", err)
			return
		}
	}
	w.logger.Info("fetch: config updated")
}

// Stop stops polling.
func (w *ConfigWatcher) Stop() {
	if !w.stopped.CompareAndSwap(false, true) {
		return
	}
	close(w.stopCh)
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

// ApplyJSONConfig is a generic configuration application function for updating
// configuration objects after JSON deserialization.
// Usage example:
//
//	var cfg MyConfig
//	watcher := NewConfigWatcher(url, tlsCfg, 30*time.Second, ApplyJSONConfig(&cfg))
func ApplyJSONConfig[T any](target *T) func([]byte) error {
	return func(data []byte) error {
		return json.Unmarshal(data, target)
	}
}

// ConfigWatcherFromCLI creates a ConfigWatcher from CLI arguments (if applicable).
// Returns nil when url is empty, indicating dynamic configuration is not enabled.
func ConfigWatcherFromCLI(url string, tlsConfig *tls.Config, onChange func([]byte) error) *ConfigWatcher {
	if url == "" {
		return nil
	}
	return NewConfigWatcher(url, tlsConfig, 60*time.Second, onChange)
}
