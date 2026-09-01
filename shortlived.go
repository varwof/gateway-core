// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultRenewInterval is the default renewal check interval.
const DefaultRenewInterval = 30 * time.Second

// DefaultRenewWindow is the default renewal window (minutes before expiry).
const DefaultRenewWindow = 2 * time.Minute

// IssueConfig is the configuration for the short-lived certificate issuance client.
type IssueConfig struct {
	// CoreURL is the Varwof Core service address (e.g. https://varwof-core:4433).
	CoreURL string `json:"core_url"`
	// CertFile is the mTLS client certificate file path.
	CertFile string `json:"cert_file"`
	// KeyFile is the mTLS client private key file path.
	KeyFile string `json:"key_file"`
	// CACertFile is the CA certificate file path (for server verification).
	CACertFile string `json:"ca_cert_file,omitempty"`
	// DefaultCA is the default issuance CA name.
	DefaultCA string `json:"default_ca,omitempty"`
	// DefaultKeyType is the default key type (e.g. ecdsa-p256).
	DefaultKeyType string `json:"default_key_type,omitempty"`
	// DefaultValidity is the default issuance validity period (days), 0 = caller defaults (W38).
	DefaultValidity int `json:"default_validity,omitempty"`
	// Timeout is the HTTP request timeout.
	Timeout time.Duration `json:"timeout,omitempty"`
	// RetryCount is the number of retries on failure.
	RetryCount int `json:"retry_count,omitempty"`
	// RenewalIntervalSec is the certificate renewal polling interval (seconds), 0 = default 30s (W38).
	RenewalIntervalSec int `json:"renewal_interval_sec,omitempty"`
}

// RenewalInterval returns the certificate renewal polling interval (W38: configurable, default 30s).
func (c *IssueConfig) RenewalInterval() time.Duration {
	if c == nil || c.RenewalIntervalSec <= 0 {
		return 30 * time.Second
	}
	return time.Duration(c.RenewalIntervalSec) * time.Second
}

// IssueRequest is a short-lived certificate issuance request.
type IssueRequest struct {
	CA             string `json:"ca"`
	CN             string `json:"cn"`
	SAN            string `json:"san,omitempty"`
	Profile        string `json:"profile,omitempty"`
	KeyType        string `json:"key_type,omitempty"`
	Validity       int    `json:"validity,omitempty"`
	AgentType      *int   `json:"agent_type,omitempty"`
	AgentId        string `json:"agent_id,omitempty"`
	MarketAccessId string `json:"market_access_id,omitempty"`
	// OldSerial, when non-empty, records the certificate serial being renewed so
	// the issuer can carry a linkage back to the original (finding 4). A renewed
	// certificate is then traceable to its predecessor for revocation purposes.
	OldSerial string `json:"old_serial,omitempty"`
}

// IssueResult is the result of a short-lived certificate issuance.
type IssueResult struct {
	SerialNumber string `json:"serial_number"`
	CommonName   string `json:"common_name"`
	CertPEM      string `json:"cert_pem"`
	KeyPEM       string `json:"key_pem"`
	CA           string `json:"ca"`
	cert         *x509.Certificate
}

// Certificate parses and returns the x509.Certificate (cached).
func (r *IssueResult) Certificate() (*x509.Certificate, error) {
	if r.cert != nil {
		return r.cert, nil
	}
	cert, err := ParsePEMCert([]byte(r.CertPEM))
	if err != nil {
		return nil, err
	}
	r.cert = cert
	return cert, nil
}

// IssueClient is the short-lived certificate issuance client.
type IssueClient struct {
	cfg    IssueConfig
	client *http.Client
}

// NewIssueClient creates a short-lived certificate issuance client.
func NewIssueClient(cfg IssueConfig) (*IssueClient, error) {
	if cfg.CoreURL == "" {
		return nil, fmt.Errorf("issue: core_url is required")
	}
	if cfg.CertFile == "" || cfg.KeyFile == "" {
		return nil, fmt.Errorf("issue: cert_file and key_file are required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	if cfg.RetryCount <= 0 {
		cfg.RetryCount = 2
	}

	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("issue: load mTLS cert: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if cfg.CACertFile != "" {
		caPool, err := LoadCA(cfg.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("issue: load CA: %w", err)
		}
		tlsCfg.RootCAs = caPool
	}

	return &IssueClient{
		cfg: cfg,
		client: &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
			Timeout:   cfg.Timeout,
		},
	}, nil
}

// Issue sends a short-lived certificate issuance request.
func (c *IssueClient) Issue(req *IssueRequest) (*IssueResult, error) {
	if req.CN == "" {
		return nil, fmt.Errorf("issue: CN is required")
	}
	if req.CA == "" {
		if c.cfg.DefaultCA == "" {
			return nil, fmt.Errorf("issue: CA is required (no default configured)")
		}
		req.CA = c.cfg.DefaultCA
	}
	if req.KeyType == "" && c.cfg.DefaultKeyType != "" {
		req.KeyType = c.cfg.DefaultKeyType
	}

	url := strings.TrimRight(c.cfg.CoreURL, "/") + "/api/v1/certs"
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("issue: marshal request: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt <= c.cfg.RetryCount; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt*500) * time.Millisecond)
		}
		resp, err := c.client.Post(url, "application/json", bytes.NewReader(payload))
		if err != nil {
			lastErr = fmt.Errorf("issue: request failed: %w", err)
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			var result IssueResult
			if err := json.Unmarshal(body, &result); err != nil {
				return nil, fmt.Errorf("issue: parse response: %w", err)
			}
			return &result, nil
		}
		lastErr = fmt.Errorf("issue: API returned %d: %s", resp.StatusCode, string(body))
	}
	return nil, lastErr
}

// NeedRenew checks whether a certificate is within the renewal window.
func NeedRenew(cert *x509.Certificate, renewalWindow time.Duration) bool {
	if cert == nil {
		return true
	}
	return time.Now().Add(renewalWindow).After(cert.NotAfter)
}

// DefaultRenewPct is the renewal threshold percentage (spec P2-A-11 / P2-D-02: renewal
// is triggered when remaining validity falls below 10% of total validity).
const DefaultRenewPct = 0.10

// NeedRenewPct checks whether a certificate has entered the renewal window, taking
// the earlier of two triggers (concurrent semantics, spec P2-A-11):
//   - Percentage threshold: remaining validity ≤ total validity × pct (pct<=0 uses DefaultRenewPct)
//   - Fixed window fallback: remaining validity ≤ DefaultRenewWindow (2 minutes, prevents
//     ultra-short validity certificates from never triggering at the 10% threshold)
//
// Falls back to the fixed window when NotBefore is missing.
func NeedRenewPct(cert *x509.Certificate, pct float64) bool {
	if cert == nil {
		return true
	}
	if pct <= 0 {
		pct = DefaultRenewPct
	}
	remaining := time.Until(cert.NotAfter)
	if remaining <= DefaultRenewWindow {
		return true
	}
	if !cert.NotBefore.IsZero() {
		total := cert.NotAfter.Sub(cert.NotBefore)
		if total > 0 && remaining <= time.Duration(float64(total)*pct) {
			return true
		}
	}
	return false
}

// ParsePEMCert parses a PEM-encoded certificate.
func ParsePEMCert(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM data")
	}
	return x509.ParseCertificate(block.Bytes)
}

// AutoIssueResult is the auto-issuance result (including temp file paths).
type AutoIssueResult struct {
	CertFile string
	KeyFile  string
	CN       string
	Result   *IssueResult
}

// AutoIssueCert issues a certificate with one call and writes it to temp PEM files.
func AutoIssueCert(cfg *IssueConfig, cn, san string) (*AutoIssueResult, error) {
	client, err := NewIssueClient(*cfg)
	if err != nil {
		return nil, fmt.Errorf("auto-issue: %w", err)
	}
	req := &IssueRequest{
		CA:       cfg.DefaultCA,
		CN:       cn,
		SAN:      san,
		Validity: 10,
		Profile:  "tls-server",
	}
	result, err := client.Issue(req)
	if err != nil {
		return nil, fmt.Errorf("auto-issue: %w", err)
	}

	dir, err := os.MkdirTemp("", "pki-gateway-*")
	if err != nil {
		return nil, fmt.Errorf("auto-issue: create temp dir: %w", err)
	}
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")

	if err := os.WriteFile(certFile, []byte(result.CertPEM), 0644); err != nil {
		return nil, fmt.Errorf("auto-issue: write cert: %w", err)
	}
	if err := os.WriteFile(keyFile, []byte(result.KeyPEM), 0600); err != nil {
		return nil, fmt.Errorf("auto-issue: write key: %w", err)
	}

	return &AutoIssueResult{
		CertFile: certFile,
		KeyFile:  keyFile,
		CN:       cn,
		Result:   result,
	}, nil
}

// RenewalLoop periodically checks and automatically renews short-lived certificates.
func RenewalLoop(cfg *IssueConfig, cn, san string, certFile, keyFile string, renewWindow, checkInterval time.Duration, stopCh <-chan struct{}, onRenew func()) {
	if renewWindow <= 0 {
		renewWindow = DefaultRenewWindow
	}
	if checkInterval <= 0 {
		checkInterval = DefaultRenewInterval
	}

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	loadCert := func() *x509.Certificate {
		data, err := os.ReadFile(certFile)
		if err != nil {
			return nil
		}
		cert, err := ParsePEMCert(data)
		if err != nil {
			return nil
		}
		return cert
	}

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			cert := loadCert()
			if !NeedRenew(cert, renewWindow) {
				continue
			}

			client, err := NewIssueClient(*cfg)
			if err != nil {
				continue
			}
			req := &IssueRequest{
				CA:       cfg.DefaultCA,
				CN:       cn,
				SAN:      san,
				Validity: 10,
				Profile:  "tls-server",
			}
			result, err := client.Issue(req)
			if err != nil {
				continue
			}

			if err := os.WriteFile(certFile, []byte(result.CertPEM), 0644); err != nil {
				continue
			}
			if err := os.WriteFile(keyFile, []byte(result.KeyPEM), 0600); err != nil {
				continue
			}

			if onRenew != nil {
				onRenew()
			}
		}
	}
}
