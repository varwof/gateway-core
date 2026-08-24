// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Revoker — revokes client certificates via the varwof-core API
//
// Automatically revokes short-lived certificates when connections close,
// implementing "use-and-revoke" semantics.
// Uses the gateway's own mTLS certificate for API authentication (requires gateway:revoker role).

package gw

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// RevokerConfig is the configuration for the certificate revoker.
type RevokerConfig struct {
	// CoreURL is the base URL of the varwof-core API, e.g. "https://core.varwof.com:4433/api/v1".
	CoreURL string `json:"core_url"`
	// MTLSCertFile and MTLSKeyFile are the gateway's own mTLS client certificate,
	// which must have revocation privileges (gateway:revoker role).
	MTLSCertFile string `json:"mtls_cert_file"`
	// MTLSKeyFile is the path to the mTLS client private key.
	MTLSKeyFile string `json:"mtls_key_file"`
	// CAMap maps certificate Issuer.CommonName to varwof-core's internal CA name.
	// Example: {"Varwof Issuing CA": "issuing", "Varwof Client CA": "client"}
	CAMap map[string]string `json:"ca_map"`
	// Timeout is the HTTP request timeout, default 10 seconds.
	Timeout time.Duration `json:"timeout,omitempty"`
	// RetryCount is the number of retries on revocation failure, default 2.
	RetryCount int `json:"retry_count,omitempty"`
}

// Revoker handles certificate revocation.
type Revoker struct {
	cfg      RevokerConfig
	client   *http.Client
	registry *ConnExpiryRegistry
}

// NewRevoker creates a revocation client. Returns an error if the mTLS certificate fails to load.
func NewRevoker(cfg RevokerConfig) (*Revoker, error) {
	if cfg.CoreURL == "" {
		return nil, fmt.Errorf("revoker: core_url is required")
	}
	if cfg.MTLSCertFile == "" || cfg.MTLSKeyFile == "" {
		return nil, fmt.Errorf("revoker: mtls_cert_file and mtls_key_file are required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.RetryCount <= 0 {
		cfg.RetryCount = 2
	}

	cert, err := tls.LoadX509KeyPair(cfg.MTLSCertFile, cfg.MTLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("revoker: load mTLS cert: %w", err)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		},
	}

	return &Revoker{
		cfg: cfg,
		client: &http.Client{
			Transport: tr,
			Timeout:   cfg.Timeout,
		},
	}, nil
}

// SetConnRegistry associates a ConnExpiryRegistry (P2-A-15 renewal marker linkage).
// If the registry determines a certificate should be skipped (renewed or expired), no revocation is initiated.
func (r *Revoker) SetConnRegistry(reg *ConnExpiryRegistry) {
	r.registry = reg
}

// Registry returns the associated ConnExpiryRegistry (may be nil).
func (r *Revoker) Registry() *ConnExpiryRegistry {
	return r.registry
}

// RevokeClientCert conditionally revokes the given client certificate.
// Condition: only revokes certificates that have not expired (expired certs
// don't need revocation, wasting an API call).
// If a ConnExpiryRegistry is associated and the serial number has been renewed
// (P2-A-15), revocation is also skipped.
// Extracts Issuer.CommonName from the certificate, maps it to the CA internal
// name via ca_map, then calls the varwof-core revoke API. Retries on failure
// and logs audit entries.
func (r *Revoker) RevokeClientCert(cert *x509.Certificate, audit *AuditLogger) {
	r.revoke(cert, audit, false)
}

// RevokeClientCertForced forcefully revokes the given client certificate (G2(c)).
// Unlike RevokeClientCert: bypasses the ConnExpiryRegistry renewal-marker skip
// (renewed-skip only applies to "passive disconnection revocation", i.e., the
// connection close revocation when a certificate is superseded by renewal;
// security-triggered active revocation—risk monitor kick, task completion
// revocation, admin kick—must not be allowed through by the renewed flag,
// otherwise an attacker could mark a certificate as renewed to permanently
// escape revocation). Other conditions (not-expired, ca_map, retry, audit)
// remain unchanged.
func (r *Revoker) RevokeClientCertForced(cert *x509.Certificate, audit *AuditLogger) {
	r.revoke(cert, audit, true)
}

// revoke executes revocation (force=true bypasses renewal-marker skip).
func (r *Revoker) revoke(cert *x509.Certificate, audit *AuditLogger, force bool) {
	if cert == nil {
		return
	}
	// Expired certificates are not revoked (they expire automatically)
	if !NeedRevoke(cert) {
		return
	}

	serial := NormalizeSerial(cert.SerialNumber)
	// Renewal marker linkage (P2-A-15): serial already renewed → skip revocation.
	// G2(c): only non-forced paths skip; active revocation (force=true) is not
	// allowed through by the renewal marker.
	if !force && r.registry != nil && r.registry.ShouldSkipRevoke(serial) {
		slog.Info("revoker: skip (renewed or expired)",
			"issuer_cn", cert.Issuer.CommonName,
			"serial", serial,
		)
		if audit != nil {
			audit.Log(AuditEntry{
				Action:       "revoke_skip",
				Target:       "varwof-core",
				ClientCN:     cert.Subject.CommonName,
				ClientSerial: serial,
				DenyReason:   "renewed",
			})
		}
		return
	}

	issuerCN := cert.Issuer.CommonName
	caName := r.caNameFor(issuerCN)

	if caName == "" {
		slog.Warn("revoker: no ca_map entry for issuer",
			"issuer_cn", issuerCN,
			"serial", serial,
		)
		if audit != nil {
			audit.Log(AuditEntry{
				Action:       "revoke_skip",
				Target:       "varwof-core",
				ClientCN:     cert.Subject.CommonName,
				ClientSerial: serial,
				DenyReason:   fmt.Sprintf("unknown_ca: %s", issuerCN),
			})
		}
		return
	}

	url := strings.TrimRight(r.cfg.CoreURL, "/") + "/cert/" + caName + "/" + serial + "/revoke"
	body := RevokeRequest{Reason: "superseded"}
	payload, _ := json.Marshal(body)

	var lastErr error
	for attempt := 0; attempt <= r.cfg.RetryCount; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt*500) * time.Millisecond)
		}

		resp, err := r.client.Post(url, "application/json", bytes.NewReader(payload))
		if err != nil {
			lastErr = fmt.Errorf("revoker: request failed: %w", err)
			slog.Warn("revoker: retrying", "serial", serial, "attempt", attempt, "error", lastErr)
			continue
		}

		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			slog.Info("revoker: certificate revoked",
				"serial", serial,
				"ca", caName,
				"issuer_cn", issuerCN,
			)
			if audit != nil {
				audit.Log(AuditEntry{
					Action:       "revoke_success",
					Target:       "varwof-core",
					TargetID:     fmt.Sprintf("%s/%s", caName, serial),
					ClientCN:     cert.Subject.CommonName,
					ClientSerial: serial,
				})
			}
			return
		}

		lastErr = fmt.Errorf("revoker: API returned %d: %s", resp.StatusCode, string(respBody))
		slog.Warn("revoker: unexpected status", "serial", serial, "status", resp.StatusCode, "attempt", attempt)
	}

	slog.Error("revoker: failed to revoke after retries",
		"serial", serial,
		"ca", caName,
		"error", lastErr,
	)
	if audit != nil {
		audit.Log(AuditEntry{
			Action:       "revoke_failed",
			Target:       "varwof-core",
			TargetID:     fmt.Sprintf("%s/%s", caName, serial),
			ClientCN:     cert.Subject.CommonName,
			ClientSerial: serial,
			DenyReason:   lastErr.Error(),
		})
	}
}

// RevokeRequest is the JSON body of a revocation request.
type RevokeRequest struct {
	Reason string `json:"reason,omitempty"`
}

// caNameFor looks up the CA internal name for a given Issuer.CommonName via ca_map.
// Tries exact match first, then falls back to case-insensitive match.
func (r *Revoker) caNameFor(issuerCN string) string {
	if r.cfg.CAMap == nil {
		return ""
	}
	if name, ok := r.cfg.CAMap[issuerCN]; ok {
		return name
	}
	lower := strings.ToLower(issuerCN)
	for k, v := range r.cfg.CAMap {
		if strings.ToLower(k) == lower {
			return v
		}
	}
	return ""
}

// NormalizeSerial converts a certificate serial number to standard hex format (uppercase, no 0x prefix, zero-padded to 40 characters).
func NormalizeSerial(serial *big.Int) string {
	return fmt.Sprintf("%040X", serial)
}
