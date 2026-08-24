package gw

import (
	"crypto/tls"
	"time"
)

// ── Protocol constants ──────────────────────────────────────────────────────
// These replace the old tls_mode field which mixed transport and TLS semantics.

const (
	// Transport protocols (layer 4)
	ProtocolTCP  = "tcp"  // TCP transparent proxy
	ProtocolUDP  = "udp"  // UDP packet forwarder
	ProtocolQUIC = "quic" // QUIC transport (UDP-based, built-in TLS 1.3)

	// Application protocols over TCP (layer 7)
	ProtocolHTTP1 = "http1" // HTTP/1.1
	ProtocolHTTP2 = "http2" // HTTP/2 (TLS)
	ProtocolH2C   = "h2c"   // HTTP/2 cleartext (no TLS)
	ProtocolGRPC  = "grpc"  // gRPC (HTTP/2 + proto)
	ProtocolWS    = "ws"    // WebSocket (HTTP upgrade)
	ProtocolWSS   = "wss"   // WebSocket over TLS

	// Application protocols over UDP (layer 7)
	ProtocolDTLS = "dtls" // DTLS (Datagram TLS)
	ProtocolH3   = "h3"   // HTTP/3 (QUIC + HTTP/2 framing)
)

// ── TLS mode constants ──────────────────────────────────────────────────────
// These describe the TLS authentication mode, independent of transport.

const (
	TLSModeNone   = "none"   // No TLS (plaintext)
	TLSModeServer = "server" // Server certificate only (one-way)
	TLSModeMTLS   = "mtls"   // Mutual TLS (two-way)
)

// ── Unified TLS configuration ───────────────────────────────────────────────
// TLSConfig is the TLS/MTLS configuration shared by all gateways.
// It separates TLS concerns from transport/protocol concerns.

type TLSConfig struct {
	// Mode is the TLS authentication mode: none / server / mtls.
	Mode string `json:"mode,omitempty"`

	// CACertFile is the CA certificate file path (required for mtls mode, used to verify clients).
	CACertFile string `json:"ca_cert_file,omitempty"`

	// CertFile is the server certificate file path (required for server/mtls modes).
	CertFile string `json:"cert_file,omitempty"`

	// KeyFile is the server private key file path (required for server/mtls modes).
	KeyFile string `json:"key_file,omitempty"`

	// MinTLSVersion is the minimum TLS version (e.g. "1.2", "1.3").
	MinTLSVersion string `json:"min_tls_version,omitempty"`

	// CipherSuites is the list of TLS cipher suite names.
	CipherSuites []string `json:"cipher_suites,omitempty"`

	// ── Revocation checking ──

	// CRLURL is the CRL distribution point URL.
	CRLURL string `json:"crl_url,omitempty"`

	// CRLRefreshSec is the CRL cache refresh interval in seconds (default 300).
	CRLRefreshSec int `json:"crl_refresh_sec,omitempty"`

	// OCSPCacheTTLSec is the OCSP response cache TTL in seconds (default 300).
	OCSPCacheTTLSec int `json:"ocsp_cache_ttl_sec,omitempty"`

	// OCSPFallback is the OCSP degradation policy when unavailable: deny / allow.
	OCSPFallback string `json:"ocsp_fallback,omitempty"`

	// ── TSA ──

	// TSAURL is the TSA timestamp service URL.
	TSAURL string `json:"tsa_url,omitempty"`

	// TSACertFile is the TSA certificate file path.
	TSACertFile string `json:"tsa_cert_file,omitempty"`

	// ── Audit ──

	// AuditFile is the audit log output file path.
	AuditFile string `json:"audit_file,omitempty"`

	// AuditMaxSizeMB is the max audit log file size in MB (default 100).
	AuditMaxSizeMB int `json:"audit_max_size_mb,omitempty"`

	// AuditMaxBackups is the max number of audit log backup files to retain (default 3).
	AuditMaxBackups int `json:"audit_max_backups,omitempty"`

	// ── Connection limits ──

	// MaxConnsPerIP is the max connections per IP (0=unlimited).
	MaxConnsPerIP int `json:"max_conns_per_ip,omitempty"`

	// MaxConnsPerCert is the max connections per certificate (0=unlimited).
	MaxConnsPerCert int `json:"max_conns_per_cert,omitempty"`

	// MaxTotalConns is the global max connections (0=unlimited).
	MaxTotalConns int `json:"max_total_conns,omitempty"`

	// ── Timeouts ──

	// IdleTimeoutSec is the idle timeout in seconds (0=unlimited).
	IdleTimeoutSec int `json:"idle_timeout_sec,omitempty"`

	// ── Auth policies ──

	// RequireAIC specifies whether clients must hold an AIC certificate.
	RequireAIC *bool `json:"require_aic,omitempty"`

	// DisallowRepresentative prohibits the delegated representative mode.
	DisallowRepresentative *bool `json:"disallow_representative,omitempty"`

	// RequireUserAuth specifies whether user authentication is required.
	RequireUserAuth *bool `json:"require_user_auth,omitempty"`

	// RequireSPIFFE requires the client certificate to carry a SPIFFE ID
	// SAN URI; connections without one are rejected.
	RequireSPIFFE *bool `json:"require_spiffe,omitempty"`

	// AllowedSPIFFEIDs is an optional exact-match allowlist of SPIFFE IDs.
	AllowedSPIFFEIDs []string `json:"allowed_spiffe_ids,omitempty"`

	// SPIFFETrustDomain when non-empty requires the client SPIFFE ID to
	// belong to this trust domain (e.g. "varwof.com").
	SPIFFETrustDomain string `json:"spiffe_trust_domain,omitempty"`

	// DisconnectOnExpiry auto-disconnects when certificate expires (default true).
	DisconnectOnExpiry *bool `json:"disconnect_on_expiry,omitempty"`

	// ── RBAC ──

	// AllowRoles is the list of allowed RBAC roles.
	AllowRoles []string `json:"allow_roles,omitempty"`

	// RequiredCapabilities is the list of capabilities the client must have.
	RequiredCapabilities []string `json:"required_capabilities,omitempty"`

	// CapabilityScheme is the capability scheme ID.
	CapabilityScheme string `json:"capability_scheme,omitempty"`
}

// ── Helper methods ──

func (t *TLSConfig) DisconnectOnExpiryEnabled() bool {
	return t == nil || t.DisconnectOnExpiry == nil || *t.DisconnectOnExpiry
}

func (t *TLSConfig) RequireAICEnabled() bool {
	return t != nil && t.RequireAIC != nil && *t.RequireAIC
}

func (t *TLSConfig) DisallowRepresentativeEnabled() bool {
	if t != nil && t.DisallowRepresentative != nil {
		return *t.DisallowRepresentative
	}
	return t.RequireAICEnabled()
}

func (t *TLSConfig) RequireUserAuthEnabled() bool {
	return t != nil && t.RequireUserAuth != nil && *t.RequireUserAuth
}

func (t *TLSConfig) RequireSPIFFEEnabled() bool {
	return t != nil && t.RequireSPIFFE != nil && *t.RequireSPIFFE
}

func (t *TLSConfig) CRLRefreshDuration() time.Duration {
	if t == nil || t.CRLRefreshSec <= 0 {
		return 5 * time.Minute
	}
	return time.Duration(t.CRLRefreshSec) * time.Second
}

func (t *TLSConfig) IdleTimeout() time.Duration {
	if t == nil || t.IdleTimeoutSec <= 0 {
		return 0
	}
	return time.Duration(t.IdleTimeoutSec) * time.Second
}

func (t *TLSConfig) AuditMaxSize() int64 {
	if t == nil || t.AuditMaxSizeMB <= 0 {
		return 100 * 1024 * 1024
	}
	return int64(t.AuditMaxSizeMB) * 1024 * 1024
}

func (t *TLSConfig) AuditMaxBackupCount() int {
	if t == nil || t.AuditMaxBackups <= 0 {
		return 3
	}
	return t.AuditMaxBackups
}

// ToGoTLSConfig converts the TLSConfig to a Go tls.Config for the server side.
// This is a helper for gateways that need to build tls.Config from the JSON config.
func (t *TLSConfig) ToGoTLSConfig() *tls.Config {
	if t == nil || t.Mode == TLSModeNone {
		return nil
	}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if t.MinTLSVersion == "1.3" {
		cfg.MinVersion = tls.VersionTLS13
	}
	return cfg
}

// ── TCP-specific extensions ─────────────────────────────────────────────────
// TCPExtra holds fields unique to TCP gateways that don't apply to HTTP/UDP.

type TCPExtra struct {
	// RequireDelegation whether dual-certificate delegation mode is required (Agent + User).
	RequireDelegation *bool `json:"require_delegation,omitempty"`

	// MaxConnectionDurationSec is the max connection duration in seconds (0=unlimited).
	MaxConnectionDurationSec int `json:"max_connection_duration_sec,omitempty"`

	// SessionTimeoutSec is the session validity period in seconds (0=unlimited).
	SessionTimeoutSec int `json:"session_timeout_sec,omitempty"`

	// ConstraintRecheckSec is the periodic recheck interval for authorizationConstraints
	// in long-lived connections (0=disabled).
	ConstraintRecheckSec int `json:"constraint_recheck_sec,omitempty"`

	// HealthCheckSec is the backend health check interval in seconds (0=no check).
	HealthCheckSec int `json:"health_check_sec,omitempty"`

	// HealthCheckURL is the health check URL (HTTP mode).
	HealthCheckURL string `json:"health_check_url,omitempty"`

	// DialTimeoutSec is the backend dial timeout in seconds (default 10).
	DialTimeoutSec int `json:"dial_timeout_sec,omitempty"`

	// RenewalEnabled whether to enable auto-renewal.
	RenewalEnabled *bool `json:"renewal_enabled,omitempty"`

	// RenewalWindowSec is the renewal advance window in seconds.
	RenewalWindowSec int `json:"renewal_window_sec,omitempty"`
}

func (t *TCPExtra) RequireDelegationEnabled() bool {
	return t != nil && t.RequireDelegation != nil && *t.RequireDelegation
}

func (t *TCPExtra) RenewalEnabledOrDefault() bool {
	if t != nil && t.RenewalEnabled != nil {
		return *t.RenewalEnabled
	}
	return false
}

func (t *TCPExtra) RenewalWindow() time.Duration {
	if t != nil && t.RenewalWindowSec > 0 {
		return time.Duration(t.RenewalWindowSec) * time.Second
	}
	return 2 * time.Minute
}

func (t *TCPExtra) MaxConnectionDuration() time.Duration {
	if t == nil || t.MaxConnectionDurationSec <= 0 {
		return 0
	}
	return time.Duration(t.MaxConnectionDurationSec) * time.Second
}

func (t *TCPExtra) SessionTimeout() time.Duration {
	if t == nil || t.SessionTimeoutSec <= 0 {
		return 0
	}
	return time.Duration(t.SessionTimeoutSec) * time.Second
}

func (t *TCPExtra) ConstraintRecheckInterval() time.Duration {
	if t == nil || t.ConstraintRecheckSec <= 0 {
		return 0
	}
	return time.Duration(t.ConstraintRecheckSec) * time.Second
}

func (t *TCPExtra) HealthCheckInterval() time.Duration {
	if t == nil || t.HealthCheckSec <= 0 {
		return 0
	}
	return time.Duration(t.HealthCheckSec) * time.Second
}

func (t *TCPExtra) DialTimeout() time.Duration {
	if t == nil || t.DialTimeoutSec <= 0 {
		return 10 * time.Second
	}
	return time.Duration(t.DialTimeoutSec) * time.Second
}

// ── HTTP-specific extensions ────────────────────────────────────────────────
// HTTPExtra holds fields unique to HTTP gateways.

type HTTPExtra struct {
	// ForwardClientCert specifies whether to forward client certificates to the backend.
	ForwardClientCert *bool `json:"forward_client_cert,omitempty"`

	// ForwardClientCertDER specifies whether to pass the client certificate
	// to the backend via X-Client-Cert-DER header.
	ForwardClientCertDER *bool `json:"forward_client_cert_der,omitempty"`

	// ReadHeaderTimeoutSec is the request header read timeout in seconds (default 30).
	ReadHeaderTimeoutSec int `json:"read_header_timeout_sec,omitempty"`

	// WriteTimeoutSec is the response write timeout in seconds (default 300).
	WriteTimeoutSec int `json:"write_timeout_sec,omitempty"`

	// TLSTermination specifies whether TLS is terminated at the gateway.
	TLSTermination *bool `json:"tls_termination,omitempty"`
}

func (h *HTTPExtra) ForwardClientCertEnabled() bool {
	return h == nil || h.ForwardClientCert == nil || *h.ForwardClientCert
}

func (h *HTTPExtra) ForwardClientCertDEREnabled() bool {
	return h != nil && h.ForwardClientCertDER != nil && *h.ForwardClientCertDER
}

func (h *HTTPExtra) TLSTerminationEnabled() bool {
	return h == nil || h.TLSTermination == nil || *h.TLSTermination
}

func (h *HTTPExtra) ReadHeaderTimeout() time.Duration {
	if h == nil || h.ReadHeaderTimeoutSec <= 0 {
		return 30 * time.Second
	}
	return time.Duration(h.ReadHeaderTimeoutSec) * time.Second
}

func (h *HTTPExtra) WriteTimeout() time.Duration {
	if h == nil || h.WriteTimeoutSec <= 0 {
		return 300 * time.Second
	}
	return time.Duration(h.WriteTimeoutSec) * time.Second
}

// ── UDP-specific extensions ─────────────────────────────────────────────────
// UDPExtra holds fields unique to UDP gateways.

type UDPExtra struct {
	// RequireDelegation whether dual-certificate delegation mode is required.
	RequireDelegation *bool `json:"require_delegation,omitempty"`

	// MaxPktsPerIP is the max packets per IP per second (0=unlimited).
	MaxPktsPerIP int `json:"max_pkts_per_ip,omitempty"`

	// MaxTotalPkts is the global max total packet count (0=unlimited).
	MaxTotalPkts int `json:"max_total_pkts,omitempty"`

	// ConnectionBPS is per-connection byte-level rate limiting in bps (0=unlimited).
	ConnectionBPS int64 `json:"connection_bps,omitempty"`

	// ConnectionBurst is the token bucket burst capacity in bytes.
	ConnectionBurst int64 `json:"connection_burst,omitempty"`

	// DisconnectOnExpirySec is automatic disconnect delay on certificate expiry in seconds.
	DisconnectOnExpirySec int `json:"disconnect_on_expiry_sec,omitempty"`
}

func (u *UDPExtra) RequireDelegationEnabled() bool {
	return u != nil && u.RequireDelegation != nil && *u.RequireDelegation
}

func (u *UDPExtra) DisconnectOnExpiryEnabled() bool {
	return u != nil && u.DisconnectOnExpirySec > 0
}
