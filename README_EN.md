# gateway-core

> Package name: `gw` | Pure Go | No external dependencies | 32,661 lines of source (55 files) + 18,947 lines of tests (65 files)

Shared security engine library providing gateway-tcp/http/udp with unified mTLS, CRL, OCSP, TSA, RBAC, auditing, metrics, decisioning, and short-lived certificate capabilities.

---

## Module List

| Module | File | Function |
|------|------|------|
| **CRL Cache** | `crl.go` | Certificate revocation list fetching and caching, with scheduled refresh over HTTP URLs |
| **OCSP Cache** | `ocsp.go` | Online certificate status queries, TTL cache + timeout fallback |
| **TSA Client** | `tsa.go` | RFC 3161 timestamp requests and verification |
| **TSA Proof** | `tsa_proof.go` | Periodic audit proof logging, chained TSA timestamp anchoring |
| **RBAC** | `rbac.go` | Role extraction from certificate OUs and permission checks |
| **Policy File** | `policy.go` | authz.json authorization policy loading (HasGrant/RoleGrants/OU mapping) |
| **Audit Log** | `audit.go` | JSON Lines format with rotating file output |
| **Audit Index** | `audit_index.go` | Segmented index over audit logs for fast retrieval |
| **Merkle Hash Chain** | `merkle.go` | Audit log tamper protection; Merkle tree built every thousand entries |
| **Metrics** | `metrics.go` | Prometheus format: Counter, Gauge, Histogram |
| **TLS Config** | `tls.go` | MTLSServerConfig, LoadCert, LoadCA helpers |
| **Unified Protocol/TLS** | `mtls.go` | Unified `TLSConfig`/`TCPExtra`/`HTTPExtra`/`UDPExtra` + protocol/TLS constants |
| **Connection Tracking** | `tracker.go` | Per-cert connection counting and limits |
| **Masking Utilities** | `mask.go` | Sensitive data masking: certificate serials, tokens, file paths |
| **Alarming** | `alarm.go` | Alert notifications for CRL/OCSP anomalies |
| **Signal Handling** | `signal_unix.go` / `signal_windows.go` | Platform signal handling |
| **Unified Admission Pipeline** | `pipeline.go` | `RunAccessPipeline()` — one-stop CRL → OCSP → RBAC → AIC → constraints → plugin checks |
| **Idempotent Shutdown** | `stopher.go` | `StopGuard` — unified idempotent stop primitive shared across gateways |
| **Management API Framework** | `management.go` | `ManagementServer` — unified `/health`, `/metrics`, `/audit` endpoints |
| **TokenBucket Rate Limiter** | `ratelimit.go` | Generic token bucket supporting Allow/WaitN/SetRate/SetBurst |
| **Revocation Client** | `revoker.go` | Conditional revocation of unexpired certificates via mTLS API (`NeedRevoke()`) |
| **Short-Lived Certificates** | `shortlived.go` | `AutoIssueCert()` + `RenewalLoop()` — automatic issuance and scheduled renewal |
| **Confirmed Renewal** | `confirmed_renewal.go` | Confirmed renewal state machine (Idle→Awaiting→Confirmed/Rejected) + DA re-signing |
| **Connection Expiry Registry** | `connexpiry.go` | Per-certificate connection tracking + renewal marker (conditional revocation skip) |
| **AIC Parser** | `aic.go` | Agent Identity Certificate extension parsing (OID 1.3.6.1.4.1.66257.1.1) |
| **GS Parser** | `session.go` | GatewaySession extension parsing (OID 1.3.6.1.4.1.66257.1.5) |
| **PA Parser** | `user_permission.go` | PrincipalAuthorization extension parsing (OID 1.3.6.1.4.1.66257.1.2) |
| **SPIFFE** | `spiffe.go` | SPIFFE ID parsing (RFC 7555 trust domain validation) + cert SAN URI extraction |
| **Unified Decision Engine** | `decision.go` | `CheckAdmission()` — joint AIC + GS + PA checks; P∩C intersection by mode |
| **Delegation Chain** | `delegation_chain.go` | Multi-level delegation chain verification + loop protection + cert-bomb protection + capability subset + C_eff intersection |
| **Credential Bundle** | `credential_bundle.go` | Dual-chain verification (Agent chain + Principal chain) + keyHash fail-close |
| **Three-Layer Trust Model** | `trust_model.go` | `VerifyLayer1/2/3` (identity → representation → online authz) + `VerifyTrustLayers` |
| **Parameter Boundary** | `parameters.go` | Per-scheme parameter boundary validator registry (compared post P∩C) |
| **Capability Plugins** | `plugin.go` / `pluginconfig.go` | Plugin registry + 4 built-in plugins (allowlist/denylist/rbac/webhook) |
| **Policy Versioning** | `policystore.go` | Monotonic whole-policy versions + history snapshots + branch control (agent routing) |
| **Capability Registry** | `capregistry.go` / `registry.go` | Capability scheme registration (single source of truth) |
| **Risk Monitor** | `riskmonitor.go` | Behavior violation → disconnect + revoke reactive loop |
| **Mesh Control Plane** | `mesh_control.go` | Inter-node revoke/disconnect control message broadcast + dedup loop protection |
| **Task Registry** | `tasks.go` | Task ID → certificate serial mapping (X-AIC-Task-* headers) |
| **Nonce Cache** | `nonce_cache.go` | DA nonce anti-replay cache |
| **Offline RBAC** | `offline_rbac.go` | Offline/disconnected role decisions (enterprise cases 2/6) |
| **Renewal Token** | `renewal_token.go` | RenewalToken extension (OID 1.6) parsing |
| **Self Verify** | `selfverify.go` | Certificate chain self-verification helpers |
| **Stream Mux** | `streammux.go` | TCP/QUIC stream multiplexing primitives |

---

## Quick Start

```go
import gw "github.com/varwof/gateway-core"

// Create a CRL cache (refresh every 30 minutes)
caCert, _ := gw.LoadCACert("ca.pem")
crlCache := gw.NewCRLCache(caCert, "http://crl.example.com/ca.crl", 1800, nil, "zh")

// Create an OCSP cache (TTL 5 minutes)
ocspCache := gw.NewOCSPCache(5*time.Minute, "", nil, "zh")

// RBAC: extract roles from certificate OU
roles := gw.ExtractRoles(cert)
if !gw.CheckRole(roles, []string{"gateway:admin"}) {
    // Reject connection
}

// Audit log (maxSize bytes, maxBak rotation backups)
audit, _ := gw.NewAuditLogger("/var/log/pki/audit.log", nil, 100*1024*1024, 3)
audit.Log(gw.AuditEntry{
    Action:    "connection_allowed",
    ClientCN:  "user@example.com",
    Roles:     []string{"gateway:admin"},
})

// Prometheus metrics
gw.RegisterCounter(myCounter)
gw.RegisterGauge(myGauge)
gw.RegisterHistogram(myHistogram)

// TLS configuration (load certs then build mTLS server config)
cert, _ := gw.LoadCert("cert.pem", "key.pem")
tlsCfg, _ := gw.MTLSServerConfig("ca.pem", cert, nil, "1.2")
```

---

## Key Design

### CRL Cache Strategy

```
Request → check local cache
  ├── cached and not expired → return directly
  └── no cache/expired → fetch CRL over HTTP
       ├── success → update cache, return
       └── failure → return stale cache (fallback)
```

### OCSP Cache Strategy

```
Request → check local cache
  ├── valid and not expired → return OCSP status
  └── no cache/expired → query OCSP responder concurrently
       ├── success → update cache, return
       └── failure/timeout → fall back to CRL check
```

### RBAC Role Extraction

Certificate OU → role mapping rules:

| OU Prefix | Mapped Role | Description |
|---------|---------|------|
| `gateway:admin` | admin | Full control |
| `gateway:ops` | ops | Operations |
| `gateway:audit` | audit | Read-only auditing |
| `gateway:*` | wildcard | All roles |
| Other OUs | none | Access denied |

### Audit Log Format

```json
{"time":"2026-07-09T10:00:00Z","action":"connection_allowed","src_ip":"192.168.1.1",
 "client_cn":"client.example.com","client_serial":"ABCD1234","roles":["gateway:admin"],
 "mapping":"tls-proxy","target":"192.168.1.2:443","bytes_in":1024,"bytes_out":2048}
```

### Metric Naming

```
pki_gateway_{type}_{name}_total      // Counter
pki_gateway_{type}_{name}            // Gauge
pki_gateway_{type}_{name}_seconds    // Histogram
```

---

## Testing

```bash
go test -count=1 ./...
```

Current test coverage: 65 test files, 18,947 lines of test code.

## Go SDK Usage Examples

### CRL Cache

```go
import gw "github.com/varwof/gateway-core"

caCert, _ := gw.LoadCACert("ca.pem")
cache := gw.NewCRLCache(caCert, "http://crl.example.com/ca.crl", 1800, nil, "zh")

// Check whether a certificate is revoked
revoked, err := cache.IsRevoked(serialHex)
if err != nil {
    // CRL download failed, using stale cache
}
if revoked {
    // Reject connection
}
```

### OCSP Query

```go
cache := gw.NewOCSPCache(5*time.Minute, "", nil, "zh")

status, err := cache.Check(cert)
switch status {
case gw.StatusGood:
    // Certificate is valid
case gw.StatusRevoked:
    // Certificate has been revoked
case gw.StatusUnknown:
    // OCSP responder unavailable, falling back to CRL
}
```

### RBAC Checks

```go
roles := gw.ExtractRoles(clientCert)
if !gw.CheckRole(roles, []string{"gateway:admin"}) {
    // Reject, return 403
}
```

### Audit Log

```go
logger, _ := gw.NewAuditLogger("/var/log/gateway/audit.log", nil, 100*1024*1024, 3)

logger.Log(gw.AuditEntry{
    Action:  "connected",
    SrcIP:   "192.168.1.1",
    Mapping: "web-proxy",
    Target:  "192.168.1.2:443",
    ClientCN: "admin@example.com",
    Roles:   []string{"gateway:admin"},
})
```

### TLS Configuration

```go
cert, _ := gw.LoadCert("cert.pem", "key.pem")
tlsCfg, err := gw.MTLSServerConfig("ca.pem", cert, nil, "1.2")
// Returns *tls.Config ready for http.Server or tls.Listener
```

### Prometheus Metrics

```go
connTotal := gw.NewMetricCounter(
    "pki_gateway_tcp_connections_total",
    "Total TCP connections",
    "mapping", "status")
gw.RegisterCounter(connTotal)

connTotal.Inc("web-proxy", "allowed")
connTotal.Inc("web-proxy", "denied")

// Expose the /metrics endpoint
http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte(gw.RenderMetrics("# HELP pki_gateway_build_info")))
})
```

## Project Structure

```
gateway-core/
├── docs/             # User documentation
├── *.go              # Source files (flat at repository root)
├── *_test.go         # Test files
├── README.md
└── go.mod
```
