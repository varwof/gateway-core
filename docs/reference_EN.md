# gateway-core Reference Manual

## Architecture Overview

gateway-core is a pure-Go shared security engine library that provides unified security capabilities for the three gateways (TCP/HTTP/UDP).

```
┌─────────────────────────────────────────────────────┐
│                  gateway-core (gw)                  │
├─────────────────────────────────────────────────────┤
│  ┌──────────┐ ┌──────────┐ ┌──────────┐             │
│  │CRL Cache │ │OCSP Cache│ │TSA Client│             │
│  └──────────┘ └──────────┘ └──────────┘             │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐             │
│  │ RBAC     │ │Audit Log │ │ Metrics  │             │
│  └──────────┘ └──────────┘ └──────────┘             │
│  ┌──────────────────────────────────────┐           │
│  │      Unified Admission Pipeline      │           │
│  │  CRL → OCSP → RBAC → AIC → Plugins   │           │
│  └──────────────────────────────────────┘           │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐             │
│  │  Plugin  │ │   Conn   │ │   Rate   │             │
│  │  Engine  │ │ Tracking │ │  Limiter │             │
│  └──────────┘ └──────────┘ └──────────┘             │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐             │
│  │ Mgmt API │ │  Alarms  │ │   Mesh   │             │
│  └──────────┘ └──────────┘ └──────────┘             │
└─────────────────────────────────────────────────────┘
```

## Admission Pipeline Execution Order

```
1. Certificate validity check       (expired / not yet valid)
2. CRL check                        (whether the certificate is revoked)
3. OCSP check                       (online certificate status)
4. RBAC role extraction             (certificate OU → roles)
5. AIC parsing                      (Agent Identity Certificate)
6. GatewaySession                   (session constraints)
7. Capability intersection check    (AIC.Capabilities ∩ PA.Grants)
8. Delegation authorization verification (DelegationAuthorization signature)
9. GS CIDR check                    (IP allowlist)
10. Plugin execution                (Capability Plugin Registry)
→ Returns PipelineResult (Granted/Denied)
```

## Module Dependencies

```
Pipeline ──→ CRLCache
         ──→ OCSPCache
         ──→ RBAC (ExtractRoles/CheckRole)
         ──→ CheckAdmission
                ├── ParseAIC
                ├── ValidateAIC
                ├── ParseGatewaySessionExtension
                ├── VerifyDelegationAuth
                ├── CheckDAFreshness (optional, P1-B-13; AdmissionConfig.CheckDAAge)
                ├── NonceCache
                └── PrincipalAuthorization
         ──→ PluginRegistry.Execute
         ──→ AuditLogger.Log
```

## File Index

| File | Lines | Responsibility |
|------|------|------|
| `aic.go` | ~300 | AIC ASN.1 parsing + validation |
| `alarm.go` | ~200 | Alarm rules + webhook notification |
| `audit.go` | ~420 | Audit logging + rotation + query + authorization evidence fingerprints (da_hash/aic_fingerprint) |
| `audit_fts.go` | ~100 | Audit full-text search |
| `audit_index.go` | ~200 | BoltDB audit index |
| `configwatch.go` | ~100 | Config hot reload |
| `crl.go` | ~200 | CRL cache + background refresh |
| `decision.go` | ~400 | Admission decisions + delegation verification |
| `management.go` | ~300 | Management API server |
| `mask.go` | ~80 | Sensitive data masking |
| `merkle.go` | ~300 | Merkle tree + hash chain |
| `metrics.go` | ~200 | Prometheus metrics |
| `mesh.go` | ~200 | Mesh federation (health checks/forwarding) |
| `mesh_control.go` | ~180 | Mesh control-plane messages (revoke/disconnect/peer_sync broadcast + dedup loop prevention) |
| `nonce_cache.go` | ~60 | Nonce anti-replay |
| `ocsp.go` | ~250 | OCSP cache + stapling |
| `pipeline.go` | ~200 | Unified admission pipeline |
| `plugin.go` | ~150 | Plugin engine |
| `pluginconfig.go` | ~200 | Built-in plugin configuration |
| `policystore.go` | ~190 | Policy versioning/rollback (Task 5a) |
| `principal.go` | ~100 | Principal Profile |
| `ratelimit.go` | ~80 | Token bucket rate limiting |
| `registry.go` | ~100 | Connection registry |
| `renewal_token.go` | ~80 | Renewal token |
| `revoker.go` | ~120 | Certificate revocation client |
| `rbac.go` | ~100 | RBAC role checks |
| `session.go` | ~100 | GatewaySession parsing |
| `shortlived.go` | ~250 | Short-lived certificate issuance + renewal |
| `spiffe.go` | ~80 | SPIFFE ID parsing |
| `stopher.go` | ~50 | Idempotent shutdown |
| `streammux.go` | ~150 | Stream multiplexing |
| `tls.go` | ~200 | TLS/mTLS configuration |
| `tracker.go` | ~80 | Connection tracking |
| `tsa.go` | ~300 | TSA client |
| `tsa_proof.go` | ~100 | TSA proof log |
| `user_permission.go` | ~150 | PrincipalAuthorization |
| `utils.go` | ~50 | Utility functions |

## Three-Gateway Integration Pattern

Standard flow shared by the three gateways:

```go
// 1. Load configuration
cfg := LoadConfig("config.json")

// 2. Create lib infrastructure
crlCache := gw.NewCRLCache(...)
ocspCache := gw.NewOCSPCache(...)
auditLog := gw.NewAuditLogger(...)
registry := gw.NewPluginRegistry()
ms := gw.NewManagementServer(...)
guard := gw.NewStopGuard()

// 3. TLS configuration
tlsCfg, _ := gw.MTLSServerConfig(caFile, cert, nil, "1.2")

// 4. Connection handling
result := gw.RunAccessPipeline(certChain, &gw.PipelineConfig{
    CRLCache: crlCache, OCSPCache: ocspCache,
    AllowRoles: allowedRoles, AuditLogger: auditLog,
    CapabilityPluginRegistry: registry,
})
```

## Security Constraints

| Constraint | Value | Description |
|------|-----|------|
| Nonce size | 32 bytes | DelegationAuthorization.Nonce must be 32B |
| RequestedLifetime | 3600-86400 seconds | Default 3600 |
| Capability SchemeId | 1-128 bytes | |
| CapabilityId | 1-256 bytes | |
| Capability Parameters | 0-4096 bytes | |
| RenewalToken ValidityPeriod | ≤300 seconds | |
| GS MaxConcurrent | ≥1 | |
| GS HardTimeout | ≥60 seconds | |

## Predefined OIDs

| OID | Name | Purpose |
|-----|------|------|
| `1.3.6.1.4.1.66257.1.1` | AIC | Agent Identity Certificate |
| `1.3.6.1.4.1.66257.1.2` | GatewaySession | Session constraint extension |
| `1.3.6.1.4.1.66257.1.3` | OfflineRBAC | Offline RBAC extension |
| `1.3.6.1.4.1.66257.1.4` | PrincipalProfile | Identity profile |
| `1.3.6.1.4.1.66257.1.5` | UserPermission | User permission (v1.4 compatibility) |
| `1.3.6.1.4.1.66257.1.6` | RenewalToken | Renewal token |
| `1.3.6.1.4.1.66257.1.1.11` | SPIFFE | SPIFFE ID extension |
