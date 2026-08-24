# gateway-core Configuration Reference

gateway-core is a library, not a standalone service. Configuration is passed through constructor parameters of each module. This document lists all configurable items.

## Common Patterns

All modules follow these conventions:

- Constructors accept a `Config` struct or discrete parameters
- `nil` parameters use default values
- `stop <-chan struct{}` or `chan struct{}` is used for graceful shutdown
- The `Translator` interface + `lang string` support i18n

## CRL Cache

```go
gw.NewCRLCache(caCert *x509.Certificate, url string, refreshSec int, translator Translator, lang string) *CRLCache
```

| Parameter | Type | Default | Description |
|------|------|--------|------|
| `caCert` | `*x509.Certificate` | required | CA certificate used to verify CRL signatures |
| `url` | `string` | required | HTTP URL of the CRL distribution point |
| `refreshSec` | `int` | 1800 | Refresh interval (seconds); 1800-3600 recommended |
| `translator` | `Translator` | `nil` | i18n translator |
| `lang` | `string` | `"zh"` | Language code |

**Cache behavior**:
- Fetches the CRL synchronously on the first `Start()`
- Then refreshes in the background every `refreshSec` seconds
- Falls back to the stale cache when a refresh fails (stale fallback)
- Refresh can be triggered manually via `ForceRefresh()`

## OCSP Cache

```go
gw.NewOCSPCache(ttl time.Duration, fallback string, translator Translator, lang string) *OCSPCache
```

| Parameter | Type | Default | Description |
|------|------|--------|------|
| `ttl` | `time.Duration` | 5m | Cache TTL |
| `fallback` | `string` | `"crl"` | Degradation strategy when the responder is unavailable |

**Fallback modes**:

| Value | Behavior |
|----|------|
| `"allow"` | Allow connections when queries fail |
| `"deny"` | Deny connections when queries fail |
| `"crl"` | Fall back to CRL checking |

## TSA Client

```go
client := gw.NewTSAClient(url string)
client.SetCACert(certFile string) error
client.SetMaxTSTAge(d time.Duration)
```

| Parameter | Default | Description |
|------|--------|------|
| `url` | required | RFC 3161 TSA service URL |
| `caCert` | none | Path to the TSA CA certificate file |
| `maxTSTAge` | 1h | Maximum timestamp age (anti-replay window) |

## Audit Log

```go
gw.NewAuditLogger(file string, tsa *TSAClient, maxSize int64, maxBak int) (*AuditLogger, error)
```

| Parameter | Type | Default | Description |
|------|------|--------|------|
| `file` | `string` | required | Audit log file path |
| `tsa` | `*TSAClient` | `nil` | TSA client (when set, every entry carries a timestamp signature) |
| `maxSize` | `int64` | 100MB | Maximum size per file (bytes) |
| `maxBak` | `int` | 3 | Number of historical files retained |

**Rotation policy**: Files rotate automatically upon reaching `maxSize`, keeping up to `maxBak` historical files.

## Audit Index

```go
gw.NewAuditIndex(path string) (*AuditIndex, error)
```

| Parameter | Description |
|------|------|
| `path` | BoltDB database file path |

## Merkle Hash Chain

```go
gw.NewAuditChain(batchSize int, onSeal func(root []byte)) *AuditChain
```

| Parameter | Default | Description |
|------|--------|------|
| `batchSize` | 1000 | Number of leaf nodes per Merkle tree |
| `onSeal` | `nil` | Callback invoked when a tree is sealed (used to trigger TSA timestamping) |

## Metrics

```go
gw.NewMetricCounter(name, help string, labels ...string) *MetricCounter
gw.NewMetricGauge(name, help string, labels ...string) *MetricGauge
gw.NewMetricHistogram(name, help string, labels []string, bounds ...float64) *MetricHistogram
```

No extra configuration. After registration, output in Prometheus format via `gw.RenderMetrics(buildInfo)`.

## TLS Configuration

```go
gw.MTLSServerConfig(caCertFile string, cert *tls.Certificate, cipherSuites []string, minTLSVersion string) (*tls.Config, error)
gw.ClientTLSConfig(caCertFile, certFile, keyFile string, cipherSuites []string, minTLSVersion string) (*tls.Config, error)
```

| Parameter | Default | Description |
|------|--------|------|
| `cipherSuites` | `nil` (secure defaults) | List of cipher suite names |
| `minTLSVersion` | `"1.2"` | Minimum TLS version |

**Available cipher suite names**: `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`, `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, `TLS_CHACHA20_POLY1305_SHA256`, etc.

## Unified Admission Pipeline

```go
gw.RunAccessPipeline(chain []*x509.Certificate, cfg *PipelineConfig) *PipelineResult
```

### PipelineConfig

| Field | Type | Default | Description |
|------|------|--------|------|
| `CRLCache` | `*CRLCache` | `nil` | CRL cache (skipped if unset) |
| `OCSPCache` | `*OCSPCache` | `nil` | OCSP cache (skipped if unset) |
| `AllowRoles` | `[]string` | `nil` | List of allowed RBAC roles |
| `CheckScope` | `PipelineCheck` | `CheckFullChain` | `CheckFullChain` or `CheckLeafOnly` |
| `MaxConnsPerCert` | `int` | 0 (unlimited) | Maximum concurrent connections per certificate |
| `RequireAIC` | `bool` | `false` | Whether the AIC extension is required |
| `RequireGS` | `bool` | `false` | Whether the GatewaySession extension is required |
| `RequiredProtocol` | `string` | `""` | Required protocol identifier |
| `RequiredCapabilities` | `[]string` | `nil` | List of required capabilities |
| `RequireUserAuth` | `bool` | `false` | Whether to verify the delegation authorization signature |
| `EnforceCapSizeConstraints` | `bool` | `false` | Whether to enforce capability size constraints |
| `EnforceSize32` | `bool` | `false` | Whether to enforce 32-byte nonces |
| `CapabilityPluginRegistry` | `*PluginRegistry` | `nil` | Capability plugin registry |
| `AuditLogger` | `*AuditLogger` | `nil` | Audit logger |
| `NonceCache` | `*NonceCache` | `nil` | Nonce anti-replay cache |
| `ClientIP` | `string` | `""` | Client IP (for GS CIDR checks) |

## Plugin Configuration

```go
registry := gw.NewPluginRegistry()
registry.BuildFromConfig(gw.PluginConfigs{
    "custom:allow": &gw.PluginConfig{
        Type: "allowlist",
        Config: map[string]interface{}{
            "allowed": []string{"cap-read", "cap-write"},
        },
    },
})
```

### Built-in Plugin Types

| Type | Description | Config fields |
|------|------|-------------|
| `allowlist` | Whitelist | `allowed []string`, `default_deny bool` |
| `denylist` | Blacklist | `denied []string`, `default_allow bool` |
| `rbac` | Role mapping | `role_map map[string][]string` |
| `webhook` | External decision | `url string`, `timeout int`, `secret string` |

## Management Server

```go
gw.NewManagementServer(gw.ManagementServerConfig{
    Listen:        ":9090",
    TLSConfig:     tlsCfg,
    BuildInfo:     "v1.0.0",
    AuditLogger:   auditLogger,
    AuditChain:    auditChain,
    PluginRegistry: registry,
})
```

### Auto-Registered Endpoints

| Endpoint | Method | Roles | Description |
|------|------|------|------|
| `/api/v1/gateway/health` | GET | public | Health check |
| `/api/v1/gateway/metrics` | GET | ops, admin | Prometheus metrics |
| `/api/v1/gateway/audit` | GET | audit, admin | Audit log query |
| `/api/v1/gateway/audit/verify` | POST | audit, admin | Merkle proof verification |
| `/api/v1/gateway/plugins` | GET | ops, admin | List plugins |
| `/api/v1/gateway/plugins/{scheme}` | GET | ops, admin | Query a specific plugin |
| `/api/v1/gateway/plugins` | PUT | admin | Replace all plugins |
| `/api/v1/gateway/plugins` | DELETE | admin | Clear all plugins |

## Short-Lived Certificate Client

```go
gw.NewIssueClient(gw.IssueConfig{
    CoreURL:            "https://pki-core:4433",
    CertFile:           "client.pem",
    KeyFile:            "client.key",
    CACertFile:         "ca.pem",
    DefaultCA:          "issuing",
    DefaultKeyType:     "ecdsa-p256",
    DefaultValidity:    10,          // default issuance validity (days), 0 = caller default (W38)
    Timeout:            10 * time.Second,
    RetryCount:         3,
    RenewalIntervalSec: 30,          // renewal polling interval (seconds), 0 = default 30s (W38)
})
```

## Alarms

```go
gw.NewAlarmClient(&gw.AlarmConfig{
    Interval: 60,
    Rules: []gw.AlarmRule{
        {Name: "crl-fail", Metric: "crl_refresh_failures", Operator: "gt", Threshold: 0, Receiver: "ops-webhook"},
    },
    Receivers: []gw.AlarmReceiver{
        {Name: "ops-webhook", Type: "dingtalk", Webhook: "https://oapi.dingtalk.com/robot/send?access_token=xxx"},
    },
})
```

**Supported alarm channels**: `dingtalk`, `slack`, `feishu`

**Operators**: `gt`, `lt`, `gte`, `lte`
