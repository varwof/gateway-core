# gateway-core Quick Start

> Package name: `gw` | Go 1.26+ | Pure standard library (only golang.org/x/crypto + bolt)

## Installation

```bash
go get github.com/varwof/gateway-core
```

## Minimal Example

```go
package main

import (
    "log"
    "time"

    gw "github.com/varwof/gateway-core"
)

func main() {
    // 1. Load CA and server certificate
    caCert, err := gw.LoadCACert("ca.pem")
    if err != nil {
        log.Fatal(err)
    }
    _ = caCert

    cert, err := gw.LoadCert("server.pem", "server.key")
    if err != nil {
        log.Fatal(err)
    }

    // 2. Create mTLS server configuration
    tlsCfg, err := gw.MTLSServerConfig("ca.pem", cert, nil, "1.2")
    if err != nil {
        log.Fatal(err)
    }

    // 3. Create CRL cache
    crlCache := gw.NewCRLCache(caCert, "http://crl.example.com/ca.crl", 1800, nil, "zh")
    stopCh := make(chan struct{})
    go crlCache.Start(stopCh)

    // 4. Create OCSP cache
    ocspCache := gw.NewOCSPCache(5*time.Minute, gw.OCSPFallbackCRL, nil, "zh")

    // 5. Create audit logger
    auditLogger, _ := gw.NewAuditLogger("/var/log/gateway/audit.log", nil, 100*1024*1024, 3)
    defer auditLogger.Close()

    // 6. Register Prometheus metrics
    connTotal := gw.NewMetricCounter("gateway_connections_total", "Total connections", "status")
    gw.RegisterCounter(connTotal)

    _ = tlsCfg
    // Start your TLS server with tlsCfg...
}
```

## Running the Pipeline Check

```go
// After a client connects, run the unified admission pipeline
result := gw.RunAccessPipeline(certChain, &gw.PipelineConfig{
    CRLCache:           crlCache,
    OCSPCache:          ocspCache,
    AllowRoles:         []string{"gateway:admin", "gateway:ops"},
    MaxConnsPerCert:    100,
    RequireAIC:         true,
    RequiredProtocol:   "tcp",
})

if !result.Granted {
    log.Printf("connection denied: %s", result.DenyReason)
    return
}

log.Printf("connection allowed: principal=%s roles=%v", result.Principal, result.Roles)
```

## Common API Cheat Sheet

| Operation | Function |
|------|------|
| Load certificate | `gw.LoadCert(certFile, keyFile)` |
| Load CA | `gw.LoadCACert(caFile)` / `gw.LoadCA(caFile)` |
| mTLS configuration | `gw.MTLSServerConfig(caFile, cert, suites, version)` |
| CRL check | `gw.NewCRLCache(...)` → `cache.IsRevoked(serial)` |
| OCSP check | `gw.NewOCSPCache(...)` → `cache.Check(cert, issuer)` |
| RBAC | `gw.ExtractRoles(cert)` → `gw.CheckRole(roles, allowed)` |
| Audit | `gw.NewAuditLogger(...)` → `logger.Log(entry)` |
| Metrics | `gw.NewMetricCounter(...)` → `gw.RenderMetrics(buildInfo)` |
| Admission pipeline | `gw.RunAccessPipeline(chain, cfg)` |
| Idempotent shutdown | `gw.NewStopGuard()` → `guard.Stop()` |

## Next Steps

- [Configuration Reference](config_EN.md) — details of every configuration item
- [Function Reference](functions_EN.md) — complete function signatures
- [Usage Guide](usage_EN.md) — in-depth usage of each module
- [API Reference](api_EN.md) — full list of exported types
