# gateway-core Usage Guide

This document introduces the modules of gateway-core by use case.

## 1. TLS/mTLS Configuration

### Server-side mTLS

```go
cert, _ := gw.LoadCert("server.pem", "server.key")
tlsCfg, err := gw.MTLSServerConfig("ca.pem", cert, nil, "1.2")
if err != nil {
    log.Fatal(err)
}

ln, err := tls.Listen("tcp", ":4433", tlsCfg)
```

### Client-side mTLS

```go
tlsCfg, err := gw.ClientTLSConfig("ca.pem", "client.pem", "client.key", nil, "1.2")
if err != nil {
    log.Fatal(err)
}

conn, err := tls.Dial("tcp", "server:4433", tlsCfg)
```

### Custom Cipher Suites

```go
suites := []string{
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
}
tlsCfg, _ := gw.ServerTLSConfig(cert, suites, "1.3")
```

## 2. CRL Cache

```go
caCert, _ := gw.LoadCACert("ca.pem")
crlCache := gw.NewCRLCache(caCert, "http://crl.example.com/ca.crl", 1800, nil, "zh")

// Start background refresh
stopCh := make(chan struct{})
go crlCache.Start(stopCh)

// Check certificate revocation status
revoked, err := crlCache.IsRevoked("CN=client.example.com", serial)
if err != nil {
    log.Printf("CRL check error (using stale cache): %v", err)
}
if revoked {
    // Reject the connection
}

// View statistics
count, thisUpdate, nextUpdate := crlCache.Stats()
```

## 3. OCSP Cache

```go
ocspCache := gw.NewOCSPCache(5*time.Minute, gw.OCSPFallbackCRL, nil, "zh")

// Check certificate status
err := ocspCache.Check(clientCert, issuerCert)
if err != nil {
    switch err {
    case gw.ErrOCSPRevoked:
        // Certificate revoked
    case gw.ErrOCSPUnavailable:
        // OCSP unavailable, fell back
    default:
        log.Printf("OCSP error: %v", err)
    }
}

// Start OCSP stapling
go gw.StartOCSPStapling(tlsCert, tlsCfg, "ca.pem", stopCh, nil, "zh")
```

## 4. RBAC Role Checks

```go
// Extract roles from the certificate
roles := gw.ExtractRoles(clientCert)
// roles = ["gateway:admin"] or ["gateway:ops", "gateway:audit"]

// Check permission
if !gw.CheckRole(roles, []string{"gateway:admin", "gateway:ops"}) {
    http.Error(w, "Forbidden", http.StatusForbidden)
    return
}

// HTTP middleware
if !gw.RequireRoles(r, []string{"gateway:admin"}) {
    http.Error(w, "Forbidden", http.StatusForbidden)
    return
}
```

### Wildcards

```go
// gateway:* matches all gateway:* roles
gw.CheckRole([]string{"gateway:*"}, []string{"gateway:admin"}) // true
gw.CheckRole([]string{"gateway:*"}, []string{"gateway:ops"})   // true
```

## 5. Audit Logging

```go
logger, _ := gw.NewAuditLogger("/var/log/gateway/audit.log", nil, 100*1024*1024, 3)
defer logger.Close()

// Log a connection event
logger.Log(gw.AuditEntry{
    Time:         time.Now().Format(time.RFC3339),
    Action:       gw.ActionConnected,
    SrcIP:        "192.168.1.100",
    ClientCN:     "admin@example.com",
    ClientSerial: "ABCD1234...",
    Roles:        []string{"gateway:admin"},
    Mapping:      "web-proxy",
    Target:       "10.0.0.1:443",
    BytesIn:      1024,
    BytesOut:     2048,
})

// Audit logging with TSA timestamps
tsaClient := gw.NewTSAClient("http://tsa.example.com")
tsaClient.SetCACert("tsa-ca.pem")
loggerWithTSA, _ := gw.NewAuditLogger("/var/log/gateway/audit.log", tsaClient, 100*1024*1024, 3)

// Query audit logs
entries, _ := gw.ReadAuditEntries("/var/log/gateway/audit.log", gw.AuditFilter{
    Since:    time.Now().Add(-24 * time.Hour),
    Action:   "connection_allowed",
    ClientCN: "admin@example.com",
    Limit:    100,
})
```

## 6. Merkle Hash Chain

```go
chain := gw.NewAuditChain(1000, func(root []byte) {
    log.Printf("Merkle tree sealed, root=%x", root)
})

// Each audit entry becomes a leaf node
hash := gw.HashLeaf(entryJSON)
sealed := chain.Seal([][]byte{hash}, chain.LatestRoot())

// Verify a proof
valid, _ := chain.Verify(batchNumber, leafHash, proof)
```

## 7. Metrics

```go
// Define metrics
connTotal := gw.NewMetricCounter("gateway_connections_total", "Total connections", "status")
activeConns := gw.NewMetricGauge("gateway_active_connections", "Active connections")
latency := gw.NewMetricHistogram("gateway_request_duration_seconds", "Request latency", nil, 0.01, 0.05, 0.1, 0.5, 1.0)

// Register
gw.RegisterCounter(connTotal)
gw.RegisterGauge(activeConns)
gw.RegisterHistogram(latency)

// Use
connTotal.Inc("allowed")
activeConns.Add(1)
latency.Observe(0.042)

// Expose the /metrics endpoint
http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/plain; version=0.0.4")
    w.Write([]byte(gw.RenderMetrics("pki-gateway 1.0.0")))
})
```

## 8. Unified Admission Pipeline

```go
result := gw.RunAccessPipeline(certChain, &gw.PipelineConfig{
    CRLCache:         crlCache,
    OCSPCache:        ocspCache,
    AllowRoles:       []string{"gateway:admin", "gateway:ops"},
    RequireAIC:       true,
    RequiredProtocol: "tcp",
    MaxConnsPerCert:  100,
    AuditLogger:      auditLogger,
    NonceCache:       gw.NewNonceCache(),
    ClientIP:         clientIP,
})

if !result.Granted {
    auditLogger.Log(gw.NewAuditEntryDenied(clientIP, mapping, target, result.DenyReason, leafCert))
    conn.Close()
    return
}
```

## 9. AIC/Capability Checks

```go
// Parse the AIC extension
aic, err := gw.ParseAIC(leafCert)
if err != nil {
    log.Printf("no AIC extension: %v", err)
}

// Check capabilities
if aic.HasProtocol("tcp") {
    // TCP protocol allowed
}

if aic.CheckPermission("file:read") {
    // File read allowed
}

// Permission intersection
allowed := aic.IntersectPermissions(userPerm)
```

## 10. Idempotent Shutdown

```go
guard := gw.NewStopGuard()

// Safe to call from multiple places
go func() {
    <-guard.StopChan()
    ln.Close()
}()

go func() {
    <-guard.StopChan()
    cache.Stop()
}()

// First call returns true, subsequent calls return false
guard.Stop() // true
guard.Stop() // false
```

## 11. Management Server

```go
ms := gw.NewManagementServer(gw.ManagementServerConfig{
    Listen:        ":9090",
    TLSConfig:     tlsCfg,
    BuildInfo:     "v1.0.0",
    AuditLogger:   auditLogger,
    AuditChain:    chain,
    PluginRegistry: registry,
})

// Register custom endpoints
ms.RegisterHandler("/api/v1/gateway/custom", myHandler, "gateway:admin")

// Start
go ms.Start()
defer ms.Stop()
```

## 12. Masking Utilities

```go
gw.MaskCertSerial("ABCD1234567890")    // "****7890"
gw.MaskToken("Bearer abcdef123456")     // "Bear****56"
gw.MaskFilePath("/etc/pki/keys/cert.pem") // "/etc/pki/keys/****pem"
gw.MaskEmail("admin@example.com")       // "a*****@example.com"
gw.SanitizeString("hello\x00world")     // "helloworld"
```
