# gateway-core Examples

## Complete mTLS Server + Audit + Metrics

```go
package main

import (
    "log"
    "net/http"
    "time"

    gw "github.com/varwof/gateway-core"
)

func main() {
    // Certificate
    cert, _ := gw.LoadCert("server.pem", "server.key")
    tlsCfg, _ := gw.MTLSServerConfig("ca.pem", cert, nil, "1.2")

    // Infrastructure
    caCert, _ := gw.LoadCACert("ca.pem")
    crlCache := gw.NewCRLCache(caCert, "http://crl.example.com/ca.crl", 1800, nil, "zh")
    ocspCache := gw.NewOCSPCache(5*time.Minute, gw.OCSPFallbackCRL, nil, "zh")
    auditLog, _ := gw.NewAuditLogger("/var/log/gateway/audit.log", nil, 100*1024*1024, 3)

    stopCh := make(chan struct{})
    go crlCache.Start(stopCh)
    defer func() { close(stopCh) }()
    defer auditLog.Close()

    // Metrics
    connTotal := gw.NewMetricCounter("gw_connections_total", "Total connections", "status")
    gw.RegisterCounter(connTotal)

    // Management API
    ms := gw.NewManagementServer(gw.ManagementServerConfig{
        Listen:      ":9090",
        TLSConfig:   tlsCfg,
        AuditLogger: auditLog,
    })
    go ms.Start()

    // Data plane server
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        peerCert := r.TLS.PeerCertificates[0]
        result := gw.RunAccessPipeline(r.TLS.PeerCertificates, &gw.PipelineConfig{
            CRLCache:   crlCache,
            OCSPCache:  ocspCache,
            AllowRoles: []string{"gateway:admin"},
            AuditLogger: auditLog,
        })
        if !result.Granted {
            connTotal.Inc("denied")
            http.Error(w, result.DenyReason, http.StatusForbidden)
            return
        }
        connTotal.Inc("allowed")
        auditLog.Log(gw.AuditEntry{
            Action:   gw.ActionProxied,
            ClientCN: peerCert.Subject.CommonName,
            Roles:    result.Roles,
        })
        w.Write([]byte("OK"))
    })

    log.Fatal(http.ListenAndServeTLS(":4433", "server.pem", "server.key", nil))
}
```

## AIC + Capability Plugins

```go
// Create the plugin registry
registry := gw.NewPluginRegistry()
registry.BuildFromConfig(gw.PluginConfigs{
    "file:access": &gw.PluginConfig{
        Type: "allowlist",
        Config: map[string]interface{}{
            "allowed":    []string{"file:read", "file:write"},
            "default_deny": true,
        },
    },
    "http:proxy": &gw.PluginConfig{
        Type: "rbac",
        Config: map[string]interface{}{
            "role_map": map[string][]string{
                "gateway:admin": {"http:proxy", "http:forward"},
                "gateway:ops":   {"http:forward"},
            },
        },
    },
})

// Admission check + plugin execution
result := gw.RunAccessPipeline(certChain, &gw.PipelineConfig{
    RequireAIC:               true,
    RequiredProtocol:         "http",
    CapabilityPluginRegistry: registry,
    AuditLogger:              auditLog,
})
```

## Short-Lived Certificate Auto-Issuance

```go
issueClient, _ := gw.NewIssueClient(gw.IssueConfig{
    CoreURL:    "https://pki-core:4433",
    CertFile:   "client.pem",
    KeyFile:    "client.key",
    CACertFile: "ca.pem",
    DefaultCA:  "issuing",
    Timeout:    10 * time.Second,
})

// One-shot issuance
result, err := gw.AutoIssueCert(issueClient.(*gw.IssueClient).Config(),
    "gateway-agent", "gateway.local")
if err != nil {
    log.Fatal(err)
}
log.Printf("certificate issued: %s -> %s", result.CN, result.CertFile)

// Periodic renewal
stopCh := make(chan struct{})
gw.RenewalLoop(issueClient.(*gw.IssueClient).Config(),
    "gateway-agent", "gateway.local",
    result.CertFile, result.KeyFile,
    2*time.Minute, 30*time.Second, stopCh,
    func() { log.Println("certificate renewed") })
```

## TSA Timestamp Signing

```go
tsaClient := gw.NewTSAClient("http://tsa.example.com")
tsaClient.SetCACert("tsa-ca.pem")
tsaClient.SetMaxTSTAge(1 * time.Hour)

// Sign an audit entry
tstDER, err := tsaClient.Sign(auditEntryJSON)
if err != nil {
    log.Printf("TSA signing failed: %v", err)
}

// Verify the timestamp
err = tsaClient.Verify(auditEntryJSON, tstDER)

// TSA proof log
proofLog, _ := gw.NewTSAProofLogger("proof.jsonl", tsaClient, auditChain, 300)
go proofLog.Start(stopCh)
```

## Alarm Notification

```go
alarmClient := gw.NewAlarmClient(&gw.AlarmConfig{
    Interval: 60,
    Rules: []gw.AlarmRule{
        {Name: "crl-fail", Metric: "crl_refresh_failures", Operator: "gt", Threshold: 0, Receiver: "ops"},
        {Name: "high-connections", Metric: "active_connections", Operator: "gt", Threshold: 1000, Receiver: "ops"},
    },
    Receivers: []gw.AlarmReceiver{
        {Name: "ops", Type: "dingtalk", Webhook: "https://oapi.dingtalk.com/robot/send?access_token=xxx"},
    },
})

// Add data sources
alarmClient.AddSource(gw.NewSnapshotSource(func() map[string]float64 {
    return map[string]float64{
        "crl_refresh_failures": float64(crlFailCount),
        "active_connections":   float64(activeConns),
    }
}))

go alarmClient.Start(stopCh)
```

## Connection Tracking + Rate Limiting

```go
tracker := gw.NewConnectionTracker()
connRegistry := gw.NewConnRegistry()

// Connection registration
removeFunc := connRegistry.Register(agentId, principalUid, func() {
    conn.Close()
})

// Rate limiting
bucket := gw.NewTokenBucket(1e6, 1e6) // 1 Mbps, 1MB burst
go func() {
    io.Copy(conn, rateLimitedReader{conn, bucket})
}()

// Disconnect a specific agent
count := connRegistry.DisconnectByAgentId(agentId)
log.Printf("disconnected %d connections", count)

// Cleanup
removeFunc()
tracker.Remove(certSerial)
```

## Config Hot Reload

```go
watcher := gw.NewConfigWatcher(
    "https://pki-core:4433/api/v1/gateway/config",
    tlsCfg,
    30*time.Second,
    func(data []byte) error {
        var newConfig Config
        if err := json.Unmarshal(data, &newConfig); err != nil {
            return err
        }
        // Apply the new configuration...
        return nil
    },
)
go watcher.Start()
```

## Audit Log Query + Analysis

```go
// Basic query
entries, _ := gw.ReadAuditEntries("/var/log/gateway/audit.log", gw.AuditFilter{
    Since:  time.Now().Add(-24 * time.Hour),
    Until:  time.Now(),
    Action: "connection_allowed",
    Limit:  100,
    Sort:   "desc",
})

// Full-text search
query := &gw.AuditIndexQuery{
    CN:    "admin@example.com",
    Since: time.Now().Add(-1 * time.Hour).Unix(),
    Limit: 50,
}
results, _ := index.Search(query)

// FTS search
ftsResults, _ := index.SearchFTS("denied connection timeout", 10)
```
