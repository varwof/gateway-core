# gateway-core 示例

## 完整 mTLS 服务器 + 审计 + 指标

```go
package main

import (
    "log"
    "net/http"
    "time"

    gw "github.com/varwof/gateway-core"
)

func main() {
    // 证书
    cert, _ := gw.LoadCert("server.pem", "server.key")
    tlsCfg, _ := gw.MTLSServerConfig("ca.pem", cert, nil, "1.2")

    // 基础设施
    caCert, _ := gw.LoadCACert("ca.pem")
    crlCache := gw.NewCRLCache(caCert, "http://crl.example.com/ca.crl", 1800, nil, "zh")
    ocspCache := gw.NewOCSPCache(5*time.Minute, gw.OCSPFallbackCRL, nil, "zh")
    auditLog, _ := gw.NewAuditLogger("/var/log/gateway/audit.log", nil, 100*1024*1024, 3)

    stopCh := make(chan struct{})
    go crlCache.Start(stopCh)
    defer func() { close(stopCh) }()
    defer auditLog.Close()

    // 指标
    connTotal := gw.NewMetricCounter("gw_connections_total", "Total connections", "status")
    gw.RegisterCounter(connTotal)

    // 管理 API
    ms := gw.NewManagementServer(gw.ManagementServerConfig{
        Listen:      ":9090",
        TLSConfig:   tlsCfg,
        AuditLogger: auditLog,
    })
    go ms.Start()

    // 数据面服务器
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

## AIC + 能力插件

```go
// 创建插件注册表
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

// 准入检查 + 插件执行
result := gw.RunAccessPipeline(certChain, &gw.PipelineConfig{
    RequireAIC:               true,
    RequiredProtocol:         "http",
    CapabilityPluginRegistry: registry,
    AuditLogger:              auditLog,
})
```

## 短命证书自动签发

```go
issueClient, _ := gw.NewIssueClient(gw.IssueConfig{
    CoreURL:    "https://pki-core:4433",
    CertFile:   "client.pem",
    KeyFile:    "client.key",
    CACertFile: "ca.pem",
    DefaultCA:  "issuing",
    Timeout:    10 * time.Second,
})

// 一键签发
result, err := gw.AutoIssueCert(issueClient.(*gw.IssueClient).Config(),
    "gateway-agent", "gateway.local")
if err != nil {
    log.Fatal(err)
}
log.Printf("证书已签发: %s -> %s", result.CN, result.CertFile)

// 定时续签
stopCh := make(chan struct{})
gw.RenewalLoop(issueClient.(*gw.IssueClient).Config(),
    "gateway-agent", "gateway.local",
    result.CertFile, result.KeyFile,
    2*time.Minute, 30*time.Second, stopCh,
    func() { log.Println("证书已续签") })
```

## TSA 时间戳签名

```go
tsaClient := gw.NewTSAClient("http://tsa.example.com")
tsaClient.SetCACert("tsa-ca.pem")
tsaClient.SetMaxTSTAge(1 * time.Hour)

// 签名审计日志
tstDER, err := tsaClient.Sign(auditEntryJSON)
if err != nil {
    log.Printf("TSA 签名失败: %v", err)
}

// 验证时间戳
err = tsaClient.Verify(auditEntryJSON, tstDER)

// TSA 证明日志
proofLog, _ := gw.NewTSAProofLogger("proof.jsonl", tsaClient, auditChain, 300)
go proofLog.Start(stopCh)
```

## 告警通知

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

// 添加数据源
alarmClient.AddSource(gw.NewSnapshotSource(func() map[string]float64 {
    return map[string]float64{
        "crl_refresh_failures": float64(crlFailCount),
        "active_connections":   float64(activeConns),
    }
}))

go alarmClient.Start(stopCh)
```

## 连接跟踪 + 限速

```go
tracker := gw.NewConnectionTracker()
connRegistry := gw.NewConnRegistry()

// 连接注册
removeFunc := connRegistry.Register(agentId, principalUid, func() {
    conn.Close()
})

// 速率限制
bucket := gw.NewTokenBucket(1e6, 1e6) // 1 Mbps, 1MB burst
go func() {
    io.Copy(conn, rateLimitedReader{conn, bucket})
}()

// 断开指定 Agent
count := connRegistry.DisconnectByAgentId(agentId)
log.Printf("已断开 %d 个连接", count)

// 清理
removeFunc()
tracker.Remove(certSerial)
```

## 配置热重载

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
        // 应用新配置...
        return nil
    },
)
go watcher.Start()
```

## 审计日志查询 + 分析

```go
// 基础查询
entries, _ := gw.ReadAuditEntries("/var/log/gateway/audit.log", gw.AuditFilter{
    Since:  time.Now().Add(-24 * time.Hour),
    Until:  time.Now(),
    Action: "connection_allowed",
    Limit:  100,
    Sort:   "desc",
})

// 全文搜索
query := &gw.AuditIndexQuery{
    CN:    "admin@example.com",
    Since: time.Now().Add(-1 * time.Hour).Unix(),
    Limit: 50,
}
results, _ := index.Search(query)

// FTS 搜索
ftsResults, _ := index.SearchFTS("denied connection timeout", 10)
```
