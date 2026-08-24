# gateway-core 使用指南

本文档按使用场景介绍 gateway-core 的各模块。

## 1. TLS/mTLS 配置

### 服务端 mTLS

```go
cert, _ := gw.LoadCert("server.pem", "server.key")
tlsCfg, err := gw.MTLSServerConfig("ca.pem", cert, nil, "1.2")
if err != nil {
    log.Fatal(err)
}

ln, err := tls.Listen("tcp", ":4433", tlsCfg)
```

### 客户端 mTLS

```go
tlsCfg, err := gw.ClientTLSConfig("ca.pem", "client.pem", "client.key", nil, "1.2")
if err != nil {
    log.Fatal(err)
}

conn, err := tls.Dial("tcp", "server:4433", tlsCfg)
```

### 自定义密码套件

```go
suites := []string{
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
}
tlsCfg, _ := gw.ServerTLSConfig(cert, suites, "1.3")
```

## 2. CRL 缓存

```go
caCert, _ := gw.LoadCACert("ca.pem")
crlCache := gw.NewCRLCache(caCert, "http://crl.example.com/ca.crl", 1800, nil, "zh")

// 启动后台刷新
stopCh := make(chan struct{})
go crlCache.Start(stopCh)

// 检查证书吊销状态
revoked, err := crlCache.IsRevoked("CN=client.example.com", serial)
if err != nil {
    log.Printf("CRL 检查错误（使用旧缓存）: %v", err)
}
if revoked {
    // 拒绝连接
}

// 查看统计信息
count, thisUpdate, nextUpdate := crlCache.Stats()
```

## 3. OCSP 缓存

```go
ocspCache := gw.NewOCSPCache(5*time.Minute, gw.OCSPFallbackCRL, nil, "zh")

// 检查证书状态
err := ocspCache.Check(clientCert, issuerCert)
if err != nil {
    switch err {
    case gw.ErrOCSPRevoked:
        // 证书已吊销
    case gw.ErrOCSPUnavailable:
        // OCSP 不可用，已 fallback
    default:
        log.Printf("OCSP 错误: %v", err)
    }
}

// 启动 OCSP Stapling
go gw.StartOCSPStapling(tlsCert, tlsCfg, "ca.pem", stopCh, nil, "zh")
```

## 4. RBAC 角色检查

```go
// 从证书提取角色
roles := gw.ExtractRoles(clientCert)
// roles = ["gateway:admin"] 或 ["gateway:ops", "gateway:audit"]

// 检查是否有权限
if !gw.CheckRole(roles, []string{"gateway:admin", "gateway:ops"}) {
    http.Error(w, "Forbidden", http.StatusForbidden)
    return
}

// HTTP 中间件
if !gw.RequireRoles(r, []string{"gateway:admin"}) {
    http.Error(w, "Forbidden", http.StatusForbidden)
    return
}
```

### 通配符

```go
// gateway:* 匹配所有 gateway:* 角色
gw.CheckRole([]string{"gateway:*"}, []string{"gateway:admin"}) // true
gw.CheckRole([]string{"gateway:*"}, []string{"gateway:ops"})   // true
```

## 5. 审计日志

```go
logger, _ := gw.NewAuditLogger("/var/log/gateway/audit.log", nil, 100*1024*1024, 3)
defer logger.Close()

// 记录连接事件
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

// 带 TSA 时间戳的审计日志
tsaClient := gw.NewTSAClient("http://tsa.example.com")
tsaClient.SetCACert("tsa-ca.pem")
loggerWithTSA, _ := gw.NewAuditLogger("/var/log/gateway/audit.log", tsaClient, 100*1024*1024, 3)

// 查询审计日志
entries, _ := gw.ReadAuditEntries("/var/log/gateway/audit.log", gw.AuditFilter{
    Since:    time.Now().Add(-24 * time.Hour),
    Action:   "connection_allowed",
    ClientCN: "admin@example.com",
    Limit:    100,
})
```

## 6. Merkle 哈希链

```go
chain := gw.NewAuditChain(1000, func(root []byte) {
    log.Printf("Merkle 树封存, root=%x", root)
})

// 每条审计日志作为叶节点
hash := gw.HashLeaf(entryJSON)
sealed := chain.Seal([][]byte{hash}, chain.LatestRoot())

// 验证证明
valid, _ := chain.Verify(batchNumber, leafHash, proof)
```

## 7. 指标

```go
// 定义指标
connTotal := gw.NewMetricCounter("gateway_connections_total", "Total connections", "status")
activeConns := gw.NewMetricGauge("gateway_active_connections", "Active connections")
latency := gw.NewMetricHistogram("gateway_request_duration_seconds", "Request latency", nil, 0.01, 0.05, 0.1, 0.5, 1.0)

// 注册
gw.RegisterCounter(connTotal)
gw.RegisterGauge(activeConns)
gw.RegisterHistogram(latency)

// 使用
connTotal.Inc("allowed")
activeConns.Add(1)
latency.Observe(0.042)

// 暴露 /metrics 端点
http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/plain; version=0.0.4")
    w.Write([]byte(gw.RenderMetrics("pki-gateway 1.0.0")))
})
```

## 8. 统一准入管线

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

## 9. AIC/能力检查

```go
// 解析 AIC 扩展
aic, err := gw.ParseAIC(leafCert)
if err != nil {
    log.Printf("无 AIC 扩展: %v", err)
}

// 检查能力
if aic.HasProtocol("tcp") {
    // 允许 TCP 协议
}

if aic.CheckPermission("file:read") {
    // 允许文件读取
}

// 权限交集
allowed := aic.IntersectPermissions(userPerm)
```

## 10. 幂等关闭

```go
guard := gw.NewStopGuard()

// 多处调用安全
go func() {
    <-guard.StopChan()
    ln.Close()
}()

go func() {
    <-guard.StopChan()
    cache.Stop()
}()

// 第一次调用返回 true，后续返回 false
guard.Stop() // true
guard.Stop() // false
```

## 11. 管理服务器

```go
ms := gw.NewManagementServer(gw.ManagementServerConfig{
    Listen:        ":9090",
    TLSConfig:     tlsCfg,
    BuildInfo:     "v1.0.0",
    AuditLogger:   auditLogger,
    AuditChain:    chain,
    PluginRegistry: registry,
})

// 注册自定义端点
ms.RegisterHandler("/api/v1/gateway/custom", myHandler, "gateway:admin")

// 启动
go ms.Start()
defer ms.Stop()
```

## 12. 脱敏工具

```go
gw.MaskCertSerial("ABCD1234567890")    // "****7890"
gw.MaskToken("Bearer abcdef123456")     // "Bear****56"
gw.MaskFilePath("/etc/pki/keys/cert.pem") // "/etc/pki/keys/****pem"
gw.MaskEmail("admin@example.com")       // "a*****@example.com"
gw.SanitizeString("hello\x00world")     // "helloworld"
```
