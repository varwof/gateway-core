# gateway-core 快速开始

> 包名: `gw` | Go 1.26+ | 纯标准库（仅 golang.org/x/crypto + bolt）

## 安装

```bash
go get github.com/varwof/gateway-core
```

## 最小示例

```go
package main

import (
    "log"
    "time"

    gw "github.com/varwof/gateway-core"
)

func main() {
    // 1. 加载 CA 和服务端证书
    caCert, err := gw.LoadCACert("ca.pem")
    if err != nil {
        log.Fatal(err)
    }
    _ = caCert

    cert, err := gw.LoadCert("server.pem", "server.key")
    if err != nil {
        log.Fatal(err)
    }

    // 2. 创建 mTLS 服务器配置
    tlsCfg, err := gw.MTLSServerConfig("ca.pem", cert, nil, "1.2")
    if err != nil {
        log.Fatal(err)
    }

    // 3. 创建 CRL 缓存
    crlCache := gw.NewCRLCache(caCert, "http://crl.example.com/ca.crl", 1800, nil, "zh")
    stopCh := make(chan struct{})
    go crlCache.Start(stopCh)

    // 4. 创建 OCSP 缓存
    ocspCache := gw.NewOCSPCache(5*time.Minute, gw.OCSPFallbackCRL, nil, "zh")

    // 5. 创建审计日志
    auditLogger, _ := gw.NewAuditLogger("/var/log/gateway/audit.log", nil, 100*1024*1024, 3)
    defer auditLogger.Close()

    // 6. 注册 Prometheus 指标
    connTotal := gw.NewMetricCounter("gateway_connections_total", "Total connections", "status")
    gw.RegisterCounter(connTotal)

    _ = tlsCfg
    // 用 tlsCfg 启动你的 TLS 服务器...
}
```

## 运行管线检查

```go
// 客户端连接后，执行统一准入管线
result := gw.RunAccessPipeline(certChain, &gw.PipelineConfig{
    CRLCache:           crlCache,
    OCSPCache:          ocspCache,
    AllowRoles:         []string{"gateway:admin", "gateway:ops"},
    MaxConnsPerCert:    100,
    RequireAIC:         true,
    RequiredProtocol:   "tcp",
})

if !result.Granted {
    log.Printf("连接被拒绝: %s", result.DenyReason)
    return
}

log.Printf("允许连接: principal=%s roles=%v", result.Principal, result.Roles)
```

## 常用 API 速查

| 操作 | 函数 |
|------|------|
| 加载证书 | `gw.LoadCert(certFile, keyFile)` |
| 加载 CA | `gw.LoadCACert(caFile)` / `gw.LoadCA(caFile)` |
| mTLS 配置 | `gw.MTLSServerConfig(caFile, cert, suites, version)` |
| CRL 检查 | `gw.NewCRLCache(...)` → `cache.IsRevoked(serial)` |
| OCSP 检查 | `gw.NewOCSPCache(...)` → `cache.Check(cert, issuer)` |
| RBAC | `gw.ExtractRoles(cert)` → `gw.CheckRole(roles, allowed)` |
| 审计 | `gw.NewAuditLogger(...)` → `logger.Log(entry)` |
| 指标 | `gw.NewMetricCounter(...)` → `gw.RenderMetrics(buildInfo)` |
| 准入管线 | `gw.RunAccessPipeline(chain, cfg)` |
| 幂等关闭 | `gw.NewStopGuard()` → `guard.Stop()` |

## 下一步

- [配置参考](config.md) — 所有配置项详解
- [函数参考](functions.md) — 完整函数签名
- [使用指南](usage.md) — 各模块深入使用
- [API 参考](api.md) — 导出类型完整列表
