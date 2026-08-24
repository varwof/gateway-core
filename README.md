# gateway-core

> 包名: `gw` | 纯 Go | 无外部依赖 | 32,661 行源码（55 文件）+ 18,947 行测试（65 文件）

共享安全引擎库，为 gateway-tcp/http/udp 提供统一的 mTLS、CRL、OCSP、TSA、RBAC、审计、指标、决策、短命证书能力。

---

## 模块清单

| 模块 | 文件 | 功能 |
|------|------|------|
| **CRL 缓存** | `crl.go` | 证书吊销列表获取与缓存，支持 HTTP URL 定时刷新 |
| **OCSP 缓存** | `ocsp.go` | 在线证书状态查询，TTL 缓存 + 超时 fallback |
| **TSA 客户端** | `tsa.go` | RFC 3161 时间戳请求与验证 |
| **TSA Proof** | `tsa_proof.go` | 定期审计证明日志，TSA 时间戳链式固化 |
| **RBAC** | `rbac.go` | 基于证书 OU 的角色提取与权限检查 |
| **策略文件** | `policy.go` | authz.json 授权策略加载（HasGrant/RoleGrants/OU 映射） |
| **审计日志** | `audit.go` | JSON Lines 格式，轮转文件输出 |
| **审计索引** | `audit_index.go` | 审计日志分段索引，支持快速检索 |
| **Merkle 哈希链** | `merkle.go` | 审计日志防篡改，每千条构建 Merkle 树 |
| **指标** | `metrics.go` | Prometheus 格式：Counter、Gauge、Histogram |
| **TLS 配置** | `tls.go` | MTLSServerConfig、LoadCert、LoadCA 辅助函数 |
| **统一协议/TLS** | `mtls.go` | 统一 `TLSConfig`/`TCPExtra`/`HTTPExtra`/`UDPExtra` + 协议/TLS 常量 |
| **连接跟踪** | `tracker.go` | per-cert 连接计数与限制 |
| **脱敏工具** | `mask.go` | 敏感数据脱敏：证书序列号、Token、文件路径 |
| **告警** | `alarm.go` | CRL/OCSP 异常事件告警通知 |
| **信号处理** | `signal_unix.go` / `signal_windows.go` | 平台信号处理 |
| **统一准入管线** | `pipeline.go` | `RunAccessPipeline()` — CRL → OCSP → RBAC → AIC → 约束 → 插件一站式检查 |
| **幂等关闭** | `stopher.go` | `StopGuard` — 跨 gateway 统一的幂等停止基元 |
| **管理 API 框架** | `management.go` | `ManagementServer` — 统一 `/health`、`/metrics`、`/audit` 端点 |
| **TokenBucket 限速** | `ratelimit.go` | 通用令牌桶，支持 Allow/WaitN/SetRate/SetBurst |
| **吊销客户端** | `revoker.go` | 通过 mTLS API 条件吊销未到期证书（`NeedRevoke()`） |
| **短命证书** | `shortlived.go` | `AutoIssueCert()` + `RenewalLoop()` — 自动签发与定时续签 |
| **确认续签** | `confirmed_renewal.go` | 确认续签状态机（Idle→Awaiting→Confirmed/Rejected）+ DA 重签 |
| **连接过期注册表** | `connexpiry.go` | 按证书序列号跟踪活跃连接 + 续期标记（条件性吊销跳过） |
| **AIC 解析器** | `aic.go` | Agent Identity Certificate 扩展解析（OID 1.3.6.1.4.1.66257.1.1）|
| **GS 解析器** | `session.go` | GatewaySession 扩展解析（OID 1.3.6.1.4.1.66257.1.5）|
| **PA 解析器** | `user_permission.go` | PrincipalAuthorization 扩展解析（OID 1.3.6.1.4.1.66257.1.2）|
| **SPIFFE** | `spiffe.go` | SPIFFE ID 解析（RFC 7555 trust domain 校验）+ 证书 SAN URI 提取 |
| **统一决策引擎** | `decision.go` | `CheckAdmission()` — AIC + GS + PA 联合检查，P∩C 交集按模式区分 |
| **委托链验证** | `delegation_chain.go` | 多级委托链验签 + 防环 + 防证书炸弹 + 能力子集 + C_eff 求交 |
| **凭证包验证** | `credential_bundle.go` | 双链验证（Agent 链 + Principal 链）+ keyHash Fail-Close |
| **三层信任模型** | `trust_model.go` | `VerifyLayer1/2/3`（身份→代表关系→在线授权）+ `VerifyTrustLayers` |
| **参数边界校验** | `parameters.go` | 按 schemeId 的参数边界校验器注册表（P∩C 交集后逐条比对） |
| **能力插件** | `plugin.go` / `pluginconfig.go` | 插件注册表 + 4 种内置插件（allowlist/denylist/rbac/webhook） |
| **策略版本化** | `policystore.go` | 整包策略版本单调递增 + 历史快照 + 分支控制（Agent 路由） |
| **能力注册表** | `capregistry.go` / `registry.go` | 能力方案注册（单一事实源） |
| **风险监控** | `riskmonitor.go` | 行为违规 → 踢线 + 吊销反应闭环 |
| **Mesh 控制面** | `mesh_control.go` | 节点间 revoke/disconnect 控制消息广播 + 去重防环 |
| **任务注册表** | `tasks.go` | 任务 ID → 证书序列号映射（X-AIC-Task-* 头） |
| **Nonce 缓存** | `nonce_cache.go` | DA nonce 防重放缓存 |
| **离线 RBAC** | `offline_rbac.go` | 离线/断网场景角色决策（企业用例 2/6） |
| **续期令牌** | `renewal_token.go` | RenewalToken 扩展（OID 1.6）解析 |
| **自校验** | `selfverify.go` | 证书链自校验辅助 |
| **流多路复用** | `streammux.go` | TCP/QUIC 流多路复用基元 |

---

## 快速开始

```go
import gw "github.com/varwof/gateway-core"

// 创建 CRL 缓存（每 30 分钟刷新）
caCert, _ := gw.LoadCACert("ca.pem")
crlCache := gw.NewCRLCache(caCert, "http://crl.example.com/ca.crl", 1800, nil, "zh")

// 创建 OCSP 缓存（TTL 5 分钟）
ocspCache := gw.NewOCSPCache(5*time.Minute, "", nil, "zh")

// RBAC：从证书 OU 提取角色
roles := gw.ExtractRoles(cert)
if !gw.CheckRole(roles, []string{"gateway:admin"}) {
    // 拒绝连接
}

// 审计日志（maxSize 字节，maxBak 个轮转备份）
audit, _ := gw.NewAuditLogger("/var/log/pki/audit.log", nil, 100*1024*1024, 3)
audit.Log(gw.AuditEntry{
    Action:    "connection_allowed",
    ClientCN:  "user@example.com",
    Roles:     []string{"gateway:admin"},
})

// Prometheus 指标
gw.RegisterCounter(myCounter)
gw.RegisterGauge(myGauge)
gw.RegisterHistogram(myHistogram)

// TLS 配置（加载证书后构造 mTLS server 配置）
cert, _ := gw.LoadCert("cert.pem", "key.pem")
tlsCfg, _ := gw.MTLSServerConfig("ca.pem", cert, nil, "1.2")
```

---

## 关键设计

### CRL 缓存策略

```
请求 → 检查本地缓存
  ├── 有缓存且未过期 → 直接返回
  └── 无缓存/已过期 → HTTP 获取 CRL
       ├── 成功 → 更新缓存，返回
       └── 失败 → 返回旧缓存（fallback）
```

### OCSP 缓存策略

```
请求 → 检查本地缓存
  ├── 有效且未过期 → 返回 OCSP 状态
  └── 无缓存/已过期 → 并发请求 OCSP 响应器
       ├── 成功 → 更新缓存，返回
       └── 失败/超时 → fallback 到 CRL 检查
```

### RBAC 角色提取

证书 OU → 角色映射规则：

| OU 前缀 | 映射角色 | 说明 |
|---------|---------|------|
| `gateway:admin` | admin | 完全控制 |
| `gateway:ops` | ops | 运维操作 |
| `gateway:audit` | audit | 审计只读 |
| `gateway:*` | 通配 | 所有角色 |
| 其他 OU | 无 | 拒绝访问 |

### 审计日志格式

```json
{"time":"2026-07-09T10:00:00Z","action":"connection_allowed","src_ip":"192.168.1.1",
 "client_cn":"client.example.com","client_serial":"ABCD1234","roles":["gateway:admin"],
 "mapping":"tls-proxy","target":"192.168.1.2:443","bytes_in":1024,"bytes_out":2048}
```

### 指标命名

```
pki_gateway_{type}_{name}_total      // Counter
pki_gateway_{type}_{name}            // Gauge
pki_gateway_{type}_{name}_seconds    // Histogram
```

---

## 测试

```bash
go test -count=1 ./...
```

当前测试覆盖：65 个测试文件，18,947 行测试代码。

## Go SDK 使用示例

### CRL 缓存

```go
import gw "github.com/varwof/gateway-core"

caCert, _ := gw.LoadCACert("ca.pem")
cache := gw.NewCRLCache(caCert, "http://crl.example.com/ca.crl", 1800, nil, "zh")

// 检查证书是否被吊销
revoked, err := cache.IsRevoked(serialHex)
if err != nil {
    // CRL 下载失败，使用旧缓存
}
if revoked {
    // 拒绝连接
}
```

### OCSP 查询

```go
cache := gw.NewOCSPCache(5*time.Minute, "", nil, "zh")

status, err := cache.Check(cert)
switch status {
case gw.StatusGood:
    // 证书有效
case gw.StatusRevoked:
    // 证书已被吊销
case gw.StatusUnknown:
    // OCSP 响应器不可用，fallback 到 CRL
}
```

### RBAC 检查

```go
roles := gw.ExtractRoles(clientCert)
if !gw.CheckRole(roles, []string{"gateway:admin"}) {
    // 拒绝，返回 403
}
```

### 审计日志

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

### TLS 配置

```go
cert, _ := gw.LoadCert("cert.pem", "key.pem")
tlsCfg, err := gw.MTLSServerConfig("ca.pem", cert, nil, "1.2")
// 返回 *tls.Config 可直接用于 http.Server 或 tls.Listener
```

### Prometheus 指标

```go
connTotal := gw.NewMetricCounter(
    "pki_gateway_tcp_connections_total",
    "Total TCP connections",
    "mapping", "status")
gw.RegisterCounter(connTotal)

connTotal.Inc("web-proxy", "allowed")
connTotal.Inc("web-proxy", "denied")

// 暴露 /metrics 端点
http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte(gw.RenderMetrics("# HELP pki_gateway_build_info")))
})
```

## Project Structure

```
gateway-core/
├── docs/             # 用户文档
├── *.go              # 源码文件（平铺根目录）
├── *_test.go         # 测试文件
├── README.md
└── go.mod
```

## License

Apache-2.0
