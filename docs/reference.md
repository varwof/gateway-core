# gateway-core 参考手册

## 架构概览

gateway-core 是纯 Go 共享安全引擎库，为三网关（TCP/HTTP/UDP）提供统一安全能力。

```
┌─────────────────────────────────────────────────────┐
│                 gateway-core (gw)                │
├─────────────────────────────────────────────────────┤
│  ┌──────────┐ ┌──────────┐ ┌──────────┐            │
│  │ CRL 缓存 │ │ OCSP 缓存│ │ TSA 客户端│           │
│  └──────────┘ └──────────┘ └──────────┘            │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐            │
│  │ RBAC     │ │ 审计日志 │ │ 指标     │            │
│  └──────────┘ └──────────┘ └──────────┘            │
│  ┌──────────────────────────────────────┐           │
│  │        统一准入管线 (Pipeline)        │           │
│  │  CRL → OCSP → RBAC → AIC → 插件    │           │
│  └──────────────────────────────────────┘           │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐            │
│  │ 插件引擎 │ │ 连接跟踪 │ │ 限速器   │            │
│  └──────────┘ └──────────┘ └──────────┘            │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐            │
│  │ 管理 API │ │ 告警     │ │ Mesh 联邦│           │
│  └──────────┘ └──────────┘ └──────────┘            │
└─────────────────────────────────────────────────────┘
```

## 准入管线执行顺序

```
1. 证书有效性检查     (过期/未生效)
2. CRL 检查          (证书是否被吊销)
3. OCSP 检查         (在线证书状态)
4. RBAC 角色提取     (证书 OU → 角色)
5. AIC 解析          (Agent Identity Certificate)
6. GatewaySession    (会话约束)
7. 能力交集检查       (AIC.Capabilities ∩ PA.Grants)
8. 委托授权验证       (DelegationAuthorization 签名)
9. GS CIDR 检查      (IP 白名单)
10. 插件执行          (Capability Plugin Registry)
→ 返回 PipelineResult (Granted/Denied)
```

## 模块依赖关系

```
Pipeline ──→ CRLCache
         ──→ OCSPCache
         ──→ RBAC (ExtractRoles/CheckRole)
         ──→ CheckAdmission
                ├── ParseAIC
                ├── ValidateAIC
                ├── ParseGatewaySessionExtension
                ├── VerifyDelegationAuth
                ├── CheckDAFreshness (可选，P1-B-13；AdmissionConfig.CheckDAAge)
                ├── NonceCache
                └── PrincipalAuthorization
         ──→ PluginRegistry.Execute
         ──→ AuditLogger.Log
```

## 文件索引

| 文件 | 行数 | 职责 |
|------|------|------|
| `aic.go` | ~300 | AIC ASN.1 解析 + 验证 |
| `alarm.go` | ~200 | 告警规则 + Webhook 通知 |
| `audit.go` | ~420 | 审计日志 + 轮转 + 查询 + 授权证据指纹（da_hash/aic_fingerprint） |
| `audit_fts.go` | ~100 | 审计全文搜索 |
| `audit_index.go` | ~200 | BoltDB 审计索引 |
| `configwatch.go` | ~100 | 配置热重载 |
| `crl.go` | ~200 | CRL 缓存 + 后台刷新 |
| `decision.go` | ~400 | 准入决策 + 委托验证 |
| `management.go` | ~300 | 管理 API 服务器 |
| `mask.go` | ~80 | 敏感数据脱敏 |
| `merkle.go` | ~300 | Merkle 树 + 哈希链 |
| `metrics.go` | ~200 | Prometheus 指标 |
| `mesh.go` | ~200 | Mesh 联邦（健康检查/转发） |
| `mesh_control.go` | ~180 | Mesh 控制面消息（revoke/disconnect/peer_sync 广播 + 去重防环） |
| `nonce_cache.go` | ~60 | Nonce 防重放 |
| `ocsp.go` | ~250 | OCSP 缓存 + Stapling |
| `pipeline.go` | ~200 | 统一准入管线 |
| `plugin.go` | ~150 | 插件引擎 |
| `pluginconfig.go` | ~200 | 内置插件配置 |
| `policystore.go` | ~190 | 策略版本化/回滚（任务 5a） |
| `principal.go` | ~100 | Principal Profile |
| `ratelimit.go` | ~80 | 令牌桶限速 |
| `registry.go` | ~100 | 连接注册表 |
| `renewal_token.go` | ~80 | 续签令牌 |
| `revoker.go` | ~120 | 证书吊销客户端 |
| `rbac.go` | ~100 | RBAC 角色检查 |
| `session.go` | ~100 | GatewaySession 解析 |
| `shortlived.go` | ~250 | 短命证书签发 + 续签 |
| `spiffe.go` | ~80 | SPIFFE ID 解析 |
| `stopher.go` | ~50 | 幂等关闭 |
| `streammux.go` | ~150 | 流多路复用 |
| `tls.go` | ~200 | TLS/mTLS 配置 |
| `tracker.go` | ~80 | 连接跟踪 |
| `tsa.go` | ~300 | TSA 客户端 |
| `tsa_proof.go` | ~100 | TSA 证明日志 |
| `user_permission.go` | ~150 | PrincipalAuthorization |
| `utils.go` | ~50 | 工具函数 |

## 三网关集成模式

三网关共享 lib 的标准流程：

```go
// 1. 加载配置
cfg := LoadConfig("config.json")

// 2. 创建 lib 基础设施
crlCache := gw.NewCRLCache(...)
ocspCache := gw.NewOCSPCache(...)
auditLog := gw.NewAuditLogger(...)
registry := gw.NewPluginRegistry()
ms := gw.NewManagementServer(...)
guard := gw.NewStopGuard()

// 3. TLS 配置
tlsCfg, _ := gw.MTLSServerConfig(caFile, cert, nil, "1.2")

// 4. 连接处理
result := gw.RunAccessPipeline(certChain, &gw.PipelineConfig{
    CRLCache: crlCache, OCSPCache: ocspCache,
    AllowRoles: allowedRoles, AuditLogger: auditLog,
    CapabilityPluginRegistry: registry,
})
```

## 安全约束

| 约束 | 值 | 说明 |
|------|-----|------|
| Nonce 大小 | 32 字节 | DelegationAuthorization.Nonce 必须为 32B |
| RequestedLifetime | 3600-86400 秒 | 默认 3600 |
| Capability SchemeId | 1-128 字节 | |
| CapabilityId | 1-256 字节 | |
| Capability Parameters | 0-4096 字节 | |
| RenewalToken ValidityPeriod | ≤300 秒 | |
| GS MaxConcurrent | ≥1 | |
| GS HardTimeout | ≥60 秒 | |

## 预定义 OID

| OID | 名称 | 用途 |
|-----|------|------|
| `1.3.6.1.4.1.66257.1.1` | AIC | Agent Identity Certificate |
| `1.3.6.1.4.1.66257.1.2` | GatewaySession | 会话约束扩展 |
| `1.3.6.1.4.1.66257.1.3` | OfflineRBAC | 离线 RBAC 扩展 |
| `1.3.6.1.4.1.66257.1.4` | PrincipalProfile | 身份档案 |
| `1.3.6.1.4.1.66257.1.5` | UserPermission | 用户权限（v1.4 兼容） |
| `1.3.6.1.4.1.66257.1.6` | RenewalToken | 续签令牌 |
| `1.3.6.1.4.1.66257.1.1.11` | SPIFFE | SPIFFE ID 扩展 |
