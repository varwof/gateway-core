# gateway-core 配置参考

gateway-core 是一个库，不是独立服务。配置通过各模块的构造函数参数传入。本文档列出所有可配置项。

## 通用模式

所有模块遵循以下约定：

- 构造函数接受 `Config` 结构体或离散参数
- `nil` 参数使用默认值
- `stop <-chan struct{}` 或 `chan struct{}` 用于优雅关闭
- `Translator` 接口 + `lang string` 支持 i18n

## CRL 缓存

```go
gw.NewCRLCache(caCert *x509.Certificate, url string, refreshSec int, translator Translator, lang string) *CRLCache
```

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `caCert` | `*x509.Certificate` | 必填 | CA 证书，用于验证 CRL 签名 |
| `url` | `string` | 必填 | CRL 分发点 HTTP URL |
| `refreshSec` | `int` | 1800 | 刷新间隔（秒），建议 1800-3600 |
| `translator` | `Translator` | `nil` | i18n 翻译器 |
| `lang` | `string` | `"zh"` | 语言代码 |

**缓存行为**：
- 首次 `Start()` 时同步获取 CRL
- 之后每 `refreshSec` 秒后台刷新
- 刷新失败时使用旧缓存（stale fallback）
- 通过 `ForceRefresh()` 可手动触发刷新

## OCSP 缓存

```go
gw.NewOCSPCache(ttl time.Duration, fallback string, translator Translator, lang string) *OCSPCache
```

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `ttl` | `time.Duration` | 5m | 缓存有效期 |
| `fallback` | `string` | `"crl"` | 响应器不可用时的降级策略 |

**Fallback 模式**：

| 值 | 行为 |
|----|------|
| `"allow"` | 无法查询时允许连接 |
| `"deny"` | 无法查询时拒绝连接 |
| `"crl"` | 降级到 CRL 检查 |

## TSA 客户端

```go
client := gw.NewTSAClient(url string)
client.SetCACert(certFile string) error
client.SetMaxTSTAge(d time.Duration)
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `url` | 必填 | RFC 3161 TSA 服务 URL |
| `caCert` | 无 | TSA CA 证书文件路径 |
| `maxTSTAge` | 1h | 最大时间戳年龄（防重放窗口） |

## 审计日志

```go
gw.NewAuditLogger(file string, tsa *TSAClient, maxSize int64, maxBak int) (*AuditLogger, error)
```

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `file` | `string` | 必填 | 审计日志文件路径 |
| `tsa` | `*TSAClient` | `nil` | TSA 客户端（启用时每条日志带时间戳签名） |
| `maxSize` | `int64` | 100MB | 单文件最大大小（字节） |
| `maxBak` | `int` | 3 | 保留的历史文件数 |

**轮转策略**：文件达到 `maxSize` 时自动轮转，保留最多 `maxBak` 个历史文件。

## 审计索引

```go
gw.NewAuditIndex(path string) (*AuditIndex, error)
```

| 参数 | 说明 |
|------|------|
| `path` | BoltDB 数据库文件路径 |

## Merkle 哈希链

```go
gw.NewAuditChain(batchSize int, onSeal func(root []byte)) *AuditChain
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `batchSize` | 1000 | 每棵 Merkle 树的叶节点数 |
| `onSeal` | `nil` | 树封存回调（用于触发 TSA 时间戳） |

## 指标

```go
gw.NewMetricCounter(name, help string, labels ...string) *MetricCounter
gw.NewMetricGauge(name, help string, labels ...string) *MetricGauge
gw.NewMetricHistogram(name, help string, labels []string, bounds ...float64) *MetricHistogram
```

无额外配置。注册后通过 `gw.RenderMetrics(buildInfo)` 输出 Prometheus 格式。

## TLS 配置

```go
gw.MTLSServerConfig(caCertFile string, cert *tls.Certificate, cipherSuites []string, minTLSVersion string) (*tls.Config, error)
gw.ClientTLSConfig(caCertFile, certFile, keyFile string, cipherSuites []string, minTLSVersion string) (*tls.Config, error)
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `cipherSuites` | `nil`（使用安全默认值） | 密码套件名称列表 |
| `minTLSVersion` | `"1.2"` | 最低 TLS 版本 |

**可用密码套件名称**：`TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`、`TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`、`TLS_CHACHA20_POLY1305_SHA256` 等。

## 统一准入管线

```go
gw.RunAccessPipeline(chain []*x509.Certificate, cfg *PipelineConfig) *PipelineResult
```

### PipelineConfig

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `CRLCache` | `*CRLCache` | `nil` | CRL 缓存（跳过如未设置） |
| `OCSPCache` | `*OCSPCache` | `nil` | OCSP 缓存（跳过如未设置） |
| `AllowRoles` | `[]string` | `nil` | 允许的 RBAC 角色列表 |
| `CheckScope` | `PipelineCheck` | `CheckFullChain` | `CheckFullChain` 或 `CheckLeafOnly` |
| `MaxConnsPerCert` | `int` | 0（无限制） | 每证书最大并发连接数 |
| `RequireAIC` | `bool` | `false` | 是否要求 AIC 扩展 |
| `RequireGS` | `bool` | `false` | 是否要求 GatewaySession 扩展 |
| `RequiredProtocol` | `string` | `""` | 要求的协议标识 |
| `RequiredCapabilities` | `[]string` | `nil` | 要求的能力列表 |
| `RequireUserAuth` | `bool` | `false` | 是否验证委托授权签名 |
| `EnforceCapSizeConstraints` | `bool` | `false` | 是否强制能力大小约束 |
| `EnforceSize32` | `bool` | `false` | 是否强制 Nonce 为 32 字节 |
| `CapabilityPluginRegistry` | `*PluginRegistry` | `nil` | 能力插件注册表 |
| `AuditLogger` | `*AuditLogger` | `nil` | 审计日志记录器 |
| `NonceCache` | `*NonceCache` | `nil` | Nonce 防重放缓存 |
| `ClientIP` | `string` | `""` | 客户端 IP（用于 GS CIDR 检查） |

## 插件配置

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

### 内置插件类型

| 类型 | 说明 | Config 字段 |
|------|------|-------------|
| `allowlist` | 白名单 | `allowed []string`, `default_deny bool` |
| `denylist` | 黑名单 | `denied []string`, `default_allow bool` |
| `rbac` | 角色映射 | `role_map map[string][]string` |
| `webhook` | 外部决策 | `url string`, `timeout int`, `secret string` |

## 管理服务器

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

### 自动注册端点

| 端点 | 方法 | 角色 | 说明 |
|------|------|------|------|
| `/api/v1/gateway/health` | GET | 公开 | 健康检查 |
| `/api/v1/gateway/metrics` | GET | ops, admin | Prometheus 指标 |
| `/api/v1/gateway/audit` | GET | audit, admin | 审计日志查询 |
| `/api/v1/gateway/audit/verify` | POST | audit, admin | Merkle 证明验证 |
| `/api/v1/gateway/plugins` | GET | ops, admin | 列出插件 |
| `/api/v1/gateway/plugins/{scheme}` | GET | ops, admin | 查询指定插件 |
| `/api/v1/gateway/plugins` | PUT | admin | 替换所有插件 |
| `/api/v1/gateway/plugins` | DELETE | admin | 清空所有插件 |

## 短命证书客户端

```go
gw.NewIssueClient(gw.IssueConfig{
    CoreURL:            "https://pki-core:4433",
    CertFile:           "client.pem",
    KeyFile:            "client.key",
    CACertFile:         "ca.pem",
    DefaultCA:          "issuing",
    DefaultKeyType:     "ecdsa-p256",
    DefaultValidity:    10,          // 默认签发有效期（天），0=调用方缺省（W38）
    Timeout:            10 * time.Second,
    RetryCount:         3,
    RenewalIntervalSec: 30,          // 续签轮询间隔（秒），0=默认 30s（W38）
})
```

## 告警

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

**支持的告警通道**：`dingtalk`、`slack`、`feishu`

**操作符**：`gt`、`lt`、`gte`、`lte`
