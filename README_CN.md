# varwof-gateway-core

> 共享安全引擎库 —— 为 gateway-tcp/http/udp 提供统一的 mTLS、CRL、OCSP、TSA、RBAC、审计、指标、决策能力

[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/varwof/gateway-core)](https://pkg.go.dev/github.com/varwof/gateway-core)

> ⚠️ **预览版** — 不可用于生产环境。API 和功能可能在正式发布前发生变更。

[English](README.md)

## 什么是 varwof-gateway-core？

共享安全引擎库，为三网关提供统一的 mTLS、CRL、OCSP、TSA、RBAC、审计、指标、决策、短命证书能力。纯 Go，无外部依赖。

## 快速开始

```go
import gw "github.com/varwof/gateway-core"

caCert, _ := gw.LoadCACert("ca.pem")
crlCache := gw.NewCRLCache(caCert, "http://crl.example.com/ca.crl", 1800, nil, "zh")

roles := gw.ExtractRoles(cert)
if !gw.CheckRole(roles, []string{"gateway:admin"}) {
    // 拒绝
}
```

## 安装

```bash
go get github.com/varwof/gateway-core@v0.1.0
```

## 核心模块

| 模块 | 说明 |
|------|------|
| CRL/OCSP 缓存 | 证书吊销列表 + 在线状态查询 |
| TSA 客户端 | RFC 3161 时间戳 |
| RBAC | 基于证书 OU 的角色提取 |
| 审计日志 | JSON Lines + Merkle 哈希链 |
| 指标 | Prometheus Counter/Gauge/Histogram |
| 统一准入管线 | CRL → OCSP → RBAC → AIC → 约束 → 插件 |
| ACPs AAC Profile | 实验性（opt-in）：`acps` 包 + `RunAccessPipelineAAC`（AIC/AAC/AIP v0 切片） |

## ACPs AAC Profile（实验性）

ACPs v2.2.0 授权模型的 opt-in 强制执行层：

- `acps` — 自包含包（AIC 语法 + CRC-16 校验码、委托 token 信任/边界规则、可信上下文提供者、
  fail-closed PDP、AAC/AIP 错误码）。
- `pipeline_aac.go` — `RunAccessPipelineAAC(chain, cfg, aac, req)`：未启用 AAC 时与既有
  `RunAccessPipeline` 完全一致（默认行为不变）；启用后在业务处理前叠加身份绑定（AIP §6.0）、
  可信上下文构建、audience/chain/replay 检查与 fail-closed PDP 裁决，并记录授权审计（AAC §13）。

文档：`docs/acps/ACPs-v02.2-requirements.md`（需求基线）、
`docs/acps/aac-to-gateway-core-mapping.md`（组件映射）、
`docs/acps/conformance-matrix.md`（逐条一致性矩阵）。

gateway-core 是三网关的**共享安全引擎层**。本项目是 [Open Invention Network](https://openinventionnetwork.com/) 成员。

## 链接

| | |
|---|---|
| 主页 | https://varwof.com |
| 社区 | https://varwof.org |
| IETF 草案 | [draft-wei-aic-identity-cert](https://datatracker.ietf.org/doc/draft-wei-aic-identity-cert/) |
| 许可证 | Apache-2.0 |
| 成员 | [Open Invention Network](https://openinventionnetwork.com/) |
