# 贡献指南

## 前提
- Go 1.26+
- `go vet ./...` 零警告
- 所有测试通过

## 开发流程

```bash
# 克隆
git clone https://github.com/varwof/gateway-core

# 构建
go build ./...

# 测试
go test -count=1 -race ./...

# 代码检查
go vet ./...
gofmt -s -l .
```

## 提交信息格式

```
<type>: <简短描述>

类型: feat / fix / docs / test / refactor / chore
```

## PR 要求
1. 新增功能需包含测试
2. 配置变更需同步更新 docs/
3. OpenAPI 变更需同步更新 openapi.yaml

## 与 aic-verifier 的镜像关系（协议执行逻辑）

`aic.go` / `decision.go` / `pipeline.go` / `constraints.go` / `policy.go` /
`rbac.go` / `user_permission.go` / `delegation_chain.go` / `credential_bundle.go` /
`crl.go` / `ocsp.go` / `tsa.go` / `jwt.go` / `spiffe.go` / `nonce_cache.go` / `merkle.go` / `mask.go` / `parameters.go` / `plugin.go` /
`capregistry.go` / `riskmonitor.go` / `trust_model.go` 是
[varwof/aic-verifier](https://github.com/varwof/aic-verifier) 中同名文件的镜像。
两者**不共享代码**（aic-verifier 不依赖本模块），一致性靠人工同步维持。

改动上述任一文件时：

1. 先在 aic-verifier 落地，同一个 commit 复制过来（本模块包名为 `gw`，
   aic-verifier 为 `aicverifier`，只需替换包名与 import 路径）。
2. 准入判定、拒绝原因字符串、TTL/时间窗、fail-closed 行为必须逐字相同。
   仅在两边都不使用的配置面（`Operations`/CLC、`ConstraintRegistry`、
   `gmsm`/`pipeline_aac`/`shortlived` 等各自独有特性）上允许分歧。
3. 不要单方面修改拒绝原因字符串——它是跨实现的实际契约。

已对齐的权威值（改动前请确认这些来源）：

| 值 | 权威来源 |
|---|---|
| `DefaultDAAgeMax = 1m` | varwof/core `internal.DefaultDATimestampSkew` |
| replay store 默认容量 65536 + 饱和 fail-closed | 见 `jwt.go` `NewReplayNonceStore` 注释 |
| 同 scope nonce 复用不设上限 | 见 `nonce_cache.go` `CheckAndAdd` 注释 |
| SPIFFE trust domain 大小写不敏感（RFC 7555 §2.1） | `spiffe.go` |


## 贡献者许可协议（CLA）

提交 Pull Request 即表示您同意签署
[个人 CLA](https://github.com/varwof/.github/blob/main/CLA-INDIVIDUAL.md)
（企业赞助贡献请签[企业 CLA](https://github.com/varwof/.github/blob/main/CLA-CORPORATE.md)）。
CLA Assistant 机器人会在您打开第一个 Pull Request 时提示签署；签署一次覆盖所有 Varwof 仓库。

您的贡献将按 Apache-2.0 许可证授权，详见 [LICENSE](LICENSE)。
