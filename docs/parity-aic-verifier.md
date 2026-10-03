# 与 aic-verifier 的协议执行层对齐报告

最后核对：2026-09-26

## 1. 目的与范围

`varwof/gateway` 在编译期依赖本模块（`gateway/go.mod` 固定
`github.com/varwof/gateway-core v0.4.7`），本模块因此是网关的实际判定实现。
`varwof/aic-verifier` 是同一套准入引擎的**独立抽取版**，供不使用网关的普通
API 服务直接引入。

两个模块**不共享任何代码**：`aic-verifier` 不依赖 `gateway-core`，两边靠人工
复制保持一致。本报告记录当前一致性状态、被允许的分歧范围、以及每次改动后
必须复跑的核对方法。

不在本报告范围内：CLC 语义本身、证书签发、策略编写工具、`varwof/core` 的
协议定义。

`aic-verifier` 侧的对应报告见
[`varwof/aic-verifier/docs/parity-gateway-core.md`](https://github.com/varwof/aic-verifier/blob/main/docs/parity-gateway-core.md)；
两边内容一致，如有冲突以本文件为准（本网关是编译期依赖方）。

## 2. 快照

| 仓库 | 分支 | HEAD |
|---|---|---|
| `gateway-core` | `feat/acps-aac` | `b112ee4` |
| `aic-verifier` | `main` | `df24fc0` |

本次对齐的改动**尚未提交**，两库工作区均为 dirty 状态。

## 3. 文件级一致性

### 3.1 代码逐行一致（仅注释有别）

以下 18 个文件，去掉包名与注释后**逐行完全相同**：

| 文件 | 文件 | 文件 |
|---|---|---|
| `aic.go` | `capregistry.go` | `constraints.go` |
| `credential_bundle.go` | `delegation_chain.go` | `parameters.go` |
| `crl.go` | `jwt.go` | `plugin.go` |
| `mask.go` | `merkle.go` | `riskmonitor.go` |
| `nonce_cache.go` | `ocsp.go` | `spiffe.go` |
| `tsa.go` | `user_permission.go` | |

唯一残留的文本差异是**注释**：本模块在注释里标注专利权利要求编号
（如 `P1-B-27`、`P2-A-01`），`aic-verifier` 作为对外开源的干净抽取版刻意不
带这些编号。`nonce_cache.go` 另有一行互相指认镜像位置的注释，两边方向相反
（正确）。

### 3.2 仍存在差异（仅限配置面，见第 4 节）

| 文件 | 差异性质 |
|---|---|
| `policy.go` | 角色提取的策略注入点不同 |
| `constraints.go` | 仅 aic-verifier 侧多出 41 行 CLC 约束胶水代码（注册表本身两边一致） |
| `trust_model.go` | 传入 `CheckAdmission` 的 CLC 字段数不同 |
| `pipeline.go` | CLC 字段装配 + aic-verifier 的多 operation 聚合 |
| `decision.go` | CLC 评估层、约束注册表路由、`VerifyDelegationAuth` 形参 |

## 4. 允许分歧的白名单

分歧只允许存在于**另一边不存在的配置面**上。以下逐条给出"为什么同输入仍
同判定"，以及"什么条件下会真的分叉"。

### 4.1 CLC operation 层（`pipeline.go` / `decision.go` / `trust_model.go`）

`aic-verifier` 的 `AdmissionConfig` 多出 `Operations`、`UnresolvedEvaluator`、
`DischargeObligations`、`ObligationsUnderstood`、`RequireFreshDecisionContext`、
`DecisionContext`、`ConstraintRegistry` 七个字段，`AdmissionResult` 多出
`OperationDecisions` 与 `Sources`，`PipelineConfig` / `PipelineResult` 同样多出
一组 CLC 字段。这些是**公开 API 字段**，两库都要保留原样，本模块不加对应的
死配置（`DecisionContext` 还会给网关引入 `register/semantics` 依赖，不值得）。

CLC 的**全部实现**已从共享文件搬进 aic-verifier 独有的 `clc.go`：

| 搬走的东西 | 现在在哪 |
|---|---|
| 56 行逐 operation 授权循环 | `clc.go` `evaluateCLCOperations` |
| `checkDecisionContext` | `clc.go` |
| `ConstraintToCapability`、`ConnectionConstraintEvaluator` | `clc.go` |
| `aggregateCLCDecisions` | `clc.go` |
| 拒绝时回填 `OperationDecisions` 的 6 行 | `clc.go` `denyWithAdmission` |
| 7 个 CLC 字段的装配 | `clc.go` `applyCLCAdmissionConfig` |

共享文件里因此只剩两处单行接缝：

```go
applyCLCAdmissionConfig(&ac, cfg)   // 装配 7 个 CLC 字段
if denied := evaluateCLCOperations(aic, &result, &cfg); denied != nil { return *denied }
```

- 同输入同判定：CLC 字段在本网关侧不存在，无从触发；`applyCLCAdmissionConfig`
  在本网关侧无对应定义。
- 分叉条件：只在把 `aic-verifier` 当作 CLC 决策端使用时出现。

### 4.2 约束求值路径（`constraints.go` / `decision.go`）

**约束注册表本身两边完全一致**：`globalConstraintRegistry`、`NewConstraintRegistry`、
`Register` / `Replace` / `Remove` / `Reset` / `Find` / `Len` / `Keys`、
`RegisterConstraint` / `ReplaceConstraint` / `ResetConstraints` 三个扩展点，
`init()` 注册的 8 个内建求值器（`cidr`、`time_window`、`max_concurrent`、
`hard_timeout`、`idle_timeout`、`read_only`、`audit_required`、`geo_fence`），
以及 `isKnownConstraintType` 的语义，全部逐行相同。`constraints.go` 的 41 行差异
**不涉及注册表**。

为了让两侧调用点逐字相同，本模块**也**补上了 `checkConstraintsReg` /
`firstUnknownConstraintReg` / `isKnownConstraintTypeReg` 三个注册表参数化形式，
以及一个恒返回 `globalConstraintRegistry` 的 `admissionConstraintRegistry`
间接层，并把 `CheckAdmission` 里的 5 个调用点改成参数化形式。代价是本模块多了
约 20 行目前不派上用场的间接层；收益是这一段约束求值逻辑在两库间**逐行相同**，
`constraints.go` 也因此变成零差异文件。

真实差异只剩一处：aic-verifier 的 `admissionConstraintRegistry` 会优先取
`cfg.ConstraintRegistry`，本模块的版本恒取全局。

- 同输入同判定：`cfg.ConstraintRegistry` 为 nil（默认）且未调用
  `RegisterConstraint` / `ReplaceConstraint` 时，两侧解析到的是同一个
  `globalConstraintRegistry`。
- 分叉条件：仅当 aic-verifier 的使用方在 `AdmissionConfig.ConstraintRegistry`
  里挂了自定义注册表。"已知约束类型"集合随之改变，影响 `StrictConstraints` 下的
  `unknown constraint type %q` 拒绝与 `ActionUnknownConstraint` 审计条目。
  本模块没有按 admission 覆盖注册表的入口——网关侧的约束词表是固定的。

### 4.3 策略注入点（`policy.go`）

`aic-verifier` 的 `extractPolicyRoles(cert, policy)` 显式接收策略参数；
`gateway-core` 的 `ExtractPolicyRoles(cert)` 读全局
`GetAuthorizationPolicy()`。取到的角色集合相同，只是取策略的位置不同。

### 4.4 `VerifyDelegationAuth` 形参（`decision.go`）

`gateway-core` 是三参 `VerifyDelegationAuth(aic, userCert, agentCert)`；
`aic-verifier` 保留原两参 `VerifyDelegationAuth(aic, userCert)` 作为 wrapper，
新增 `VerifyDelegationAuthWithAgent(aic, userCert, agentCert)` 承担 v2 验证。
两者内部实现与拒绝原因完全相同，**这是为不破坏 aic-verifier 既有 API 稳定性
契约（见其 README）的刻意差异，不是遗漏**。aic-verifier 的准入路径与
delegation chain 均已改走三参版本。

### 4.5 仅本模块存在的能力

`gmsm.go`、`pipeline_aac.go`、`shortlived` / `confirmed_renewal`、
`selfverify`。`aic-verifier` 侧无对应物，属功能范围差异，不影响共同输入的
判定。

## 5. 本次修齐的分歧

### 5.1 aic-verifier → gateway-core

| 文件 | 问题 | 处理 |
|---|---|---|
| `constraints.go` | `RegisterGeoResolver` 写 `geoResolvers`，`checkGeoFence` 无同步读，`-race` 下可检测到数据竞争（可能 panic） | 加 `sync.RWMutex` 与 `lookupGeoResolver` |
| `tsa.go` | 4 处 ASN.1 解析缺陷：`FullBytes` 误用、嵌套 OCTET STRING 未解包、certs 之后未正确推进剩余数据、`parseSignerInfo` 静默吞掉 Unmarshal 错误并产出空签名者（下游报"签名验证失败"，真因丢失） | 全部改为传播错误；`parseSignerInfo` 改为返回 `error`，同步更新 `tsa_test.go` |
| `jwt.go` | `memReplayStore` 容量 4096；饱和时淘汰最旧条目——等于给 nonce 开重放窗口 | 容量提至 65536；饱和且仅有 live marker 时 fail-closed（可用性换安全性，注释已写明） |
| `crl.go` | HTTP 客户端无拨号/TLS 握手超时，单个 CRL 端点可拖住判定 | 加 5s 拨号、30s keepalive、5s 握手超时 |
| `nonce_cache.go` | `Stop()` 非幂等 | 改为幂等 + nil-safe |
| `ocsp.go` | `fallback_allow` 是唯一的 fail-open 路径，却不记录被放行的证书 | 增加一行不可翻译的 `[ERROR] ... ALLOWING certificate <CN> without revocation proof` |
| `merkle.go` | `string(hash) == string(root)` | 改 `bytes.Equal` |
| `decision_test.go` | `TestVerifyDelegationAuth_SPKIHashMismatch` 的夹具从未签出有效 TBS（漏 `RequestedLifetime`），却只断言 `err != nil`，长期假绿 | 重写夹具：复用同一时间戳、构造完整 `DelegationAuthTBS`，并加强断言 |

### 5.2 gateway-core → aic-verifier

| 文件 | 问题 | 处理 |
|---|---|---|
| `spiffe.go` `pipeline.go` | trust domain 未按 RFC 7555 §2.1 做大小写不敏感规范化；allowlist 用未规范化字符串比较 | 加 `canonicalSPIFFEID`、trust domain 小写化 + 字符集校验，allowlist 走规范化比较 |
| `decision.go` | `DefaultDAAgeMax = 30s`，与 `varwof/core` 常量不符 | 改为 `time.Minute` |
| `decision.go` | 不支持 DA v2 的 `agentKeyBinding` | 新增 `VerifyDelegationAuthWithAgent`（见 4.4） |
| `nonce_cache.go` | `maxScopeUse = 3` 上限 | **删除**（见 6.2） |

### 5.3 差异压缩（第二轮）

在功能不变的前提下把共享文件的差异从 290 行降到 60 行，18/22 个镜像文件变成
零差异：

| 动作 | 效果 |
|---|---|
| aic-verifier：CLC 实现整体搬进独有的 `clc.go` | `decision.go` 的 56 行授权循环、`aggregateCLCDecisions`、约束胶水离开共享文件 |
| aic-verifier：`applyCLCAdmissionConfig` 承担 7 个 CLC 字段的装配 | `pipeline.go` / `trust_model.go` 的 19 字段 `AdmissionConfig` 字面量两侧逐字相同 |
| aic-verifier：`denyWithAdmission` 抽出拒绝路径的回填 | `pipeline.go` 少 6 行 |
| 本模块：补 `*Reg` 参数化形式 + `admissionConstraintRegistry` 间接层 | 约束求值段两侧逐行相同，代价是本模块多约 20 行暂不派用场的间接层 |
| aic-verifier：从 gateway-core 移植 6 个 SPIFFE 大小写不敏感测试 | 见 5.4 |

`policy.go` 的 3 行差异**没有**压缩：AV 的 `extractPolicyRoles(cert, policy)`
支持按请求隔离策略（`Config.AuthorizationPolicy`），本模块读进程级全局。压掉它
等于删掉一个安全特性，因此保留。

### 5.4 一个被这个流程抓到的回归

压缩过程中对 `pipeline.go` 做过一次 `git checkout --`，把上一轮移植的 SPIFFE
规范化（`canonicalSPIFFEID` + trust domain 小写比较）一起抹掉了，而
`go test -race ./...` 全绿——因为 aic-verifier 当时**没有**覆盖这点的测试，
即第 8 节记录的那个缺口。已从 `spiffe_test.go` 移植
`TestParseSPIFFEID_TrustDomainLowercase`、`TestValidTrustDomainCharset`、
`TestCanonicalSPIFFEID`、`TestVerifySPIFFESAN_CaseInsensitiveTrustDomain`、
`TestPipelineSPIFFETrustDomainCaseVariant`、
`TestPipelineSPIFFEAllowedListCaseInsensitive` 到新的
`aic-verifier/spiffe_case_test.go`，并验证过：撤掉规范化后这 6 个测试确实失败。

教训：**镜像文件的测试也要成对移植**，否则 diff 干净并不代表行为一致。

### 5.5 两库共同修复

`verifyDelegationAuthTBS` 的 v1 → legacy-v0 回退会**掩盖真实错误**：
`PrincipalUid.KeyHash` 交叉校验失败后继续尝试 v0 编码，最终返回的是 v0 的
"签名验证失败"，而原 token 的签名其实是好的。两库均新增
`errDASignatureMismatch` 哨兵，回退仅在签名确实不匹配时发生。

## 6. 两处被否决的"对齐"

记录在此以免被重新引入。

### 6.1 core 文档里的 DA 30s

`varwof/core` 的 `docs/openapi.yaml:1147` 写 `da_max_timestamp_skew` 默认 30s，
`docs/bench/{zh,en}/benchmark-report-2026-08-27.md` 也按 "skew 30s" 推算 nonce
容量，但 `core/internal/config.go:208` 的
`DefaultDATimestampSkew = time.Minute` 是 1m。**文档陈旧，常量为准**。
`gateway-core` 原本就对，`aic-verifier` 向其对齐。

### 6.2 aic-verifier 的同 scope nonce 限次

`aic-verifier` 曾对同一 scope 的 nonce 复用设 `maxScopeUse = 3` 上限，看起来
更"fail-closed"，**但不能移植**：

- DA nonce 是 X.509 扩展里的静态值，不随请求轮换；
- `aic-verifier` 默认 `Config.NonceCache` 为 nil，该限制从未被触发；
- `gateway` 在 `http/gateway.go:82` 无条件创建 nonce cache，照搬会让
  长生命周期证书的代理**从第 4 个请求起全部被拒**。

结论：两边都不设同 scope 上限，仅保留跨 scope 重放拒绝。理由已写入两边
`nonce_cache.go` 的注释。

## 7. 权威值表

改动下列任何一项前，先回到来源确认。

| 值 | 权威来源 |
|---|---|
| `DefaultDAAgeMax = 1m` | `varwof/core` `internal.DefaultDATimestampSkew`（core 文档写 30s，已过时） |
| replay store 默认容量 65536，饱和 fail-closed | `jwt.go` `NewReplayNonceStore` 注释 |
| 同 scope nonce 复用不限次 | `nonce_cache.go` `CheckAndAdd` 注释 |
| SPIFFE trust domain 大小写不敏感 | RFC 7555 §2.1；实现见 `spiffe.go` |
| 内建约束类型共 8 个 | `aic-verifier/constraints.go` `init()`；本模块硬编码于 `constraints.go` |

## 8. 回归测试

| 测试 | 覆盖 |
|---|---|
| `TestNonceCacheScopeSeparation`（两库） | 同 scope 连续 64 次复用放行；跨 scope 拒绝 |
| `TestCheckDAFreshness`（aic-verifier） | 30s 通过 / 61s 拒绝（边界对齐 1m） |
| `TestVerifyDelegationAuth_SPKIHashMismatch`（本模块） | 签名有效但 keyHash 不匹配时，拒绝原因必须是 keyHash 交叉校验失败，不得被 v0 回退覆盖 |
| `TestVerifyDelegationAuth_ECDSA_Expired`（两库） | DA 过期 |
| `TestParseSPIFFEID_TrustDomainLowercase`、`TestCanonicalSPIFFEID`、`TestVerifySPIFFESAN_CaseInsensitiveTrustDomain`、`TestPipelineSPIFFETrustDomainCaseVariant`、`TestPipelineSPIFFEAllowedListCaseInsensitive`（本模块） | trust domain 大小写不敏感 |
| `TestOCSPFallbackAllowLogsWarning`（aic-verifier） | fail-open 路径必须留痕 |

### 已知测试缺口

两处，都是"实现已对齐、测试没跟上"，补齐前不要以"两边都验过"为由改这些行：

1. **本模块**同步了 `ocsp.go` 的 fail-open 留痕代码，但**没有**对应的
   `fallback_allow` 测试（该测试只存在于 aic-verifier 的
   `security_fixes_test.go`）。
2. ~~**aic-verifier** 同步了 `spiffe.go` 的规范化实现，但**没有**同步本模块
   `spiffe_test.go` 里的大小写不敏感测试~~ — **已于 5.4 关闭**，见
   `aic-verifier/spiffe_case_test.go`。

仍然成立的一般规则：`spiffe_test.go` / `decision_test.go` 这类**测试**文件不在
22 个镜像文件之列，容易只移植实现不移植测试。改共享逻辑时，测试要成对搬。

## 9. 如何复验

### 9.1 代码一致性

```sh
cd /path/to/gateway-core
for f in aic.go capregistry.go constraints.go credential_bundle.go crl.go \
         delegation_chain.go jwt.go mask.go merkle.go nonce_cache.go ocsp.go \
         parameters.go plugin.go rbac.go riskmonitor.go spiffe.go tsa.go \
         user_permission.go; do
  diff <(sed -e 's/^package .*/package X/' ../aic-verifier/$f) \
       <(sed -e 's/^package .*/package X/' "$f")
done
```

期望：零输出（`constraints.go` 起 18 个文件应完全一致）。

另外 4 个文件（`policy.go`、`trust_model.go`、`pipeline.go`、`decision.go`）
预期只剩第 4 节列出的接缝，共 60 行；超出即回归。

### 9.2 构建与测试

两库都必须通过（`aic-verifier` 额外跑 versioncheck 与 showcase）：

```sh
gofmt -l .            # 期望无输出
go vet ./...
go build ./...
go test -race ./...
./hack/versioncheck.sh                      # 仅 aic-verifier
go run ./examples/showcase                  # 仅 aic-verifier，期望 exit 0
```

## 10. 维护规则

1. 改动第 3.1 节任一文件时，先在 `aic-verifier` 落地，再复制到本模块，
   同一个 commit 内完成。包名 `aicverifier` → `gw`，import 路径相应替换。
2. 准入判定、拒绝原因字符串、TTL / 时间窗、fail-closed 行为必须逐字相同。
   拒绝原因字符串是跨实现的实际契约，**不得单方面修改**。
3. 新的分歧只能落在第 4 节的白名单里；超出白名单前先更新本报告。
   第 8 节的测试缺口同理，补齐前不得以「两边都验过」为由改那些行。
4. 每次同步后跑第 9 节，并更新第 2 节快照与第 5 节记录。
