# ACPs v2.2.0 → gateway-core 接线矩阵

锚点：ACPs-community tag **v2.2.0**（commit `3985c1330209f075c124669cc9d31f0e75448140`；规范与参考实现仓库：https://github.com/AIP-PUB/ACPs-community ）。
切片：`acps` 包 + `pipeline_aac.go`（gw 包）的 **v0 实验切片**。快速验证入口见 `docs/acps/README.md`。

## 与一致性矩阵的关系（先读这段）

`conformance-matrix.md` 里的 ✅ 表示 **「已实现并测试」**——语义是**库级**：该条款有实现、有单测，但**不保证已进入任何运行路径**。
本矩阵回答的是另一个问题：**每一项能力在非测试代码里到底被谁消费**。两者语义不同，勿混读。

状态（接线维度）：
- ✅ **已接线**——该能力在当前网关运行路径（`RunAccessPipelineAAC`）中生效
- 🟢 **演示接线**——仅在冒烟/演示 CLI（`cmd/acps-smoke`）中接线，不在网关路径
- 🟡 **库实现、待接线**——库功能完整且有测试，但没有接入任何非测试路径，需集成方在验证流程中显式调用
- ⛔ **仅库级/自用**——本切片未为其提供任何非测试消费点

## 接线矩阵

| 规范条款 | 包内符号 | 接线点 | 状态 |
| --- | --- | --- | --- |
| AIP §6.0 + AIC §3-4 | `ExtractPeerAIC` / `Verify` | `pipeline_aac.go`（`RunAccessPipelineAAC`，步骤 1） | ✅ 已接线 |
| AIP §6.0 | `MatchPeerAIC` | 同上（步骤 2，senderId ↔ 对端 AIC 一致性） | ✅ 已接线 |
| AAC §7 | `MTLSProvider` / `TokenProvider` / `BuildContext`(+`BuildOptions`) | 同上（步骤 3，可信上下文构建，provider 失败 fail-closed） | ✅ 已接线 |
| AAC §4/§5/§8 | `PDP` / `Decide` / `PolicyFunc` | 同上（步骤 5，策略裁决；nil policy / 非显式 allow 均 deny） | ✅ 已接线 |
| AAC §6.6 | `ObligationEvaluator` | 同上（配置传入 `PDP`，`Decide` 内由 `EvaluateObligations` 调度）；**切片未内置具体义务器，空配置即短路** | ✅ 已接线（机制接通） |
| AAC §12/§13 | `AuditRecord` / `HighRiskReasons` / `Code*` | 同上（all-path 审计 + 对外仅暴露三种公开消息） | ✅ 已接线 |
| AAC §14.3(2) | `ReplayGuard` / `NonceCache` | 同上（步骤 4，jti 一次性 + 跨证书防重放；由 gw 包实现，非 acps 包） | ✅ 已接线 |
| AAC §6.6 | `AuthorizationResource` | 同上（`AACRequest.Resource` 入参） | ✅ 已接线 |
| AIP §6.0 | `Allow` / `SignRecord` / `NewSignedDelegation` / `FromTokenClaims` / `DelegationModeDynamic` / `AuthorizationRequest` / `AuthorizationDecision` | `cmd/acps-smoke/main.go`（演示 + 端到端自检） | 🟢 演示接线 |
| AAC §14.2 | `BindToPresenter` / `PresenterMatches` / `DelegationRecord.Validate` | **无网关接线**——由网关既有 JWT 验证器承担签名与 presenter 绑定校验 | 🟡 库实现、待接线 |
| AAC §10.6/§14.5 | `VerifyDelegation` / `BoundaryState.ValidateNext` / `FromSelfClaimedPayload` / `ScopeNarrowed` | 无（库级 + 单测） | ⛔ 仅库级 |
| AIC 规范化 | `ParseAIC` / `NormalizeAICText` / `CRC16CCITTFALSE` / `Base36Encode` / `VerifyChecksum` | 经 `Verify`/`ExtractPeerAIC` 间接进入运行路径 | ✅ 间接接线 |
| 规范 §6.1 | `AgentSubject` / `HumanSubject` / `ServiceSubject` / `RelatedSubject` / `SubjectID` / `CanonicalAudience` | 无（包内 + 单测） | ⛔ 仅库级 |

## 集成契约（责任边界）

当前的接线形态是一个**可选信封**：`RunAccessPipelineAAC(chain, cfg, aac, req)` 先跑既有 `RunAccessPipeline`，仅在 AAC 启用时叠加强制层（身份绑定 → 上下文构建 → 策略裁决 → 重放防护 → 审计）。

**委托 token 的验签责任：**
`RunAccessPipelineAAC` 的 bearer 委托 token **假定已由网关既有 JWT 验证器完成签名校验**（与 `AACRequest.Bearer` 注释一致——「already crypto-verified by the gateway JWT verifier」）；AAC 信封负责身份绑定、上下文构建、策略裁决与重放防护。**委托链的深度校验（`VerifyDelegation`）为库级能力，由验证路径在集成时调用**，信封内不重复验签。

含义：若集成方绕过网关 JWT 验证器、直接把未验签的 token 塞进 `AACRequest.Bearer`，签名与 presenter 绑定校验将缺位。这既是当前切片的如实边界，也是留给规范作者的一个接口问题（见外联信问题 4）。

## 安全默认与显式配置

启用 AAC 后以下控制**默认关闭**，属合法但不缺席的 opt-in 配置。`AACProfileConfig.Validate()` 会逐项给出运维告警（并发验证）：`RunAccessPipelineAAC` 首次遇到同一 profile 时经审计通道以 INFO 打出一条 `aac_config_warning`，弱默认不再「静默」（见 `TestRunAccessPipelineAAC_ConfigWarnOnce`）。

| 控制 | 关闭时的行为 | 显式打开 |
| --- | --- | --- |
| AIC 校验码 | 仅结构校验（§4.2；salt 为 ARSP 内分泌，开启需合规放行） | `AACSalt`（≥2 字节，见 `MinSaltLen`） |
| 委托链深度 | 不限制（`MaxChainDepth<=0`） | `MaxChainDepth` |
| jti 一次性（§14.3(2)） | 不查重放（`ReplayGuard=nil`） | `NewReplayGuard()` / `NewReplayGuardLimited` |
| 跨证书 jti 重放 | 不检查（`NonceCache=nil`） | 网关 `NonceCache` |
| 义务（§6.6） | 无义务器即短路放行 | `ObligationEvaluators` |
| 兜底 | nil `Policy` fail-closed（§5(6)） | `PolicyFunc` |

**ReplayGuard 有界性**：`NewReplayGuard()` 默认上界 100 万条 / TTL 24h；满容量时先清过期再淘汰单条，进程内上限恒定。仍为**单实例**，跨节点共享重放状态需外部存储（v0 范围外）。

## 观测与压测

- **指标**（Prometheus 文本格式，经 `metrics.go` 全局注册表导出）：
  - `aac_decision_total{decision=allow|deny, reason=<内部原因码或 allow>}`
  - `aac_decision_duration_ms`（决策耗时直方图）
- **审计通道**：决策走 `AuditRecord` → `AuditSink` / 网关 `AuditLogger`（allow=INFO / deny=WARN），配置告警走 `aac_config_warning`（INFO）。
- **健壮性**：`acps/fuzz_test.go`（ParseAIC / NormalizeAICText / VerifyChecksum / FromTokenClaims，5s 破 10 万 execs 无崩溃）、`acps/bench_test.go`（Verify≈3.2µs、ContextConstruction≈127µs/157 alloc，本机基线）。
- **限制**：无跨实现交叉测试（对照 aic-lib 三语言交叉），无恶意 token 规模化攻击模拟。

## 对外口径

- 本切片是 v0 实验实现：**实现完整 ≠ 已上线**。对外展示一致性矩阵时，应同时挂出本矩阵，避免「✅ 被读成已生效」。
- 所有 🟡/⛔ 项缺失时均 fail-closed（不放松授权安全边界）；接线缺位不扩大授权面，仅意味着相关能力未在本切片中激活。