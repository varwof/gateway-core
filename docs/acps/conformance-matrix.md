# ACPs v2.2.0 → gateway-core 一致性矩阵

锚点：ACPs-community tag **v2.2.0**（commit `3985c1330209f075c124669cc9d31f0e75448140`）。
实现：`acps` 包 + `pipeline_aac.go`（gw 包）的 **v0 实验切片**。
状态：✅ 已实现并测试 · 🟡 部分实现（v0 边界内） · ⛔ 不在 v0（fail closed / 预留接口）。

## AIC（Agent Identity Code）

| 条款 | 要求 | 状态 | 位置 | 测试 |
| --- | --- | --- | --- | --- |
| §3 | 结构：前缀 `1.2.156.3088`、10 层、版本、序列范围、null 实体 | ✅ | `acps/aic.go: ParseAIC` | `aic_test.go: TestParseAIC_*` |
| §3 | 字符集 0-9/A-Z，大小写不敏感 | ✅ | `NormalizeAICText` | `TestParseAIC_LowercaseNormalized` |
| §4.1 | CRC-16/CCITT-FALSE（0x1021，init 0xFFFF）+ ARSP salt ≥2 字节，Base36 4 位 | ✅ | `CRC16CCITTFALSE` / `VerifyChecksum` / `Base36Encode` | `TestCRC16CCITTFALSE_SpecVector`（0x646C→`0JU4`） |
| §4.2 | 校验码验证：无 salt → 结构验证（`ChecksumValidated=false`）；有 salt → 完整 CRC | 🟡 | `Verify` | `TestVerifyChecksum_*` |
| `1.2.156.3088.1.1.34C2.478BDF.3GF546.0JU4` | spec 示例可解析 | ✅ | — | `TestParseAIC_Valid` |

## AIA / AIP 身份（subset，AIP §6.0）

| 条款 | 要求 | 状态 | 位置 | 测试 |
| --- | --- | --- | --- | --- |
| 4.1 | mTLS 证书携带 AIC（ext-key-usage clientAuth + AIC 扩展/AIA OID） | 🟡 | v0 从 SAN `acps://` + Subject CN 读取；an.4/attrs 扩展不解析 | `ExtractPeerAIC` |
| §6.0 / 4.2 | Subject CN 为主来源、SAN acps:// 为补充来源，两者必须一致 | ✅ | `acps/aic.go: ExtractPeerAIC` | `TestExtractPeerAIC_CNAndSAN*` |
| §6.0 / 4.3 | 证书无身份 / CN 无效 / SAN 缺失（strict）→ 无效 | ✅ | `ExtractPeerAIC` + `RequireSAN` | `TestExtractPeerAIC_*` |
| §6.0 | senderId 与对端 AIC 一致性 | ✅ | `pipeline_aac.go`（`MatchPeerAIC`） | `TestRunAccessPipelineAAC_SenderIDMismatch` |
| — | AIP JSON-RPC 错误码 -32008/-32009/-32010 | ✅ | `acps/errors.go` | `context_test.go`（AACError.Code） |

## AAC 总体流程（§4）与 Fail Closed（§5）

| 条款 | 要求 | 状态 | 位置 | 测试 |
| --- | --- | --- | --- | --- |
| §4 step 1-2 | 通道身份（mTLS）→ 委托 token | ✅ | `pipeline_aac.go` | `TestRunAccessPipelineAAC_*` |
| §4 step 3 | 上下文提供者构建可信上下文 | ✅ | `acps/context.go: BuildContext` | `context_test.go: TestBuildContext_*` |
| §4 step 4-5 | PDP 裁决 + 审计 | ✅ | `acps/pdp.go: Decide` | `pdp_test.go` |
| §5(6) | 无策略 = deny | ✅ | `pdp.go`（nil Policy） | `TestPDP_NilPolicyFailsClosed` |
| §5(7) | 非显式 allow = deny | ✅ | `pdp.go` | `TestPDP_PolicyReturnsNilFailsClosed` |
| §5 | provider 失败 = 上下文无效 = deny | ✅ | `BuildContext` | `TestBuildContext_*` |
| §6.6 | 义务（obligation）不满足 → allow 撤销为 deny | ✅ | `pdp.go: ObligationEvaluators` | `TestPDP_AllowObligationUnsatisfied` |

## 主体 / 链 / 上下文（§6）

| 条款 | 要求 | 状态 | 位置 | 测试 |
| --- | --- | --- | --- | --- |
| §6.1 | human/agent/service/related 规范化 SubjectID | ✅ | `acps/context.go` | `TestSubjectBuilders` |
| §6.3/6.4 | immediate + actor_chain（tail==immediate） | ✅ | `BuildContext` / `EffectiveActorChain` | `TestBuildContext_DelegationOverridesChain`; `TestDelegation_EffectiveActorChain*` |
| §6.6 | AuthorizationRequest 形状（主体/动作/资源/环境） | ✅ | `context.go` | `pdp_test.go: testRequest` |
| §6.7 | audience = `acps:agent:{AIC}`；Boundary 校验 aud 不越界 | ✅ | `CanonicalAudience`/`ValidateNext` | `TestBoundaryState_ValidateNext_AudienceAndScope` |
| §9.5 | 事件必须来自 provider（带 Source） | ✅ | `NewVerifiedAuthorizationEvent` / `BuildContext` | `TestBuildContext_UnverifiedEventRejected` |

## 上下文提供者（§7）

| 条款 | 要求 | 状态 | 位置 | 测试 |
| --- | --- | --- | --- | --- |
| §7.1 | mTLS 提供者：peer AIC → agent 主体 | ✅ | `MTLSProvider` | `TestMTLSProvider_Verify*` |
| §7.4/§10 | Token Exchange 提供者：delegation token → primary/actor/boundary | ✅ | `TokenProvider` | `TestTokenProvider_Verify*` |
| §7.5/§7.6 | provider 失败即上下文无效（fail closed） | ✅ | `BuildContext` | `TestBuildContext_*` |
| — | STS / 外部 Token Exchange 联调 | ⛔ | 接口预留、本地签名演示 | `TestTokenProvider_Verify` |

## 委托与边界（§10）

| 条款 | 要求 | 状态 | 位置 | 测试 |
| --- | --- | --- | --- | --- |
| §10.1 | fixed / dynamic 两种模式 | ✅ | `DelegationToken.DelegationMode` | `TestBoundaryState_ValidateNext_FixedRoute/DynamicPartner` |
| §10.2 | 必需字段 iss/sub/aud/exp/iat/jti/scope/act 缺一即拒 | ✅ | `ValidateRequiredClaims` | `TestDelegation_Validate_MissingRequiredClaim` |
| §10.2 | exp/iat/nbf 生命周期 | ✅ | `ValidateLifetime` | `TestDelegation_Validate_Expired` |
| §10.3 | 推荐字段（含 `acps_*`）解析 | ✅ | `FromTokenClaims` | `delegation_test.go` |
| §10.6/10.7 | 边界：fixed 路由 / dynamic 伙伴集 / 深度 | ✅ | `BoundaryState.ValidateNext` | `TestBoundaryState_ValidateNext_*` |
| §14.1(2) | scope 只收窄不扩宽 | ✅ | `ScopeNarrowed` | `TestScopeNarrowed`; `TestBoundaryState_ValidateNext_AudienceAndScope` |
| §9.4(5) | chain depth ≤ max | ✅ | `ValidateNext` / `RunAccessPipelineAAC` | `TestBoundaryState_ValidateNext_Depth` |

## 认证 / 绑定 / 重放（§12、§13、§14）

| 条款 | 要求 | 状态 | 位置 | 测试 |
| --- | --- | --- | --- | --- |
| §12 | 对外消息不泄露细节（三种公共消息） | ✅ | `errors.go` / `pipeline_aac.go` publicMessage | `TestRunAccessPipelineAAC_*` |
| §14.2 | presenter 绑定（证书 SPKI / cnf） | ✅ | `BindToPresenter` / `PresenterMatches` / `Validate` | `TestDelegation_Validate_CNFBinding` |
| §14.3(2) | jti/一次性 token 重放 | ✅ | `pipeline_aac.go: ReplayGuard`（一次使用）＋ `NonceCache`（跨证书） | `TestRunAccessPipelineAAC_BearerAndReplay` |
| §14.4 | impersonation 默认拒绝、显式授权放行 | ✅ | `PDP.AllowImpersonation` | `TestPDP_Impersonation*` |
| §14.5(1)(2)(6) | 自声明 payload 拒绝（unsigned/unbound/asserted） | ✅ | `Validate`（Asserted/签名/绑定） | `TestDelegation_Validate_SelfClaimed/Unsigned/Unbound` |
| §13 | 审计不记 token 原文 | ✅ | `AuditRecord`/`TokenAuditRef` | `TestPDP_AllowWithObligationsSatisfied` |
| §13(4) | 高风险原因 WARN | ✅ | `HighRiskReasons` + gw 适配器 | `TestPDP_ImpersonationDeniedByDefault`; `TestRunAccessPipelineAAC_AuditLoggerDrain` |

## 网关集成（pipeline_aac.go）

| 行为 | 状态 | 测试 |
| --- | --- | --- |
| 未启用 AAC → 与既有 `RunAccessPipeline` 完全一致 | ✅ | `TestRunAccessPipelineAAC_DisabledPassthrough` |
| 无对端身份 → `Authentication required` | ✅ | `TestRunAccessPipelineAAC_MissingIdentity` |
| senderId 不一致 → `Authorization failed` | ✅ | `TestRunAccessPipelineAAC_SenderIDMismatch` |
| 无策略 → `Authorization failed`（PDP 不可用） | ✅ | `TestRunAccessPipelineAAC_NilPolicyFailsClosed` |
| 策略 allow → Granted；deny → 仅公共消息 | ✅ | `TestRunAccessPipelineAAC_Allow` |
| 审计：AuditSink 与 AuditLogger 两条路径 | ✅ | `TestRunAccessPipelineAAC_AuditSink` / `_AuditLoggerDrain` |

## v0 之外（⛔）

- OIDC/OAuth2 完整授权码流程、Authorization Server 集成
- 外部 STS / Token Exchange 生产联调（v0 为本地确定性签名演示）
- ACI 私有 CA、ADP、Linked-in 关联、CIEM/CM 策略语言
- AIA an.4 扩展、AIC attr/assertion 扩展解析（仅 SAN+CN 读取）
- 多节点共享 replay 存储（进程内实现；接口保留）

> 所有 ⛔ 项在实现缺失时均 fail closed，不放松授权安全边界。