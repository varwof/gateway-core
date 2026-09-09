# AAC → gateway-core 映射（aac-to-gateway-core-mapping）

> 说明本切片如何把 ACPs AAC v2.2.0 概念映射到 gateway-core 既有引擎，划清"复用 / 扩展 /
> 新增"边界，并记录每个 ACPs 概念对应的代码位置（`gw` 根包与新增 `acps` 包）。
> 要求基线见 `ACPs-v02.2-requirements.md`；符合性清单见 `conformance-matrix.md`。

## 1. 总体映射

| AAC 概念（规范位置） | gateway-core 既有能力 | 复用点 | 缺口 / 本切片处理 |
| --- | --- | --- | --- |
| 通信身份验证（§4 步骤1） | `mtls.go`、`decision.go CheckAdmission`、`pipeline.go RunAccessPipeline`（CRL/OCSP/有效期） | 证书链校验、AIC 解析、RBAC | AIP 身份绑定（CN vs SAN `acps://`）、`senderId == peer AIC` 需要新逻辑 → `acps` 包 |
| 受保护请求处理总流程（§4） | `RunAccessPipeline`（连接准入）+ `CheckOperationCapability`（操作层） | 既有两阶段执行点 | AAC 要求 "构造 AuthorizationRequest → PDP → enforce before business" → `pipeline_aac.go`（新文件，gw 包）包装 |
| Fail Closed（§5） | `DecisionAllow/Deny/NeedAuth`、admission 一律 deny 非 allow | not-allow==deny 语义 | PDP 未配置 / 策略缺失 / 解析失败也归 deny → `acps/pdp.go` |
| Subject ID（§6.1） | `Subject.CommonName`、AIC `AgentId`、`PrincipalUid` | 证书 CN 与 AIC | `subject:{issuer}#{sub}`、`agent:{aic}`、`service:...` 规范化 → `acps/aic.go`、`acps/context.go` |
| Primary/Immediate Actor（§6.2/6.3） | 证书 CN（现实驱动器）；`aicAgentID` 回退 | — | `VerifiedAuthorizationContext` 双字段构造 → `acps/context.go` |
| Actor Chain（§6.4） | `delegation_chain.go`（证书级委托链，DA 签名链、P1-B-14/15/16/17） | 证书级链的防环/深度/权限子集规则是 **token 级 actor_chain 的校验模板** | token/STS 级 chain 校验（末位 == immediate_actor、深度上限、来源可验证）→ `acps/delegation.go` |
| AuthorizationRequest/Decision（§6.6） | `Capability`、`PluginRegistry`、`MatchCapabilityRules` | 资源-动作可用 `capabilityId` 表达 | 规范化 request/decision + obligations → `acps/pdp.go` |
| 委托模式 & Boundary（§10） | `DelegationAuthorization`（DA）、`DelegationChainVerifier.MaxDepth` | depth 上限语义 | 动态/固定委托边界（boundary id/hash/route/partner 集/chain depth）→ `acps/delegation.go` |
| Delegation Token 字段（§10.2/10.3） | `aicjwt.OuterClaims`（iss/sub/aud/exp/iat/jti/aic） | token 基础校验（签名/有效期/aud/jti）已在 aicjwt | `acps_delegation_*` 字段解析 + 必填字段校验 → `acps/delegation.go` |
| 上下文提供者（§7） | `mtls.go`（mTLS 来源）、`PolicyServer` 接口 | provider 抽象可以包装既有来源 | `ContextProvider` 接口 + `MTLSProvider`/`TokenProvider` 实现 → `acps/context.go` |
| 裁决模型（§8） | RBAC（`policy.go` roles/grants、`CheckRole`）+ Capability 决策 | AAC wrapper 复用网关 RBAC 裁决 | PDP 将 RBAC 裁决封装为 allow/deny + reason_code → `acps/pdp.go` |
| 通信 Profile A/B/C/D（§9） | `DisallowRepresentative`、`RequireAIC`、既有 profile 支持 | Profile B 由 mTLS+AIC 天然覆盖 | Profile C/D 需要 primary=originator 的多跳语义 → `acps/context.go` |
| 错误映射（§12） | 自定义错误类型；gateway 内部无 AIP JSON-RPC 码 | — | `-32008/-32009/-32010` 三码 + 对外不泄露细节 → `acps/errors.go` |
| 审计（§13） | `AuditLogger.Log(AuditEntry)`（JSON Lines、异步、关键事件不丢弃） | 复用写日志/轮转/TSA | AuditEntry 无 actor_chain/delegation_id/reason_code 字段 → `acps.AuditRecord` + `pipeline_aac.go` 适配器映射为 AuditEntry（不改 audit.go 结构） |
| 安全-不信任自报（§14.5） | `pipeline.go` 阶段二 fail-closed、"未注册→拒绝" | 既有 fail-closed 哲学 | `delegation.go` 硬性拒绝 未签名/未绑定/仅 payload 自报 record → `acps/delegation.go` |
| 最小权限/收窄（§14.1、§10.5） | P∩C 交集（`CheckAdmission.EffectiveCaps`） | 授权不扩大 | boundary 中 aud/scope 收窄校验 → `acps/delegation.go` |
| Token 绑定（§14.2） | `JWTVerifier.SetBearerPolicy` / `PresenterKey`（cnf 绑定） | 证书绑定 token 的可复用底座 | `cnf` 与 peer 证书匹配的 AAC 断言 → `acps/delegation.go` + `pipeline_aac.go` |

## 2. AIC 映射（AIC-v02.02）

| AIC 规范要求 | gateway-core 现有 | 本切片处理（acps/aic.go） |
| --- | --- | --- |
| 语法 `1.2.156.3088.…` 每级 `0-9A-Z`（不区分大小写） | 无独立 ACPs-AIC 解析 | `ParseAIC(raw)`：前缀、总级数、逐级字符约束（大小写归一） |
| 第 5 级版本号 `1~Z` | — | `ParseAIC` 内嵌校验：单字符、`1..Z` |
| 第 9 级 `0` 表示本体 | — | `IsBody()` 辅助（语义字段，不参与结构校验） |
| 第 10 级校验码（CRC-16/CCITT-FALSE + ARSP salt，Base36 4 位） | — | `VerifyChecksum(code, salt)`：可配置 salt（≥2 字节）；**salt 未配置只做结构校验**并在文档声明 |
| 统一大写 normalization | — | `NormalizeAICText(raw)`：大写化 + 校验入口 |
| 生成的 subject | — | `SubjectID(aic) = "agent:"+NormalizeAICText(aic)` |

## 3. 委托上下文映射（delegation.go）

| 语义（§6.4/§7.4/§10） | 实现 |
| --- | --- |
| DelegationToken（已验证 token 声明的结构化视图） | `delegation.go: DelegationToken`（iss/sub/aud/exp/iat/jti/scope/act + acps_* 字段） |
| 必填字段（§10.2） | `ValidateRequiredClaims`：iss/sub/aud/exp/iat/jti/scope/act 缺一即拒绝 |
| 来源可信（§14.5⑥） | `FromSelfClaimedPayload` **显式标注 Asserted 并强制拒绝**；`Validate` 要求 签名+必填+有效期+绑定 全过（`ErrSelfClaimed` / `ErrUnsignedDelegation` / `ErrUnboundDelegation`） |
| 委托边界（§10.1/10.7） | `BoundaryState`：boundary id/hash、delegation_id、mode(fixed/dynamic)、max_chain_depth、chain_depth、allowed_route、allowed_partner_aics |
| 边界校验（fail closed） | `BoundaryState.ValidateNext(next *DelegationToken)`（`DelegationToken.Boundary()` 构造）：深度、route/partner 集、aud/scope 收窄不扩大 |
| actor chain 末位绑定（§6.4③） | `actor_chain[len-1] == immediate_actor` 不成立 → 上下文无效 |

## 4. 上下文构造映射（context.go）

| 概念 | 实现 |
| --- | --- |
| ContextProvider | 接口：`Name() string` + `Verify(input any) (*ProviderResult, error)`（结果即已验证声明） |
| MTLSProvider | 输入 peer 证书 → 提取并校验 AIC（+CN/SAN 绑定），输出 `agent:{aic}` immediate actor |
| TokenProvider | 输入 delegation token + presenter 证书 → 校验签名/aud/exp/jti/act/cnf，输出 primary/actor_chain/boundary |
| VerifiedAuthorizationContext | primary_subject / immediate_actor / actor_chain / resource / action / environment / client_actor / authorization_events / providers |
| 构造失败（provider 失败/resolver 失败） | `BuildContext(BuildOptions)` 返回错误 → 调用方按 deny 处理（fail closed） |

## 5. 裁决映射（pdp.go）

| AAC 要求 | 实现 |
| --- | --- |
| PEP 构造规范化 request（§6.6） | `PDP.Decide(req *AuthorizationRequest)` |
| 只有 allow 才允许（§4⑤/§5⑦） | `AuthorizationDecision{Allowed, ReasonCode, Obligations}`；非 allow 一律 deny |
| 上下文可信但策略不允许（§12 表） | `-32009` reason 映射 |
| obligations（§6.6） | `EvaluateObligations` 全部执行或按 deny |
| 内嵌策略模型 | `PolicyFunc`（RBAC/Capability 判定注入网关权威判据）+ 默认 fail closed |
| impersonation 默认禁止（§14.4） | `AllowImpersonation` 默认 false；自报 impersonation 一律拒绝 |

## 6. 执行 & 审计映射（pipeline_aac.go + errors.go）

| AAC 要求 | 实现 |
| --- | --- |
| 执行点在业务处理前强制执行（§4） | `RunAccessPipelineAAC(chain, cfg, aac, req)`：先跑既有 `RunAccessPipeline`（默认行为），启用 AAC 后叠加身份绑定→可信上下文→PDP 裁决，**deny 在返回给业务前终止** |
| 审计（§13） | `acps.AuditRecord`（decision/reason_code/primary/immediate/actor_chain/resource/action/providers/token 摘要，**不含 token 原文**）；gw 适配器写 `AuditEntry`（Level=WARN for deny） |
| 错误对外不泄露细节（§12） | `aacPublicMessage(code)` 只暴露 `Authentication required` / `Authorization failed` / `Invalid access token`；明细进审计 |
| 错误码（AIP 表） | `CodeAuthenticationRequired(-32008)`、`CodeAuthorizationFailed(-32009)`、`CodeAccessTokenInvalid(-32010)` |

## 7. 未复用 / 待扩展说明

- `AuditEntry` 结构不新增字段（避免改 audit.go）；AAC 审计明细以 `acps.AuditRecord` 承载，
  由 `pipeline_aac.go` 适配器映射为既有 `AuditEntry` 字段（Decision/DenyReason/PrincipalUid/
  Capabilities/Level）并保留 trace 关联。
- `pipeline.go`（有未提交 SPIFFE 改动）**不修改**：AAC 入参独立定义在 `pipeline_aac.go`，
  通过新的 `RunAccessPipelineAAC` 包装既有管线，`PipelineConfig` 不变，默认行为不变。
- 外部 STS / Token Exchange 联调不在 v0：`TokenProvider` 用本地确定性签名（测试密钥）演示
  绑定逻辑，接口与生产 STS 一致。
- Replay（§14.3(2)）复用 gateway-core 的 `NonceCache.CheckAndAdd(scope, nonce)`：
  - 一次性使用语义由 `AACProfileConfig.ReplayGuard`（`pipeline_aac.go: ReplayGuard`）保证——
    `NonceCache` 的契约是"同一证书重复同一 nonce 视为重传、放行"，与 jti 一次性使用（任何
    二次使用都拒绝）冲突；
  - `NonceCache` 作为跨证书防重放（同一 jti 被不同 peer 证书再次呈现 → 拒绝），双保险。