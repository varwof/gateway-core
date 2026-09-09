# ACPs v2.2.0 AAC 兼容要求（requirements 基线）

> 本文件提取 ACPs v2.2.0 各规范中对本次实现有约束力的 **要求项**，作为 `acps` 包的实现基线
> （v0 纵向切片）。每条要求给出规范定位（manifest + 章节/行号）与本实现的处理方式，供
> 代码审查与 conformance-matrix 追溯使用。
>
> - 规范基线 tag：`ACPs-community v2.2.0`，commit `3985c1330209f075c124669cc9d31f0e75448140`
> - 本文件只 **转述** 规范语义，不复制规范正文；代码中只引用条款号（见各实现文件头注释）。

## 1. 范围

本切片覆盖 ACPs **AAC**（智能体访问控制）的核心闭环，并选取 **AIC / AIA / AIP** 中与
AAC 直接相关的子集：

| 规范 | 全称 | 定位 |
| --- | --- | --- |
| AAC | 智能体访问控制（ACPs-spec-AAC-v02.02） | 主规范，定义上下文、裁决、执行、审计 |
| AIC | 智能体身份码（ACPs-spec-AIC-v02.02） | 身份码语法与校验码 |
| AIA | 智能体身份认证（ACPs-spec-AIA-v02.02） | mTLS/CAI 载体下 AIC 的来源 |
| AIP | 智能体交互协议（ACPs-spec-AIP-v02.02） | 身份绑定与 JSON-RPC 错误码映射 |

不在本切片范围（v1+ 候选）：OIDC/OAuth2 完整授权码流、与 STS/Token Exchange 服务的
联调、ACI（可信执行体）与私有 CA 集成、ADP 发现、连屏（Linked in）真实身份证明等。

## 2. 总体流程（AAC §4）

AAC §4（行 65-101）要求任何受保护请求按如下顺序处理，且 **只有 allow 才能进入业务
handler**：

1. 验证通信身份（mTLS peer 证书、TLS server 证书、AIP `senderId` 绑定）；
2. 验证 token / session（签名、issuer、audience、expiry、scope、`act`、`cnf`）；
3. 构造可信授权上下文（primary subject、immediate actor、actor chain、authorization
   events、resource、action、environment）；
4. 授权裁决（ACL / RBAC / ABAC / ReBAC / OPA 或等价模型 → allow / deny）；
5. **执行裁决：deny 或上下文错误必须在业务逻辑前终止**；
6. 记录审计（主体、actor、资源、动作、决策、原因码、token jti / delegation id，不记录
   完整 token）。

> 本实现要求 1-6 全部成立：`acps.PDP.Decide` 返回 deny / error 时，调用方（gateway 侧
> enforcement）不得进入业务处理（见 `pdp.go` 的 `DenyBeforeBusiness` 约定与 `pipeline_aac.go`
> 的 enforcement 包装）。

## 3. Fail Closed（AAC §5）

AAC §5（行 103-119）规定以下情况 **必须拒绝**：

1. 必需的身份认证凭据缺失；
2. token、证书、session、delegation chain 验证失败；
3. issuer、audience、expiry、scope、actor binding、certificate binding 不满足；
4. AIP `senderId` 与已认证 peer AIC 不一致；
5. resource、action、skillId、taskId、groupId 无法解析；
6. PDP 不可用、策略文件缺失或格式错误且无显式降级策略；
7. **授权裁决结果不是明确 allow**（not-allow == deny）。

> 本实现：`PDP.Decide` 只返回两种结果之一——`allow` 或 `deny`（含 reason_code）。
> 解析失败、策略缺失、PDP 未配置一律归入 deny（fail closed），不存在"缺失即放行"路径。

## 4. 可信授权上下文（AAC §6）

### 4.1 Subject ID 规范（§6.1，行 123-143）

- 可执行主体形态：真人 `human:{issuer}#{sub}`、Agent `agent:{aic}`、服务账号
  `service:{issuer}#{client_id}`；
- 组织 `org:{org_id}`、租户 `tenant:{tenant_id}` 为关联主体，不作为直接请求发起方；
- **subject ID 不得由未经验证的 payload 字段直接生成**。

> 本实现：`SubjectID` 仅在已知来源（已验证证书 AIC / 已验证 binding 的 token 声明）之上构造；
> AIP payload 自报字段不允许进入 `VerifiedAuthorizationContext`（见 §13.5）。

### 4.2 Primary Subject（§6.2，行 145-156）

`primary_subject` 表示当前请求代表谁执行。Agent 多跳场景应为原始发起者
`agent:{originator_aic}` 或 `human:{issuer}#{sub}`，不得是当前 hop 的 actor。

### 4.3 Immediate Actor（§6.3，行 158-174）

`immediate_actor` 是当前一跳的直接调用方：

- Agent→Agent：`immediate_actor = agent:{mTLS peer AIC}`；
- 真人→Agent：`immediate_actor = primary_subject`；
- OAuth client（浏览器/CLI/服务账号）作为 `client_actor` 或上下文属性记录，**不得覆盖**
  primary/immediate 语义。

### 4.4 Actor Chain（§6.4，行 176-207）

- `actor_chain = [origin_actor, ..., immediate_actor]`；
- **必须来自可验证凭据**（Token Exchange token / 签名 delegation token / STS 查询结果）；
- Resource Server **不得信任** AIP payload 中未签名、未绑定、未验证的 `agentChain`；
- **最后一个 actor 必须与当前已认证的 immediate_actor 一致**；
- 历史 actor 可用于授权/审计/风控，但不能自动赋予当前 actor 权限。

> 本实现：`DelegationBoundary`/`VerifiedAuthorizationContext` 要求 `actor_chain[len-1] ==
> immediate_actor`，不一致即上下文无效（fail closed）。

### 4.5 AuthorizationRequest 与 Decision（§6.6，行 234-282）

PEP 先将规范化后的 `AuthorizationRequest` 交给 PDP 裁决，PDP 返回
`{allowed, reasonCode?, obligations?}`。若 PDP 返回 obligations，PEP 必须在进入业务 handler
前执行或确认；无法执行 → 按 deny 处理。

> 本实现：`AuthorizationRequest`（primary subject / actor / action / resource / environment /
> verifiedContext）+ `AuthorizationDecision{Allowed, ReasonCode, Obligations}`。obligations
> 检查失败由 enforcement 归入 deny（`EvaluateObligations` 默认全执行或拒绝）。

### 4.6 Resource Server 与 Audience（§6.7，行 284-300）

- 每台 Resource Server 定义稳定 canonical audience：Agent Partner 推荐
  `acps:agent:{normalized_aic}`；
- `aud` 必须等于 canonical audience 或经本地可信配置映射的可信 alias；alias 映射须进审计；
- audience 标识 Resource Server，不标识具体 Skill（Skill 通过 `skillId` 等资源字段裁决）。

## 5. 上下文提供者（AAC §7）

- **§7.1 mTLS / CAI / AIC**（行 304-331）：peer 证书 → CA 校验 → 提取 AIC → 身份上下文；详见
  §9 AIA 与 AIP。
- **§7.2 OIDC ID Token**、**§7.3 OAuth 2.0 Access Token**（行 333-391）：签名/issuer/audience/
  expiry/scope 校验，只作为上下文输入，不直接等同授权。
- **§7.4 Token Exchange 与 Delegation Token**（行 392-431）：Token Exchange 或 delegation
  token 用于跨跳传递 primary subject / actor chain / authorization events / scope / audience /
  expiry / delegation id / **delegation boundary**；接收方仍必须做策略裁决。
- **§7.5 Local Session**（行 433-445）：session 须由已验证流程创建、id 高随机、principal 属性
  有来源与过期策略；访问 Partner 时应转换为面向 Partner 的 token，不得透传 session id。
- **§7.6 Subject Resolver**（行 447-465）：resolver 查询键必须来自已验证上下文；resolver 失败 /
  主体不存在 / 不一致 **必须 fail closed**；返回数据应标注来源、版本、更新时间和缓存命中。

> 本实现：`ContextProvider` 接口抽象上述五类提供者；内置 `MTLSProvider`（证书→AIC）与
> `TokenProvider`（已验证 delegation token → primary/actor chain/boundary）。resolver 失败、
> provider 返回无效结果一律导致上下文无效（deny）。

## 6. 授权裁决模型（AAC §8）

AAC §8（行 467-599）不限定唯一模型，但裁决必须基于 `AuthorizationRequest` 的可信上下文。
§8.6（行 581-595）区分 ACS/ADP 边界：ACS/ADP 结果（URL、展示名、endpoint）不得单独作为
授权依据。

> 本实现：为网关现有 Capability/Plugin 决策（RBAC 风格，见 mapping 文档）提供 AAC 包装，
> 并把 ACS/ADP 元数据隔离在 resource attributes 之外，不参与裁决（仅审计属性）。

## 7. 委托模式与 Delegation Token（AAC §10）

### 7.1 两种模式（§10.1，行 750-765）

- 固定链路：初始授权上下文明确后续 actor / Partner 路径，运行时只能沿指定链路；
- 动态下一跳：初始上下文给出边界约束，当前节点在边界内选择下一跳，由 STS 逐跳裁决；
- 推荐默认 `动态下一跳 + 边界约束 + 逐跳裁决`；节点不得自行扩大 scope、audience、tenant、
  purpose、chain depth、数据敏感等级。

### 7.2 Delegation Token 必需字段（§10.2，行 767-780）

JWT access token 或 ACPs delegation token 必须包含：`iss`、`sub`、`aud`（匹配 §6.7 canonical
audience 或可信 alias）、`exp`、`iat`、`jti`、`scope`、`act`（最外层 actor 必须能解析为
immediate actor）。opaque token 须能经 introspection/resolver 取得等价信息。

### 7.3 推荐字段（§10.3，行 782-799）

`nbf`、`azp`/`client_id`、`cnf`、`acps_subject_type`、`acps_target_aic`、`acps_skill_id`、
`acps_delegation_id`、`acps_delegation_mode`(fixed/dynamic)、`acps_boundary_id`、
`acps_boundary_hash`、`acps_chain_depth`、`acps_max_chain_depth`、`acps_allowed_route`、
`acps_allowed_partner_aics`。

### 7.4 收窄与链路约束（§10.5-10.7，行 836-908）

- §10.5 Audience 与 Scope 收窄：Token Exchange 后 aud/scope 不得扩大；
- §10.6 固定链路：当前 hop 必须与 `acps_allowed_route` 对齐；
- §10.7 动态下一跳：delegation boundary id/hash/chain depth 必须合法，`acps_allowed_partner_aics`
  约束下一跳选择。

> 本实现：实现了 **delegation boundary 承载 + 校验**（`BoundaryState`：boundary id/hash、
> max_chain_depth、allowed partner AIC set、allowed route、delegation_id、mode），并把
> "audience 收窄""boundary 未授权扩大"等违例归入 deny。

## 8. 通信 Profile（AAC §9）

- §9.1 Profile A：真人→Agent 单跳：`primary=immediate=human:{issuer}#{sub}`、
  `actor_chain=[]`；
- §9.2 Profile B：Agent→Agent 单跳：`primary=immediate=agent:{peer_aic}`、
  `actor_chain=[agent:{peer_aic}]`，通过 mTLS/AIC + `senderId == peer AIC`；
- §9.3 Profile C：真人发起多跳委托：入口 OIDC/OAuth2 + 每跳 mTLS/AIC + 中间 Token Exchange；
  Partner 需同时裁决 immediate actor 可否访问、可否代表 primary、primary 可否访问资源及
  chain/scope/tenant/consent/risk 是否满足；
- §9.4 Profile D：Agent 发起多跳委托：`primary=agent:{originator_aic}`，还需裁决转委托权限与
  chain depth 上限；
- §9.5 中途真人授权事件：必须经 OIDC/OAuth2/签名审批/STS 等可信机制验证，不得由普通业务
  payload 自报"某真人已同意"。

> 本实现：`BuildContext` 按两个 profile 族构造（单跳 B / 多跳委托 C/D），event 类型只接受已
> 验证来源（provider 提供）。

## 9. 身份认证（AIA + AIP 子集）

### 9.1 AIC 语法与校验码（AIC spec）

- 前缀 `1.2.156.3088`（国家级 OID 分配节点），内容为第 5～10 级；
- 每级字符：`0-9`、`A-Z`（不区分大小写，推荐大写）；
- 第 5 级版本号取值范围 `1~Z`；第 9 级末尾为 `0` 表示本体；
- 第 10 级为校验码：AUTOSAR CRC-16 / CCITT-FALSE（0x1021、0xFFFF、无反射、非直接）对
  **规范化大写**的 ASCII 字节流，**并在尾部拼接 ARSP 盐值（≥2 字节）**后计算，结果 Base36
  编码为固定 4 位；
- 校验码为服务商内部维护的盐值；**当盐值可配置时才做 CRC 完整验证**，否则只做结构性验证，
  并在此文档与代码注释中说明。

### 9.2 mTLS / CAI（AIA spec）

- 推荐 TLS 1.3 双向认证；CAI（身份认证基础设施）签发携带 AIC 的证书；
- 网关在此载体下从已校验 peer 证书提取 AIC 作为身份上下文。

### 9.3 身份绑定与错误码（AIP §6 与 AAC §12）

- `identity_binding_enabled` 时，从 mTLS peer 证书提取对端 AIC：Subject CN 为主来源，SAN
  `URI:acps://{AIC}` 为补充；CN 与 SAN 不一致 / CN 缺失或非法 → 证书身份无效；
- AIP `senderId` 与 peer AIC 一致性校验（RpcRequest / StreamRequest / NotificationStart /
  TaskResult）；
- 错误码映射（AAC §12 表格，与 AIP 错误表一致）：

| 情况 | 错误码 |
| --- | --- |
| 缺少必需认证凭据 / peer 证书无效 / AIC 无法解析 | `-32008` AuthenticationRequiredError |
| senderId != peer AIC / act 不一致 / cnf 不匹配 / 策略不允许 | `-32009` AuthorizationFailedError |
| token 格式/签名/有效期/撤销/issuer/aud/jti 重放 问题 | `-32010` AccessTokenInvalidError |

- **对外错误信息不得泄露具体策略、名单、角色、关系链或 token claims**；详细原因只进审计日志。

## 10. 审计要求（AAC §13）

每次授权裁决都必须记录审计事件（§13 行 1004-1044）：

1. 不得记录完整 access token / refresh token / ID Token；
2. 真人 subject 应优先 hash 或 pairwise subject；
3. 应记录 issuer、audience、jti、delegation id、actor chain、resource、action、decision、
   reason code；
4. 高风险事件：impersonation、chain depth 过深、audience 不匹配、actor 不匹配、token replay、
   break-glass；
5. 审计日志应满足完整性保护、访问控制和保留周期要求。

## 11. 安全要求（AAC §14）

- §14.1 最小权限：scope 最小化；Token Exchange 不得扩大 audience/scope/有效期；高敏 Skill 用
  短期/一次性 token 或 replay 检测；refresh token 不得透传。
- §14.2 Token 绑定：`cnf` 存在时，STS 必须绑定到持有者证书；Partner 必须校验 `cnf` 与 mTLS
  peer 证书匹配；token 被窃取不得被其他 Agent 直接重放。
- §14.3 撤销与重放：可撤销 token 须 introspection/撤销列表确认；一次性/高敏 token 必须记录
  `jti`/delegation id 并在有效期内拒绝重复；验证缓存不超过 exp；检测到 replay/撤销/aud 错配/
  actor 错配必须记录高风险审计。
- §14.4 冒充默认禁止：AAC 默认只支持 delegation 不支持 impersonation；如业务必须支持，须显式
  策略 + 显式标记 + PDP 可区分 + 更高级别审计。
- §14.5 不信任自报字段：不得把以下字段直接作为可信授权输入：

  1. AIP payload 自报的 `userId`/`username`/`role`；
  2. `commandParams` 中自报的用户属性或 agent chain；
  3. prompt / 任务文本中的身份描述；
  4. 未经验证的 ID Token；
  5. `aud` 不包含当前 Resource Server 的 access token；
  6. **未签名、未绑定、未验证的 delegation record**。

  可信输入只能来自：已验证证书、已验证 token、已验证 session、已验证 STS/resolver 查询结果、
  系统自维护的资源状态与关系数据。

> 本实现把 §14.5(1)(2)(3)(6) 作为 `delegation.go` / `pdp.go` 的硬性拒绝规则（见
> `delegation.go` 的 `ErrUnsignedDelegationRecord` 等），并有对应用例覆盖。

## 12. 实现取舍（v0 切片声明）

| 项 | 决定 |
| --- | --- |
| 策略模型 | 网关已有 RBAC/Capability 风格决策之上叠加 AAC wrapper（allow=显式 allow，其余=deny） |
| OIDC/OAuth2 全流 | v0 不实现完整授权码流程；token 侧仅处理已绑定 delegation token 的验证与边界校验 |
| STS / Token Exchange 联调 | v0 定义 provider 接口与本地确定性签名（测试用例）演示，不调用外部 STS |
| AIC 校验码 | 普通结构验证 always；CRC 完整验证在提供 ARSP salt 时启用；无 salt 时结构验证 + 文档声明 |
| ACI 私有 CA / ADP / Linked-in | 不在范围 |
| Replay 一次性使用（§14.3(2)） | `ReplayGuard`（任何二次使用即拒）＋ 跨证书防重放走 gateway-core `NonceCache`；`cmd/acps-smoke` 冒烟验证 |
| impersonation | 默认拒绝（§14.4） |

> 任何"暂不实现"项都必须 fail closed（不影响授权安全边界放宽）。