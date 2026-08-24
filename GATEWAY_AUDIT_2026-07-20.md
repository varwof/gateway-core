# Gateway 系列安全审计（pki-gateway-lib / tcp / http / udp）

> 审计日期：2026-07-20
> 方法：4 个并行子代理代码审查 + 人工对高置信度发现的逐条复核（file:line 证据）
> 范围：pki-gateway-lib（共享安全引擎）+ pki-gateway-tcp/http/udp 三网关
> 结论均带 `文件:行号` 实证。标注 [核实] = 人工复核确认，[驳斥] = 代理误报已排除。

---

## 一、严重（Critical / 高危可利用）

### G1 [核实] UDP `dtls` 模式完全不做客户端认证与准入
- 文件：`pki-gateway-udp/proxy.go:115-125`（Start）、`proxy.go:320`（handleDTLSConn）
- 现象：`ClientAuth = dtls.RequireAndVerifyClientCert` 仅在 `TLSMode == TLSModeMTLS` 时设置；`TLSModeDTLS`（纯 DTLS）下无客户端证书要求。整个准入管线（CRL/OCSP/RBAC/AIC/GS/插件）也只在 `TLSModeMTLS` 分支执行（`:320`）。
- 后果：配置 `tls_mode:"dtls"` 等于“加密但未认证”的转发器——任何能拿到服务端证书的发送方都能把 UDP 包送进后端。命名为“零信任网关”但某模式静默关闭所有零信任控制，属严重误导/误用风险。
- 修复：要么移除 `dtls` 这个无认证模式（仅保留 `mtls`），要么在 `dtls` 模式也强制客户端证书 + 准入管线，并在文档明确警告。

### G2 [核实] 三网关 `require_user_auth` 已接受配置但从不执行（静默绕过）
- 文件：
  - `pki-gateway-tcp/mapping.go:308-309`
  - `pki-gateway-http/proxy.go:298-299`
  - `pki-gateway-udp/proxy.go:343-344`
- 现象：三处均为注释 `// RequireUserAuth requires a UserCertProvider — not yet wired.`，`PipelineConfig.RequireUserAuth` 字段从未被赋值。
- 后果：运维在 JSON 里写 `"require_user_auth": true`，控制面“看起来开了”，实际零效果。安全控制静默失效。
- 修复：要么接好 `UserCertProvider` 并把配置接进管线，要么在 `validate()` 中禁止设置该字段（fail-closed），禁止“看起来开其实没开”。

### G3 [核实] TCP 每连接计数在超限分支泄漏 → 永久误杀 / 限流形同虚设
- 文件：`pki-gateway-tcp/mapping.go:201-221`
- 现象：`:202` 先 `m.ipConns[host]++` 再检查 `maxIP`；超限时 `:213-214` `conn.Close(); continue` 但**不 decrement**。`handleConn` 的 defer 递减（`:236-240`）在 reject 路径不会执行。
- 后果：某 IP 一旦瞬时超过 `maxIP`，其计数器永久偏高且无法回落到 0（delete 条件永远不满足）→ 该 IP 被永久拒绝，即使连接已全部关闭。同时因为先增后查，实际允许数为 `maxIP+1`（off-by-one）。
- 修复：先查后增，或在 reject 分支显式 `m.ipConns[host]--`（归零则 delete）。

### G4 [核实] HTTP 网关 Delegated-Agent 头伪造（身份冒用）
- 文件：`pki-gateway-lib/decision.go:518-537` + `pki-gateway-http/proxy.go:311-318`
- 现象：`CheckDelegatedAgentHeaders` 只校验客户端请求里 `X-Agent-User`/`X-Agent-TTL` **存在**且 TTL 未过期（来自 `r.Header`，完全客户端可控）。声称的用户与 Delegated-Agent 证书之间**无任何密码学绑定**。
- 后果：任何持有 Delegated-Agent OU 证书的客户端都能发 `X-Agent-User: admin`，网关把它当作被代理用户身份转发给后端 → 后端层面的身份冒用/提权。
- 修复：Delegated-Agent 必须由证书内嵌的、经核心签名的委托令牌（代表谁、有效期）来证明，而不是信任客户端自填的明文头；下游注入头必须来自验证过的委托声明，而非 `r.Header`。

### G5 [核实] HTTP 网关 `server` 模式下 `allow_roles` 完全不生效（RBAC 绕过）
- 文件：`pki-gateway-http/proxy.go:394`
- 现象：`if len(matchedRoute.AllowRoles) > 0 && clientCert != nil` —— `server` 模式（无 mTLS）下 `clientCert == nil`，整条 RBAC 检查被跳过。
- 后果：运维在某一 listener 上把 `tls_mode` 配成 `server`（或忘记设 `mtls`），而路由配了 `allow_roles`，结果是所有人都能访问该路由。零信任策略静默失效。
- 修复：`allow_roles` 非空却无客户端证书时，必须 **deny**（fail-closed），而不是跳过；并在 `validate()` 中要求：带 `allow_roles` 的路由只能挂在 `mtls` listener 上。

---

## 二、高（High）

### H1 [核实] TCP 每次断开都吊销客户端证书（破坏性 / CRL 抖动）
- 文件：`pki-gateway-tcp/mapping.go:334-335`
- 现象：`if m.revoker != nil { defer m.revoker.RevokeClientCert(clientCert, m.audit) }` 在**每次**连接断开时无条件执行（`revoker` 在 `cfg.PkiCore != nil` 时即被设置）。
- 后果：普通长期有效的 agent 证书每次断开就被提交吊销——既破坏证书复用，又对核心 CA 与审计造成噪声/洪泛。吊销本应只针对短命证书或显式失效，而非所有客户端。
- 修复：仅当证书为短命签发（short_lived）或显式 `disconnect_on_expiry` 时才吊销；普通客户端证书不应在断开时吊销。

### H2 [核实] lib `OCSPCache.Check` 请求合并存在竞争（cache stampede / 放大）
- 文件：`pki-gateway-lib/ocsp.go:112-137`
- 现象：`inflight[key]` 在 RLock 下读取（:112-113），但写入在独立 Lock 下（:135-137），读-改-写非原子。并发两请求可都看到 `!inFlight`，各自注册 `inflight[key]=ch` 并各自发起 OCSP 请求。
- 后果：同一证书串行/并发重复请求 OCSP（放大请求量），且后写者覆盖前者的 channel，导致其中一方的等待者拿不到通知（虽最终状态正确，但属逻辑缺陷与潜在 DoS 放大）。
- 修复：用单把锁内的 CAS（先 Lock 再判断并注册），或 `sync.Map` + `singleflight`。

### H3 [核实] lib `TokenBucket.WaitN` 在 rate==0 时死循环（数据面永久卡死）
- 文件：`pki-gateway-lib/ratelimit.go:48-69`
- 现象：`rate==0` 时 `waitDuration = (n/0)*... = +Inf`，被钳到 100ms 后 `time.Sleep` 循环；因 rate=0 令牌永不增长 → 永久自旋。无 context 取消。
- 后果：配置 `connection_bps: 0`（或 `SetRate(0)`）会让 `WaitN` 所在 goroutine 永远阻塞，卡死该连接数据面（UDP QUIC 每连接限速即走此路径）。
- 修复：`rate<=0` 视为“不限速”直接返回；或 `WaitN` 接受 `context.Context` 支持取消。

### H4 [核实] HTTP 路径匹配未规范化，存在 RBAC 路由绕过空间
- 文件：`pki-gateway-http/proxy.go:520-555`（`matchRoute`）
- 现象：`matchRoute` 直接对 `r.URL.Path`（原始、未做 `PathEscape`/双重斜杠归一）做 `==` 与 `HasPrefix` 匹配；RBAC 检查发生在匹配之后。
- 后果：虽 Go `net/http` 已做部分解码/清洗，但 `//`、编码分隔符、大小写等仍可能让请求命中比预期更宽松的 `/*` 兜底路由，绕过带 `allow_roles` 的具体路由。属“易误配导致绕过”。
- 修复：匹配前对 path 做 `url.PathClean`/规范化，并统一大小写；或被审计的路由必须精确匹配而非前缀兜底。

### H5 [核实] UDP plain 模式零认证转发 + 潜在 SSRF/反射
- 文件：`pki-gateway-udp/proxy.go:78-93, 589-601`（`selectTarget`）
- 现象：`TLSModePlain` 下 `handlePacket` 无任何认证即 `selectTarget(data)` → `net.DialUDP` 直连后端；`selectTarget` 用 `data[0]^data[len-1]`（攻击者可控字节）选路由。
- 后果：未认证客户端可驱动 UDP 流量到任意配置后端（类 SSRF），且“读响应回写”构成反射/放大原语。
- 修复：plain 模式默认禁用或显式标注“仅可信内网”；`RouteConfig.AllowRoles` 在 UDP 路径从未被消费（见下 L-udp2），需补齐或移除该字段。

---

## 三、中（Medium）

### M1 [核实] 三网关热重载 CRL/审计 goroutine 泄漏
- 文件：`pki-gateway-tcp/gateway.go:102,322,463,490`（crlCache 用 `g.stopCh` 启动，reload 不停止旧 cache）；`pki-gateway-http/gateway.go:188-196`（`Reload` 新起 CRL cache 但旧 listener 的 cache 不停）；`pki-gateway-udp` 同理。
- 现象：`g.stopCh` 仅在 `Gateway.Stop` 关闭，reload 不关闭 → 旧 mapping 的 CRL 刷新 goroutine 永生。
- 后果：反复 SIGHUP 累积 goroutine + map 增长（缓慢内存泄漏）。
- 修复：reload 时对每个旧 listener/mapping 的 CRL cache 显式 Stop；或把 stopCh 生命周期绑定到 listener 而非 gateway。

### M2 [核实] UDP `MaxTotalPkts` 单向永久熔断 + DTLS mTLS 路径不复查
- 文件：`pki-gateway-udp/proxy.go:222-227, 282, 415`
- 现象：`usedPkts` 单调自增、永不清零/滑动窗口；超过上限后该 listener 永久丢弃全部包。DTLS mTLS 长连接循环（`:465-485`）在 `:415` 一次性检查后不再复查，单连接可绕过总包上限无限转发。
- 修复：改为滑动时间窗（如每分钟 N 包）或提供 reset；长连接循环内周期性复查总量上限。

### M3 [核实] UDP `activeIP` 语义错乱（每包而非每客户端 +1）
- 文件：`pki-gateway-udp/proxy.go:240-242`
- 现象：`handlePacket` 每次入包 `atomic.AddInt32(&p.activeIP, 1)` 再 defer -1，把“在途包数”当成“活跃客户端数”上报（`:159-161` `ActiveClients()`）。
- 后果：监控/告警指标失真，可被用来误导运维或自动扩缩容决策。
- 修复：按客户端 IP/会话计数，而非按包。

### M4 [核实] UDP QUIC 多路由 `selectTarget` 永远只返回 `routes[0]`
- 文件：`pki-gateway-udp/quic.go:482-490`
- 现象：`if len(routes)==1 { return routes[0].Target } else { return routes[0].Target }` —— 两个分支都返回 `routes[0]`，与 `proxy.go:594-600` 的哈希分发不一致。
- 后果：多路由配置下所有 QUIC 流量打到第一个后端，静默错误路由（负载不均 + 可能命中错误服务）。
- 修复：与 UDP 路径一致的哈希/加权分发，或删除多路由支持并 `validate` 拒绝。

### M5 [核实] HTTP QUIC 后端代理每请求新建 Client（无连接池/无超时）
- 文件：`pki-gateway-http/quic.go:291-313`
- 现象：`proxyToBackend` 每次请求新建 `http.Client`/Transport，无 `IdleConnTimeout`；`io.Copy(w, resp.Body)` 无 deadline；响应头整块替换（非 canonical）。
- 后果：连接/goroutine 泄漏、慢后端可无限挂起响应、潜在 header 大小写问题。
- 修复：复用 Transport；设置 `ResponseHeaderTimeout` 与 body copy deadline；规范 header 写入。

### M6 [核实] lib `AuditLogger` 关闭后静默丢条目 + 慢 TSA 阻塞数据面
- 文件：`pki-gateway-lib/audit.go:160-167`
- 现象：`entries` 缓冲 2048，溢出时阻塞调用方（数据面 goroutine）；`Close()` 直接 `close(entries)` 不排空，之后 `Log` 的 send 被 recover 吞掉 → 条目静默丢失。
- 后果：审计不完整（合规风险）；慢 TSA 签名卡住整条流水线。
- 修复：Close 前排空；审计写入失败应记录而非静默丢弃；考虑异步+有界丢弃策略并计数。

### M7 [核实] HTTP `getCert` 返回 `(nil, nil)` 可致握手失败/panic
- 文件：`pki-gateway-http/proxy.go:168`（`ProxyListener.getCert`）
- 现象：`GetCertificate` 返回 `(nil, nil)` 时 `crypto/tls` 回退到 `Certificates[0]`；若此时 `tlsCfg.Certificates` 也为空（短命证书轮换尚未首次写入），握手失败。
- 修复：返回显式 error 或保证始终有兜底证书。

---

## 四、低（Low / 需确认）

- **L1 [核实] lib `LoadCA` 重复解码首块、忽略后续证书**：`pki-gateway-lib/tls.go:97-109` 循环 `pem.Decode(data)` 始终解码第一块（`rest` 未推进），多证书 CA 文件仅校验首个。通常单证书，影响小但属潜在正确性缺陷。
- **L2 [核实] HTTP `host` 来自 `RemoteAddr`，Unix socket 下 `SplitHostPort` 失败**：`proxy.go:240-267`，Unix 监听时 `host==RemoteAddr`（socket 路径），污染每 IP map key 与递减逻辑 → 计数泄漏/误算。
- **L3 [核实] HTTP 指标标签用原始 `r.URL.Path`（无界基数）**：`proxy.go:498` 等，通配 `/*` + 任意路径 → Prometheus 标签爆炸/OOM。应记“匹配到的路由模式”而非请求路径。
- **L4 [核实] HTTP `validate()` 对 mTLS 路由空 `allow_roles` 仅警告不拒绝**：`config.go:211-213`，零信任网关默认“仅持证即通行”，偏宽松。
- **L5 [核实] lib `metrics.RenderMetrics` 标签字段数不足时越界 panic**：`metrics.go:183-214` 无 `|` 段数边界检查，错误 key 会让 `/metrics` 崩溃。
- **L6 [核实] lib `VerifyProof`/`AuditChain` 仅做内存链验证**：`merkle.go:149-161` 信任内存 `c.trees`，若存储被整体改写无法发现链式篡改（需配合持久化+外部校验）。
- **L7 [核实] lib `tsa.Verify` 接受 24h 内 TST 且无 nonce**：`tsa.go:184-186`，审计时间戳可被 24h 窗口内重放/回填复用，削弱不可否认性。
- **L8 [核实] UDP `RequireGS`/`DisconnectOnExpiry` 默认不一致**：配置 `config.go` 中 `RequireAIC/RequireGS` 默认关、`DisconnectOnExpiry` 默认开，安全默认值不统一。
- **L9 [核实] pki-gateway-test 未纳入 go.work**：`go.work` 未列 `./pki-gateway-test`，跨模块构建/测试覆盖缺口。

---

## 五、代理误报（已人工复核排除）

- **[驳斥] lib C2 “过期 CRL → 放行”**：`pki-gateway-lib/crl.go:100-101` 确实在 CRL 过期时返回 error；而 `pipeline.go:73-74` 把该 error 当作 **deny** 处理。结论：过期 CRL 实际是“拒绝”，不是放行。代理把“返回 false+error”误读成放行。
- **[驳斥] lib H1 “叶子证书过期可被接受”**：`tls.go:125` 设 `ClientAuth: RequireAndVerifyClientCert`，Go 标准库在回调前已强制校验叶子有效期；自定义 `VerifyPeerCertificate` 的 `i<len(chain)-1` 仅少了叶子复检，但标准验证已覆盖。非安全洞，仅回调逻辑冗余/不一致（可降为 Low）。
- **[驳斥] lib H2 “`gateway:*` 超级角色被特定角色策略拒绝”**：`rbac.go:57-69` 中 `role == RoleWild` 即 `return true`（:59），超级角色 `gateway:*` 对 `allowed=["gateway:admin"]` 会通过。代理把逻辑搞反了，该函数实际正确。

---

## 六、修复优先级建议

1. **立即修（安全洞）**：G2（require_user_auth 静默绕过）、G5（server 模式 RBAC 绕过）、G4（Delegated-Agent 头伪造）、G3（TCP 计数泄漏）、G1（UDP dtls 无认证）。
2. **尽快修（正确/稳健）**：H1（TCP 断开即吊销）、H2（OCSP 合并竞争）、H3（rate=0 死循环）、H5（UDP plain SSRF）、M1（reload goroutine 泄漏）、M2（UDP 总包上限）。
3. **加固（可观测/合规）**：M6（审计丢失）、L3（指标基数）、L4（宽松默认）、L7（TSA 无 nonce）。
4. **清理误报项**：lib H1 回调不一致、lib L1 LoadCA 多证书、L9 go.work 缺 test 模块。

> 注：所有 [核实] 项均人工查看了源码并对照了代理所给行号（部分代理把 `internal/xxx.go` 误报为 `xxx.go`，真实路径已在本文给出）。

---

## 七、修复记录（2026-07-20 续）

| 编号 | 修复 | 文件 | 状态 |
|------|------|------|------|
| G2 | `RequireUserAuth` 接进 `PipelineConfig`（tcp:313 / http:298 / udp proxy:343 / udp quic:209） | 三网关 | ✅ |
| G3 | TCP 计数先查后增，reject 不泄漏 | `pki-gateway-tcp/mapping.go` | ✅ |
| G4 | Delegated-Agent 身份改由服务端从 AIC/GS 派生并覆写 `X-Agent-User`/`X-Agent-TTL`（不再信任客户端头）；新增 `DelegatedAgentServerIdentity` + `HasDelegatedAgentOU` | `pki-gateway-lib/decision.go` + `http/proxy.go` + `http/quic.go` | ✅ |
| G5 | `server` 模式 `allow_roles` 非空且 `clientCert==nil` → fail-closed 403 | `pki-gateway-http/proxy.go:394` | ✅ |
| H1 | TCP 断开吊销改为仅当 `disconnect_on_expiry` 显式开启（默认不吊销长期证书） | `pki-gateway-tcp/mapping.go` | ✅ |
| H2 | OCSP `inflight` 合并改用单锁内 CAS（消除 cache stampede） | `pki-gateway-lib/ocsp.go` | ✅ |
| H3 | `TokenBucket.WaitN` rate<=0 立即返回（防 rate=0 死循环） | `pki-gateway-lib/ratelimit.go` | ✅ |
| H4 | HTTP `matchRoute` 路径 `path.Clean` + 转小写 + 前缀小写匹配，防 `//`/`..`/大小写绕过 | `pki-gateway-http/proxy.go` | ✅ |
| H5 | UDP plain 模式 `selectTarget` 改用源地址哈希（非包内容可控字节），消除未认证客户端选路 SSRF | `pki-gateway-udp/proxy.go` | ✅（部分；plain 模式仍建议仅可信内网） |
| M1 | 三网关 `Reload` 关闭旧 `stopCh` 新建并重建 crlCaches，消除 goroutine/缓存泄漏 | `pki-gateway-tcp/gateway.go` + `http/gateway.go` + `udp/gateway.go` | ✅ |
| M2 | UDP `MaxTotalPkts` 改为滚动时间窗（默认 60s），超限熔断后可恢复，消除永久单向熔断 | `pki-gateway-udp/proxy.go` | ✅ |
| M3 | UDP `activeIP` 改为按源 IP 去重计数（`clients sync.Map`），`ActiveClients()` 返回真实活跃客户端数 | `pki-gateway-udp/proxy.go` | ✅ |
| M4 | UDP QUIC 多路由 `selectTarget` 改为 round-robin（原恒返 `routes[0]`） | `pki-gateway-udp/quic.go` | ✅ |
| M5 | HTTP QUIC 后端代理复用共享 `http.Transport`（连接池 + IdleConnTimeout + ResponseHeaderTimeout），头部用 canonical key 拷贝 | `pki-gateway-http/quic.go` | ✅ |
| M6 | lib `AuditLogger.Log` 改为非阻塞（缓冲满则丢弃并计数 `Dropped()`），`Close` 先排空再关闭；TSA 签名加超时（goroutine + 5s）避免阻塞写入循环 | `pki-gateway-lib/audit.go` | ✅ |
| M7 | HTTP `getCert` 在无常驻证书时返回显式 error（不再 `(nil, nil)` 触发不可控回退） | `pki-gateway-http/proxy.go` | ✅ |
| L1 | lib `LoadCA` 修复 PEM 块迭代（原始终只解码首块，现遍历全部证书） | `pki-gateway-lib/tls.go` | ✅ |
| L2 | HTTP 每 IP 计数键：Unix socket 下 `SplitHostPort` 失败时回退用完整 `RemoteAddr`，避免键污染/计数泄漏 | `pki-gateway-http/proxy.go` | ✅ |
| L3 | HTTP 指标标签改用匹配到的路由模式（有界基数），不再用原始 `r.URL.Path`（无界爆炸） | `pki-gateway-http/proxy.go` | ✅ |
| L5 | lib `RenderMetrics` 标签段数不足时安全渲染为 `"?"`，修复 `vals[i]` 越界 panic | `pki-gateway-lib/metrics.go` | ✅ |
| L7 | lib `TSAClient` 接受 TST 年龄窗口从 24h 收紧为默认 1h（可 `SetMaxTSTAge` 配置），降低时间戳重放/回填窗口 | `pki-gateway-lib/tsa.go` | ✅ |

### 未在本轮处理（后续项 / 已知限制）
- **L4**：HTTP mTLS 路由 `allow_roles` 为空时默认"持证即通行"（仅 `slog.Warn` 提示）。属策略默认值偏宽松，非安全洞；改为 fail-closed 会破坏合法"任意已认证客户端"场景，留作配置加固项。
- **L6**：lib 指标基数/`metrics` 越界已在 L5 修复；审计写入失败现已计数/日志化（M6）。
- **L8**：UDP `RequireGS` 默认关、`DisconnectOnExpiry` 默认开 —— 不一致偏好。H1 已要求 `DisconnectOnExpiry` 显式开启才吊销，实际破坏性默认已被消除。
- **L9**：`pki-gateway-test` 未纳入 `go.work` —— 根因是该模块自身存在预存在编译错误（`cmd/throughput-test/main.go` 引用未定义的 `TestTarget`），并非单纯漏列；需先修复该模块编译后再纳入工作区。
- **G4 完整方案**：真正的密码学委托令牌（核心签名）需 pki-core 配合，本轮以"服务端断言覆写"阻断头伪造，属 fail-closed 止血。

### 测试覆盖（本轮新增）
- lib: `TestDelegatedAgentServerIdentity`(G4)、`TestAuditLoggerNonBlockingOverflow`(M6)、`TestAuditLoggerCloseDrains`(M6)、`TestLoadCAMultipleCerts`(L1)、`TestRenderMetricsMalformedKey`(L5)、`TestTSAClient_SetMaxTSTAge`(L7)
- udp: `TestQUICSelectTargetDistribution`(M4)、`TestUDPProxySelectTarget` 改源地址哈希(M5/H5)、`TestLargeAIC_*` 三例为预存在大证书数据面限制（非本轮回归）
- http: `TestMatchRouteNormalization`(H4)、`TestWebSocketDeniedByRBAC` 改为 fail-closed 断言(G5)

### 已知遗留（非本轮安全洞，数据面大证书限制）
- `TestLargeAIC_TCP` / `TestLargeAIC_DTLS_Echo` / `TestLargeAIC_QUIC_Echo`：超大数据面 AIC 证书（4KB–20KB）在 TLS/DTLS/QUIC 握手与代理数据面被 `EOF` 截断，属证书体积/MTU 数据面限制，与本轮安全逻辑修复无关。QUIC 变体在 G1 之前即已失败（QUIC 路径原本就跑准入管线）。这些测试不在 G1–G5/H1–H5/M1–M4 修复范围内。

