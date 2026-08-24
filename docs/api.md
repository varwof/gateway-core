# gateway-core API 参考

> 包别名: `gw` | 模块: `github.com/varwof/gateway-core`

## 导出类型

### AIC (Agent Identity Certificate)

```go
type AIC struct {
    Version                 int
    AgentId                 string
    PrincipalUid            PrincipalUid
    DelegationMode          DelegationMode
    Capabilities            []Capability
    DelegationAuthorization DelegationAuthorization
    Extensions              []ExtField
}

type PrincipalUid struct {
    Version    int
    Realm      string
    Identifier string
    KeyHash    []byte
    HashAlgo   asn1.ObjectIdentifier
}

type DelegationMode int
const (
    DelegationAuthorized     DelegationMode = 0
    DelegationRepresentative DelegationMode = 1
)

type DelegationAuthorization struct {
    Signature         []byte
    SignatureAlgo     AlgorithmIdentifier
    Timestamp         time.Time
    Nonce             []byte              // Exactly 32 bytes
    RequestedLifetime int                 // 3600-86400 seconds
}

type Capability struct {
    SchemeId     string  // 1-128 bytes
    CapabilityId string  // 1-256 bytes
    Parameters   []byte  // 0-4096 bytes
}

type ExtField struct {
    ExtnID    asn1.ObjectIdentifier
    Critical  bool
    ExtnValue []byte
}
```

### GatewaySessionExtension

```go
type GatewaySessionExtension struct {
    Version       int
    MaxConcurrent int
    HardTimeout   int
    AllowedCIDRs  []string
    MaxRetries    int
    KeyDerivation []KeyDerivationParams
}

type KeyDerivationParams struct {
    KDFAlgorithm asn1.ObjectIdentifier
    KeyLength    int
    Salt         []byte
    Info         string
}
```

### PrincipalAuthorization

```go
type PrincipalAuthorization struct {
    Version          int
    Roles            []string
    Grants           []Capability
    DelegationPolicy DelegationPolicy
    ExternalRef      *ExternalPolicyRef
}

type DelegationPolicy struct {
    MaxAgents           int
    AllowedMode         int
    CriticalOpsRequired bool
    MaxSessionHours     int
}

type ExternalPolicyRef struct {
    RefType   string
    RefUrl    string
    RefDigest []byte
}
```

### Admission

```go
type AdmissionConfig struct {
    RequireAIC                bool
    RequireGatewaySession     bool
    RequiredProtocol          string
    RequiredRuleId            string
    RequiredCapabilities      []string
    DisallowRepresentative    bool
    RequireUserPermission     bool
    RejectOverflow            bool
    RequireUserAuth           bool
    EnforceCapSizeConstraints bool
    NonceCache                *NonceCache
    EnforceSize32             bool
}

type AdmissionResult struct {
    Decision               DecisionResult
    Reason                 string
    AIC                    *AIC
    GatewaySession         *GatewaySessionExtension
    PrincipalAuthorization *PrincipalAuthorization
    PrincipalUid           string
}

type DecisionResult int
const (
    DecisionAllow   DecisionResult = iota
    DecisionDeny
    DecisionNeedAuth
)
```

### Pipeline

```go
type PipelineConfig struct {
    CRLCache                    *CRLCache
    OCSPCache                   *OCSPCache
    AllowRoles                  []string
    CheckScope                  PipelineCheck
    MaxConnsPerCert             int
    RequireAIC                  bool
    RequireGS                   bool
    RequiredProtocol            string
    RequiredRuleId              string
    RequiredCapabilities        []string
    DisallowRepresentative      bool
    RequireUserPermission       bool
    RejectOverflow              bool
    RequireUserAuth             bool
    EnforceCapSizeConstraints   bool
    EnforceSize32               bool
    CapabilityPluginRegistry    *PluginRegistry
    AuditLogger                 *AuditLogger
    NonceCache                  *NonceCache
    ClientIP                    string
    PolicyVersion               uint64
    RiskMonitor                 *RiskMonitor // 行为级拒绝点自动记录违规信号（2026-08-15）
}

type PipelineCheck int
const (
    CheckFullChain PipelineCheck = iota
    CheckLeafOnly
)

type PipelineResult struct {
    Granted          bool
    DenyReason       string
    Roles            []string
    Principal        string
    Serial           string
    AgentId          string
    GatewaySession   *GatewaySessionExtension
    SessionConstraint SessionConstraint
}

type SessionConstraint struct {
    MaxConcurrent int
    HardTimeout   int
    MaxRetries    int
}
```

### Plugin

```go
type PluginDecision int
const (
    PluginAllow  PluginDecision = iota
    PluginDeny
    PluginBypass
)

type PluginResult struct {
    Decision PluginDecision
    Reason   string
    Metadata map[string]string
}

type PluginContext struct {
    Context  context.Context
    AIC      *AIC
    UserPerm *UserPermission
    Target   string
    ClientCN string
    Roles    []string
}

type CapabilityPlugin interface {
    Scheme() string
    Execute(cap *Capability, ctx *PluginContext) (*PluginResult, error)
}

type PluginConfig struct {
    Type   string
    Config map[string]interface{}
}
type PluginConfigs map[string]*PluginConfig
```

### PolicyManager（策略版本化，任务 5a）

整包策略配置（`PluginConfigs`）版本化生命周期管理，对照专利 LEE US12676749B1 policy epoch 的轻量实现：

- **单调递增版本号**：每次发布/回滚产生新版本号，版本号永不回退（防重放/防回滚）。
- **历史快照**：保留 `MaxHistory`（默认 64）条完整配置快照，可回溯任意历史版本。
- **回滚**：`Rollback(version)` 将注册表重建为指定版本内容，并生成带 `RolledBackFrom` 标记的新版本。
- **防回滚下界**：`MinRollbackVersion` 禁止回滚到早于该版本的版本（0 = 不启用）。
- **来源记录**：`Source`（api/sighup）+ `Operator`（API 操作者 CN），供审计追责。
- **分支控制/灰度（任务 5b）**：`PolicyBranch` 按 Agent 标识将指定 Agent 路由到特定策略版本，实现金丝雀灰度与多策略线；`SelectRegistry(agentID)` 命中分支返回该版本的独立插件注册表与版本号，未命中回退当前生效版本；每版本注册表独立构建，不污染 active 注册表。

```go
type PolicySnapshot struct {
    Version        uint64       // 单调递增版本号
    Source         string       // "api" / "sighup"
    Operator       string       // API 操作者 CN
    RolledBackFrom uint64       // 回滚来源版本（非回滚为 0）
    Timestamp      time.Time    // 创建时间
    Configs        PluginConfigs // 完整配置快照
}

type PolicyBranch struct {
    ID       string // 分支唯一标识
    AgentID  string // 匹配串：精确 "a-123" / 前缀 "a-*" / 全量 "*"
    Version  uint64 // 命中分支后生效的策略版本（必须已发布）
    Priority int    // 优先级，越大越先匹配（默认 0）
    Comment  string // 灰度范围/回退预案说明
}

type PolicyManager struct {
    MaxHistory         int
    MinRollbackVersion uint64
    // ... 内部锁与历史
}

func NewPolicyManager(registry *PluginRegistry) *PolicyManager
func (pm *PolicyManager) Registry() *PluginRegistry
func (pm *PolicyManager) CurrentVersion() uint64
func (pm *PolicyManager) ActiveSnapshot() *PolicySnapshot
func (pm *PolicyManager) History() []*PolicySnapshot
func (pm *PolicyManager) Publish(configs PluginConfigs, source, operator string) (uint64, error)
func (pm *PolicyManager) Rollback(version uint64, source, operator string) (uint64, error)
func (pm *PolicyManager) SetBranches(branches []PolicyBranch) error // 全量替换，校验 ID 唯一/AgentID 非空/版本已发布
func (pm *PolicyManager) Branches() []PolicyBranch
func (pm *PolicyManager) ClearBranches()
func (pm *PolicyManager) SelectRegistry(agentID string) (uint64, *PluginRegistry) // 按 Agent 选择版本注册表（任务 5b）
func (pm *PolicyManager) Reset()
```

**分支匹配规则**：按 `Priority` 降序匹配第一条；`*` 全量、`a-*` 前缀、其余精确。命中分支时 `SelectRegistry` 返回分支版本的独立注册表与版本号（审计绑定该版本）；未命中返回 `(current, activeRegistry)`。

### TaskRegistry（任务生命周期跟踪，A3/A4/A5）

对照专利说明书 L75 吊销触发方式 (b)(e) 的主动上报路径实现。Agent 开始任务时向网关注册任务上下文（任务 ID → 证书序列号映射），任务完成时通过完成信号（HTTP Header `X-AIC-Task-Status: completed` 或管理 API）触发条件性吊销（"用完即吊销"）。

```go
type TaskRegistry struct{ /* 内部 RWMutex + map[taskID]*TaskRecord */ }

type TaskRecord struct {
    TaskID   string     // 任务唯一标识
    Serial   string     // 关联证书序列号（hex）
    AgentID  string     // 发起任务的主体
    Status   TaskStatus // active / completed
    Created  int64      // 注册时间戳（unix）
    Note     string     // 备注（URL/描述）
    Revoked  bool
    RevokeAt int64
}

func NewTaskRegistry() *TaskRegistry
func (r *TaskRegistry) Register(taskID, serial, agentID, note string, now int64) *TaskRecord // 返回旧记录（同 ID 覆盖）
func (r *TaskRegistry) Complete(taskID string, now int64) *TaskRecord  // 标记完成并返回记录
func (r *TaskRegistry) Unregister(taskID string) *TaskRecord           // 注销并返回
func (r *TaskRegistry) Lookup(taskID string) *TaskRecord               // 只读快照
func (r *TaskRegistry) List() []TaskRecord                             // 全量快照
func (r *TaskRegistry) Len() int
```

**Header 约定**：

| Header | 值 | 说明 |
|---|---|---|
| `X-AIC-Task-Id` | 任意字符串 | 任务 ID（A3 注册） |
| `X-AIC-Task-Status` | `completed` | 任务完成信号（A4） |

`TaskCompletedFromHeader(h func(string) string, fallbackID string) (id string, done bool)` 检测完成信号，`TaskIDFromHeader(h) string` 提取任务 ID。网关收到完成信号 → 立即吊销证书（不等连接关闭）→ 审计 `task_complete_revoke` → 注销任务。

**决策管线接线**：`PipelineConfig.CapabilityPluginResolver` 非 nil 时优先于 `CapabilityPluginRegistry` 做阶段一插件评估；返回的版本号（非 0）覆盖 `PolicyVersion` 参与审计绑定。网关注入 `policyMgr.SelectRegistry` 即可启用分支控制，未配置分支时行为与 5a 完全一致。

### Constraints

`authorizationConstraints` 授权边界约束评估引擎。约束复用 `Capability` 容器（schemeId 固定为 `constraint` 或 `constraint-v1`，capabilityId 区分约束类型，parameters 承载 JSON 配置）。约束类型通过可扩展注册机制注册——新增约束类型时只需注册对应执行器，无需修改证书 ASN.1 结构或网关核心代码。

内置约束类型（`globalConstraintRegistry`）：

| capabilityId | parameters | 语义 |
|---|---|---|
| `allowed-cidr` | 裸数组 `["10.0.0.0/8"]` 或对象 `{"cidrs":["10.0.0.0/8"]}` | 客户端 IP 必须落在允许网段内（需 ClientIP，为空则跳过） |
| `max-concurrent` | 任意（占位） | 由网关连接跟踪器检查，评估阶段跳过 |
| `time-window` | `{"start":"HH:MM","end":"HH:MM","tz":"Asia/Shanghai"}` | 评估时刻必须在窗口内，跨午夜窗口（start>end）支持；`tz` 为 IANA 时区名，空则按 UTC 评估；窗口含起点不含终点 |
| `geo-fence` | 内联表 `{"resolver":"inline","regions":{"CN-SHA":["10.0.0.0/8"]}}` 或外部 `{"resolver":"ip2region","regions":["CN-SHA"]}` | 客户端 IP 解析出的地域标识必须命中允许集合（需 ClientIP，为空则跳过）。`inline` 为内置零依赖解析器（region→CIDR 内联表）；其他 resolver 需先 `RegisterGeoResolver` 注册，未注册时评估失败（拒绝而非放行） |

未知约束类型在默认模式下忽略（向前兼容），由调用方记录 `unknown_constraint` 审计告警；注册对应执行器后即被识别执行。

```go
type ConstraintContext struct {
    ClientIP string
    Now      time.Time
}

type ConstraintEvaluator interface {
    CapabilityId() string
    Evaluate(cap *Capability, ctx *ConstraintContext) error
}

type ConstraintRegistry struct { /* ... */ }

func NewConstraintRegistry() *ConstraintRegistry
func (r *ConstraintRegistry) Register(ev ConstraintEvaluator) error   // 重复注册报错
func (r *ConstraintRegistry) Replace(ev ConstraintEvaluator) error    // 原子热替换
func (r *ConstraintRegistry) Find(capabilityId string) (ConstraintEvaluator, error)
func (r *ConstraintRegistry) Remove(capabilityId string)
func (r *ConstraintRegistry) Reset()
func (r *ConstraintRegistry) Len() int
func (r *ConstraintRegistry) Keys() []string

// 全局默认注册表（内置四种约束类型）
func RegisterConstraint(ev ConstraintEvaluator) error     // 注册自定义约束类型
func ReplaceConstraint(ev ConstraintEvaluator) error
func ResetConstraints()                                   // 重置为内置（仅测试）

// 约束评估入口（schemeId 过滤 constraint/constraint-v1，未知类型忽略）
func CheckAuthorizationConstraints(constraints []Capability, clientIP string) error
func CheckAuthorizationConstraintsAt(constraints []Capability, clientIP, timeHHMM string) error

// geo-fence 外部地域解析器注册（扩展点，如 ip2region）
type GeoResolver func(ip string) (string, error)
func RegisterGeoResolver(name string, fn GeoResolver)
```

约束常量：`ConstraintCIDRKey = "allowed-cidr"`、`ConstraintConcurrentKey = "max-concurrent"`、`ConstraintTimeWindowKey = "time-window"`、`ConstraintGeoFenceKey = "geo-fence"`。

### Capability 匹配语义

能力匹配统一采用 glob 通配（复用 `MatchCapability`，支持 `*` 单层通配与 `a:b:*` 前缀裁剪，`*` 匹配全部），"快速匹配" 与 "细节分层" 原则：

- **SchemeId = 方案级别**（插件路由键，决定能力走哪个执行器）；
- **CapabilityId = 快速匹配**（匹配的主体，允许多级 `:` 分段并在任意层使用 `*`）；
- **Parameters = 详细细节**（执行器消费的 JSON 参数，不参与匹配）。

匹配点（声明侧通配可授权带细节的请求）：

- **`RequiredCapabilities`**（Admission/Pipeline）：每条要求作为 id，AIC 声明（裸 capabilityId 与 `schemeId:capabilityId` 完整名）作为 pattern，任一声明覆盖该要求即通过。例如 AIC 声明 `SELECT:*`（完整名 `mysql:SELECT:*`）可覆盖要求 `mysql:SELECT:*` 或 `mysql:SELECT:/api/tables`（`a:b:*` 前缀）；要求 `mysql:INSERT:*` 或 `http:GET:/admin` 则拒绝。
- **`rbac` 插件 `role_map`**：条目为授权模式（pattern），AIC 声明（裸 capabilityId 与完整名）作为 id 匹配。例如 `role_map: {"mysql-read": ["mysql:SELECT:*"]}` 授权声明 `mysql:SELECT:*`；`["mysql:*"]` 授权 scheme 下全部能力；`["SELECT:*"]` 兼容裸 capabilityId 写法；`["*"]` 授权全部。任一角色命中即放行，均未命中按 `default_action` 决策。
- **`allowlist` / `denylist`**：维持精确字符串匹配（`allowed`/`denied` 条目逐字相等），需要通配请在 `rbac` `role_map` 中使用 glob 模式。

### Audit

```go
type AuditEntry struct {
    Time         string
    Action       AuditAction
    SrcIP        string
    ClientCN     string
    ClientSerial string
    Roles        []string
    Mapping      string
    Target       string
    TargetID     string
    Duration     string
    DenyReason   string
    BytesIn      int64
    BytesOut     int64
    TraceId      string
    SessionId    string
    GatewayId    string
    Protocol     string
    AgentId      string
    PrincipalUid string
    DelegationMode int
    Decision     string
    Capabilities []string
    Level        string // INFO/WARN（P2-A-28）
    DaHash       string // DelegationAuthorization signatureValue SHA-256（任务 4：授权证据指纹）
    AICFingerprint string // AIC 扩展 DER SHA-256（任务 4）
}

type SignedAuditEntry struct {
    Entry AuditEntry
    TST   string
}

// 授权证据指纹 helper（任务 4）
func AICFingerprint(cert *x509.Certificate) string
func DAHash(cert *x509.Certificate) string          // 无 DA 签名 → ""
func DAHashFromAIC(aic *AIC) string
func (e *AuditEntry) WithEvidenceFingerprints(cert *x509.Certificate) *AuditEntry

type AuditAction string
const (
    ActionConnected, ActionDisconnected, ActionDenied, ActionRevoked,
    ActionProxied, ActionCompleted, ActionNoRoute, ActionWSConnect,
    ActionWSClose, ActionPluginDecision AuditAction
)

type AuditFilter struct {
    Since, Until time.Time
    Limit, Offset int
    Sort, Action, ClientCN, Serial, Mapping string
}
```

### AuditIndex（审计全文检索索引，2026-08-15）

```go
// bbolt 索引：按 action/agent/principal/映射/时间段 + FTS 子索引（audit_fts.go）。
func NewAuditIndex(path string) (*AuditIndex, error)
func (idx *AuditIndex) Index(entry *AuditEntry) error
func (idx *AuditIndex) Search(q *AuditIndexQuery) ([]AuditIndexEntry, error)
func (idx *AuditIndex) Close() error
func (idx *AuditIndex) Drop() error
func (idx *AuditIndex) Size() (int64, error)
func (idx *AuditIndex) DBPath() string

type AuditIndexQuery struct {
    Q       string // 全文关键词（FTS 子索引）
    Action  string
    AgentId string
    Mapping string
    ClientCN string
    Since, Until int64 // Unix 秒
    Limit   int
}

type AuditIndexEntry struct {
    Hash         string // 原始条目内容 SHA-256（可回溯）
    Entry        AuditEntry
}
```

### ConnRegistry（实时连接明细 + 接入点 + agent 目录，2026-08-15）

```go
// 实时连接注册表：按连接记录 agent/principal/来源 IP/协议/证书序列号，
// 供监控呈现层端点与风险闭环使用。
func NewConnRegistry() *ConnRegistry
func (r *ConnRegistry) Register(agentID, principal string, closeFn func()) func()
func (r *ConnRegistry) RegisterConn(agentID, principal, srcIP, protocol, serial string, closeFn func()) func()
func (r *ConnRegistry) ListConnections() []ConnectionInfo // 全部活跃连接明细
func (r *ConnRegistry) ListByIP() map[string]int          // 来源 IP → 连接数聚合
func (r *ConnRegistry) ListByAgentId() map[string]int     // agent → 连接数聚合
func (r *ConnRegistry) DisconnectByAgentId(agentId string) int
func (r *ConnRegistry) DisconnectByPrincipalUid(principal string) int
func (r *ConnRegistry) Stats() int

type ConnectionInfo struct {
    ID          uint64 // 内部注册 ID
    AgentId     string
    PrincipalUid string
    SrcIP       string
    Protocol    string
    Serial      string
    Established int64 // Unix 秒
}
```

**监控呈现层端点**（2026-08-15，管理 API，lib/management.go）：

| 端点 | 方法 | 角色 | 说明 |
|------|------|------|------|
| `/api/v1/gateway/audit/search` | GET | audit/admin | 审计全文/字段检索（`q` 全文、`action`、`agent_id`、`mapping`、`client_cn`、`since`、`until`、`limit`），依赖 `ManagementServerConfig.AuditIndex`，未配置返回 404 |
| `/api/v1/gateway/connections` | GET | ops/admin | 实时连接明细（`{"connections":[ConnectionInfo]}`） |
| `/api/v1/gateway/access-points` | GET | ops/admin | IP 接入点聚合（`{"access_points":[{src_ip,connections,agents,protocols}]}`） |
| `/api/v1/gateway/agents` | GET | ops/admin | Agent 目录实时状态（`{"agents":[{agent_id,principal,connections,protocols,src_ips,serial,last_seen}]}`） |
| `/api/v1/gateway/audit/chain` | GET | audit/admin | 跨网关审计链 DAG 引用（本地链头 `local` + 对等网关链引用 `peers`） |

### ChainRefs（跨网关审计链 DAG 引用，2026-08-15）

```go
// 各网关本地 AuditChain（纵向哈希链）周期同步链头给对等网关，
// 对端记录为 ChainRef，形成横向锚定的审计证据 DAG（免共识排序）。
// 验证：核对对端自我暴露链头与本地引用一致；推进批次时校验
// 新链头 previous == 本地记录 root（链连续），防篡改/防分叉。
func NewChainRefStore() *ChainRefStore
func (s *ChainRefStore) Record(ref ChainRef)
func (s *ChainRefStore) PeerRefs() []ChainRef
func (s *ChainRefStore) Len() int
func (s *ChainRefStore) CompareRef(peer string, theirs *SealedTree) (bool, ChainRef, string)

type ChainRef struct {
    Peer        string // 对等网关名称
    BatchNumber int    // 对端最新已封存批次号
    Root        string // 对端最新批次根哈希（十六进制）
    Previous    string // 对端批次前驱根哈希
    Size        int
    Timestamp   string // 对端批次时间戳（Unix 秒）
    CapturedAt  int64  // 本地捕获时间（Unix 秒）
}

// 对等同步
type ChainPeerConfig struct {
    Name string
    URL  string // 对端管理 API 基址，如 https://gw2:9443
    TLSConfig *tls.Config
}
func NewChainHTTPClient(tlsConfig *tls.Config) *http.Client
type ChainSyncClient struct {
    Peer, URL string
    HTTPClient *http.Client
    Timeout    time.Duration
}
func (c *ChainSyncClient) Fetch() (*SealedTree, error)
func NewChainSyncer(store *ChainRefStore, peers []ChainSyncClient, interval time.Duration) *ChainSyncer
func (s *ChainSyncer) Start() / Stop()
```

### RiskMonitor（高风险 agent 自动处置闭环，2026-08-15）

```go
// 行为风险信号（管线内 plugin_deny / parameter_overflow / out_of_cidr
// 自动记录）→ 规则阈值 → 踢线 + 条件性吊销（OnAction 回调由网关注入）。
func NewRiskMonitor(cfg RiskMonitorConfig) *RiskMonitor
func (m *RiskMonitor) RecordViolation(v RiskViolation) bool // 返回是否触发处置
func (m *RiskMonitor) Violations(agentId string) int
func (m *RiskMonitor) Rules() []RiskRule
func (m *RiskMonitor) SetRules(rules []RiskRule) // SIGHUP 热重载

type RiskMonitorConfig struct {
    Rules    []RiskRule
    OnAction func(agentId, action, reason string)
    Logger   *slog.Logger
}

type RiskRule struct {
    Name          string
    Signals       []string // 触发规则的行为信号（* = 全部）
    Threshold     int      // 窗口内违规次数阈值
    WindowSeconds int      // 计数窗口（默认 60）
    Action        string   // disconnect（踢线）或 revoke（踢线+吊销）
    Reason        string
}

type RiskViolation struct {
    AgentId      string
    Signal       string
    CapabilityId string
    Details      string
    At           int64
}
```

### Metrics

```go
type MetricCounter struct { /* ... */ }
type MetricGauge struct { /* ... */ }
type MetricHistogram struct { /* ... */ }
type DurationTracker struct { /* ... */ }
```

### TLS

```go
var SecureCipherSuites []uint16
```

### Config Watcher

```go
type ConfigWatcher struct { /* ... */ }
```

### Mesh

```go
type MeshPeer struct {
    Name, Address string
    Weight        int
    Tags          map[string]string
}

type MeshConfig struct {
    LocalName    string
    TLSConfig    *tls.Config
    Peers        []MeshPeer
    DialTimeout  time.Duration
    PingInterval time.Duration
}

type MeshManager struct { /* ... */ }
```

**控制面消息**（2026-08-12，mesh_control.go）：

```go
type ControlMessageType string
const (
    ControlRevoke     ControlMessageType = "revoke"     // 吊销通知（serial/key_hash/agent_id）
    ControlDisconnect ControlMessageType = "disconnect" // 踢线通知（agent_id/reason）
    ControlPeerSync   ControlMessageType = "peer_sync"  // 状态摘要同步（version）
    ControlDedupWindow = 5 * time.Minute                 // 去重窗口
)

type ControlMessage struct {
    Type      ControlMessageType
    Source    string  // 来源网关名称（防环）
    MsgID     string  // 来源+序号唯一 ID（去重）
    Timestamp int64   // Unix 毫秒
    Serial    string  // revoke 载荷：证书序列号
    KeyHash   string  // revoke 载荷：SPKI 哈希
    AgentId   string  // revoke/disconnect 载荷：代理标识
    Reason    string  // disconnect 载荷：理由
    Version   uint64  // peer_sync 载荷：状态版本号
}

type ControlHandler func(msg ControlMessage) error

// 发送侧
func (m *MeshManager) BroadcastRevoke(serial, keyHash string) error
func (m *MeshManager) BroadcastDisconnect(agentId, reason string) error
func (m *MeshManager) BroadcastPeerSync(version uint64) error
func (m *MeshManager) Broadcast(msg ControlMessage) error      // 全部健康节点
func (m *MeshManager) SendControl(peerName string, msg ControlMessage) error

// 接收侧
func (m *MeshManager) SetControlHandler(fn ControlHandler)   // 注册回调（吊销评估/会话管理）
func (m *MeshManager) HandleControlMessage(conn io.ReadWriter) error
func (m *MeshManager) ServeControlListener(l net.Listener)   // 控制监听 accept 循环
func (m *MeshManager) StartDedupCleanup(interval time.Duration)
```

帧格式：`0xC0` magic + 2 字节大端长度 + JSON 载荷。与数据面 2 字节目标长度帧头区分（magic 首字节非 0）。去重按 `MsgID`（窗口 `ControlDedupWindow`）；来源为本节点消息忽略（防环）；消息由 mTLS 通道保证完整性与真实性。

### Alarm

```go
type AlarmRule struct {
    Name, Metric, Operator, Receiver string
    Threshold float64
    Cooldown  int
}

type AlarmReceiver struct {
    Name, Type, Webhook, Secret string
}

type AlarmConfig struct {
    Rules     []AlarmRule
    Receivers []AlarmReceiver
    Interval  int
}

type AlarmSource interface {
    Name() string
    Value() (float64, bool)
}
```

### TSA

```go
type TSAClient struct { /* ... */ }
type TSAProofLogger struct { /* ... */ }
type TSAProofEntry struct {
    Time, Root, TST string
    Batch           int
}
```

### Stream Multiplexer

```go
type StreamMux struct { /* ... */ }
type MuxStream struct { /* implements net.Conn */ }
```

### SPIFFE

```go
type SPIFFEID struct {
    TrustDomain, Path string
}
```

### Principal Profile

```go
type PrincipalProfile struct {
    PrincipalUID, CommonName string
    OrganizationalUnit       []string
    CertHash                 string
    UserPermission           *UserPermission
    Roles                    []string
}

type PrincipalProfileExtension struct {
    Version    int
    Attributes []PrincipalProfileAttribute
}

type PrincipalProfileAttribute struct {
    Type, Value string
}
```

### Renewal Token

```go
type RenewalTokenExt struct {
    Version        int
    PrincipalUid   PrincipalUid
    OldCertSerial  []byte
    NewKeyHash     []byte
    Timestamp      time.Time
    Nonce          []byte
    ValidityPeriod int
}
```

## OID 常量

```go
var OIDAlgorithmSuite, OIDAlgorithmTraditional asn1.ObjectIdentifier
var OIDSigECDSAWithSHA256, OIDSigECDSAWithSHA384, OIDSigECDSAWithSHA512 asn1.ObjectIdentifier
var OIDSigRSAWithSHA256, OIDSigRSAWithSHA384, OIDSigRSAWithSHA512 asn1.ObjectIdentifier
var OIDSigRSAPSSWithSHA256, OIDSigEd25519 asn1.ObjectIdentifier
var OIDOfflineRBAC asn1.ObjectIdentifier       // 1.3.6.1.4.1.66257.1.3
var OIDPrincipalProfile asn1.ObjectIdentifier  // 1.3.6.1.4.1.66257.1.4
var OIDRenewalToken asn1.ObjectIdentifier      // 1.3.6.1.4.1.66257.1.6
```

## RBAC 常量

```go
const RolePrefix = "gateway:"
const (
    RoleAdmin  = "gateway:admin"
    RoleOps    = "gateway:ops"
    RoleAudit  = "gateway:audit"
    RoleDeploy = "gateway:deploy"
    RoleRead   = "gateway:read"
    RoleWild   = "gateway:*"
)
```

## 预注册指标

```go
var MetricAICAdmissionTotal    *MetricCounter
var MetricAICActiveAgents      *MetricGauge
var MetricAICCertIssuedTotal   *MetricCounter
var MetricAICCertRevokedTotal  *MetricCounter
var MetricAICRenewalTotal      *MetricCounter
var MetricAICAdmissionDuration *MetricHistogram
var MetricAICBufferQueueDepth  *MetricGauge
```

## 错误类型

```go
var (
    ErrOCSPRevoked      = errors.New("ocsp: certificate revoked")
    ErrOCSPUnavailable  = errors.New("ocsp: responder unavailable")
)
```

## 常量

```go
const DefaultRenewInterval = 30 * time.Second
const DefaultRenewWindow   = 2 * time.Minute
```
