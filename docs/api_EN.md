# gateway-core API Reference

> Package alias: `gw` | Module: `github.com/varwof/gateway-core`

## Exported Types

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
    RiskMonitor                 *RiskMonitor // Behavioral-level denial point auto-records violation signals
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

### PolicyManager (Policy Versioning, Task 5a)

Full-package policy configuration (`PluginConfigs`) versioned lifecycle management, a lightweight implementation compared to patent LEE US12676749B1 policy epoch:

- **Monotonically increasing version number**: Each publish/rollback produces a new version number that never regresses (anti-replay/anti-rollback).
- **Historical snapshots**: Retains `MaxHistory` (default 64) complete configuration snapshots, allowing rollback to any historical version.
- **Rollback**: `Rollback(version)` rebuilds the registry to the specified version content and generates a new version with a `RolledBackFrom` marker.
- **Rollback floor**: `MinRollbackVersion` prevents rollback to versions earlier than the specified version (0 = disabled).
- **Source tracking**: `Source` (api/sighup) + `Operator` (API operator CN) for audit accountability.
- **Branch control/canary (Task 5b)**: `PolicyBranch` routes specific Agents to designated policy versions by Agent identifier, enabling canary rollouts and multi-policy lines; `SelectRegistry(agentID)` returns an independent plugin registry and version number for the hit branch, falling back to the current active version on miss; each version's registry is built independently without polluting the active registry.

```go
type PolicySnapshot struct {
    Version        uint64       // Monotonically increasing version number
    Source         string       // "api" / "sighup"
    Operator       string       // API operator CN
    RolledBackFrom uint64       // Rollback source version (0 if not a rollback)
    Timestamp      time.Time    // Creation time
    Configs        PluginConfigs // Complete configuration snapshot
}

type PolicyBranch struct {
    ID       string // Unique branch identifier
    AgentID  string // Match string: exact "a-123" / prefix "a-*" / wildcard "*"
    Version  uint64 // Policy version effective when branch is hit (must be published)
    Priority int    // Higher priority matches first (default 0)
    Comment  string // Canary scope / rollback plan description
}

type PolicyManager struct {
    MaxHistory         int
    MinRollbackVersion uint64
    // ... internal locks and history
}

func NewPolicyManager(registry *PluginRegistry) *PolicyManager
func (pm *PolicyManager) Registry() *PluginRegistry
func (pm *PolicyManager) CurrentVersion() uint64
func (pm *PolicyManager) ActiveSnapshot() *PolicySnapshot
func (pm *PolicyManager) History() []*PolicySnapshot
func (pm *PolicyManager) Publish(configs PluginConfigs, source, operator string) (uint64, error)
func (pm *PolicyManager) Rollback(version uint64, source, operator string) (uint64, error)
func (pm *PolicyManager) SetBranches(branches []PolicyBranch) error // Full replacement, validates ID uniqueness/AgentID non-empty/version published
func (pm *PolicyManager) Branches() []PolicyBranch
func (pm *PolicyManager) ClearBranches()
func (pm *PolicyManager) SelectRegistry(agentID string) (uint64, *PluginRegistry) // Select version registry by Agent (Task 5b)
func (pm *PolicyManager) Reset()
```

**Branch matching rules**: Match first by `Priority` descending; `*` = wildcard, `a-*` = prefix, others = exact. When a branch is hit, `SelectRegistry` returns the branch version's independent registry and version number (audit bound to that version); on miss, returns `(current, activeRegistry)`.

### TaskRegistry (Task Lifecycle Tracking, A3/A4/A5)

Implementation of patent specification L75 revocation trigger methods (b)(e) proactive reporting path. When an Agent starts a task, it registers the task context with the gateway (task ID → certificate serial number mapping); when the task completes, a completion signal (HTTP Header `X-AIC-Task-Status: completed` or management API) triggers conditional revocation ("revoke when done").

```go
type TaskRegistry struct{ /* internal RWMutex + map[taskID]*TaskRecord */ }

type TaskRecord struct {
    TaskID   string     // Unique task identifier
    Serial   string     // Associated certificate serial number (hex)
    AgentID  string     //主体 that initiated the task
    Status   TaskStatus // active / completed
    Created  int64      // Registration timestamp (unix)
    Note     string     // Note (URL/description)
    Revoked  bool
    RevokeAt int64
}

func NewTaskRegistry() *TaskRegistry
func (r *TaskRegistry) Register(taskID, serial, agentID, note string, now int64) *TaskRecord // Returns old record (same ID overwrites)
func (r *TaskRegistry) Complete(taskID string, now int64) *TaskRecord  // Mark complete and return record
func (r *TaskRegistry) Unregister(taskID string) *TaskRecord           // Unregister and return
func (r *TaskRegistry) Lookup(taskID string) *TaskRecord               // Read-only snapshot
func (r *TaskRegistry) List() []TaskRecord                             // Full snapshot
func (r *TaskRegistry) Len() int
```

**Header conventions**:

| Header | Value | Description |
|--------|-------|-------------|
| `X-AIC-Task-Id` | Any string | Task ID (A3 registration) |
| `X-AIC-Task-Status` | `completed` | Task completion signal (A4) |

`TaskCompletedFromHeader(h func(string) string, fallbackID string) (id string, done bool)` detects the completion signal, `TaskIDFromHeader(h) string` extracts the task ID. Gateway receives completion signal → immediately revokes certificate (doesn't wait for connection close) → audit `task_complete_revoke` → unregisters task.

**Pipeline wiring**: When `PipelineConfig.CapabilityPluginResolver` is non-nil, it takes precedence over `CapabilityPluginRegistry` for phase-one plugin evaluation; the returned version number (non-zero) overrides `PolicyVersion` for audit binding. Injecting `policyMgr.SelectRegistry` into the gateway enables branch control; without branches configured, behavior is identical to 5a.

### Constraints

`authorizationConstraints` authorization boundary constraint evaluation engine. Constraints reuse the `Capability` container (schemeId fixed to `constraint` or `constraint-v1`, capabilityId distinguishes constraint type, parameters carry JSON configuration). Constraint types are registered through an extensible registration mechanism — adding a new constraint type only requires registering the corresponding executor, without modifying the certificate ASN.1 structure or gateway core code.

Built-in constraint types (`globalConstraintRegistry`):

| capabilityId | parameters | Semantics |
|---|---|---|
| `allowed-cidr` | Bare array `["10.0.0.0/8"]` or object `{"cidrs":["10.0.0.0/8"]}` | Client IP must fall within allowed CIDR range (requires ClientIP, skipped if empty) |
| `max-concurrent` | Any (placeholder) | Checked by gateway connection tracker, skipped during evaluation |
| `time-window` | `{"start":"HH:MM","end":"HH:MM","tz":"Asia/Shanghai"}` | Evaluation moment must be within window, cross-midnight windows (start>end) supported; `tz` is IANA timezone name, evaluated in UTC if empty; window includes start, excludes end |
| `geo-fence` | Inline table `{"resolver":"inline","regions":{"CN-SHA":["10.0.0.0/8"]}}` or external `{"resolver":"ip2region","regions":["CN-SHA"]}` | Geographic identifier resolved from client IP must hit allowed set (requires ClientIP, skipped if empty). `inline` is built-in zero-dependency resolver (region→CIDR inline table); other resolvers require `RegisterGeoResolver` first, evaluation fails (deny not allow) if unregistered |

Unknown constraint types are ignored in default mode (forward compatibility), with callers logging `unknown_constraint` audit warnings; once the corresponding executor is registered, they are recognized and executed.

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
func (r *ConstraintRegistry) Register(ev ConstraintEvaluator) error   // Duplicate registration returns error
func (r *ConstraintRegistry) Replace(ev ConstraintEvaluator) error    // Atomic hot-swap
func (r *ConstraintRegistry) Find(capabilityId string) (ConstraintEvaluator, error)
func (r *ConstraintRegistry) Remove(capabilityId string)
func (r *ConstraintRegistry) Reset()
func (r *ConstraintRegistry) Len() int
func (r *ConstraintRegistry) Keys() []string

// Global default registry (built-in four constraint types)
func RegisterConstraint(ev ConstraintEvaluator) error     // Register custom constraint type
func ReplaceConstraint(ev ConstraintEvaluator) error
func ResetConstraints()                                   // Reset to built-in (testing only)

// Constraint evaluation entry (filters by schemeId constraint/constraint-v1, unknown types ignored)
func CheckAuthorizationConstraints(constraints []Capability, clientIP string) error
func CheckAuthorizationConstraintsAt(constraints []Capability, clientIP, timeHHMM string) error

// geo-fence external geographic resolver registration (extension point, e.g., ip2region)
type GeoResolver func(ip string) (string, error)
func RegisterGeoResolver(name string, fn GeoResolver)
```

Constraint constants: `ConstraintCIDRKey = "allowed-cidr"`, `ConstraintConcurrentKey = "max-concurrent"`, `ConstraintTimeWindowKey = "time-window"`, `ConstraintGeoFenceKey = "geo-fence"`.

### Capability Matching Semantics

Capability matching uses unified glob wildcard matching (reusing `MatchCapability`, supporting `*` single-level wildcard and `a:b:*` prefix trimming, `*` matches all), following "fast matching" and "detail layering" principles:

- **SchemeId = scheme level** (plugin routing key, determines which executor handles the capability);
- **CapabilityId = fast matching** (the matched subject, supports multi-level `:` segments with `*` at any level);
- **Parameters = detailed details** (JSON parameters consumed by the executor, not involved in matching).

Matching points (declaration-side wildcards can authorize requests with details):

- **`RequiredCapabilities`** (Admission/Pipeline): Each requirement is an id, AIC declarations (bare capabilityId and `schemeId:capabilityId` full name) are patterns; any declaration covering the requirement passes. For example, AIC declaring `SELECT:*` (full name `mysql:SELECT:*`) covers requirement `mysql:SELECT:*` or `mysql:SELECT:/api/tables` (`a:b:*` prefix); requirement `mysql:INSERT:*` or `http:GET:/admin` is denied.
- **`rbac` plugin `role_map`**: Entries are authorization patterns, AIC declarations (bare capabilityId and full name) are matched as ids. For example `role_map: {"mysql-read": ["mysql:SELECT:*"]}` authorizes declaration `mysql:SELECT:*`; `["mysql:*"]` authorizes all capabilities under scheme; `["SELECT:*"]` is compatible with bare capabilityId syntax; `["*"]` authorizes all. Any matching role passes; if none match, decision follows `default_action`.
- **`allowlist` / `denylist`**: Maintain exact string matching (`allowed`/`denied` entries must be byte-equal); for wildcard matching, use glob patterns in `rbac` `role_map`.

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
    Level        string // INFO/WARN (P2-A-28)
    DaHash       string // DelegationAuthorization signatureValue SHA-256 (Task 4: authorization evidence fingerprint)
    AICFingerprint string // AIC extension DER SHA-256 (Task 4)
}

type SignedAuditEntry struct {
    Entry AuditEntry
    TST   string
}

// Authorization evidence fingerprint helpers (Task 4)
func AICFingerprint(cert *x509.Certificate) string
func DAHash(cert *x509.Certificate) string          // No DA signature → ""
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

### AuditIndex (Audit Full-Text Search Index, 2026-08-15)

```go
// bbolt index: by action/agent/principal/mapping/time-range + FTS sub-index (audit_fts.go).
func NewAuditIndex(path string) (*AuditIndex, error)
func (idx *AuditIndex) Index(entry *AuditEntry) error
func (idx *AuditIndex) Search(q *AuditIndexQuery) ([]AuditIndexEntry, error)
func (idx *AuditIndex) Close() error
func (idx *AuditIndex) Drop() error
func (idx *AuditIndex) Size() (int64, error)
func (idx *AuditIndex) DBPath() string

type AuditIndexQuery struct {
    Q       string // Full-text keyword (FTS sub-index)
    Action  string
    AgentId string
    Mapping string
    ClientCN string
    Since, Until int64 // Unix seconds
    Limit   int
}

type AuditIndexEntry struct {
    Hash         string // Original entry content SHA-256 (traceable)
    Entry        AuditEntry
}
```

### ConnRegistry (Real-Time Connection Details + Access Points + Agent Directory, 2026-08-15)

```go
// Real-time connection registry: records agent/principal/source IP/protocol/certificate serial per connection,
// used for monitoring presentation layer endpoints and risk closed-loop.
func NewConnRegistry() *ConnRegistry
func (r *ConnRegistry) Register(agentID, principal string, closeFn func()) func()
func (r *ConnRegistry) RegisterConn(agentID, principal, srcIP, protocol, serial string, closeFn func()) func()
func (r *ConnRegistry) ListConnections() []ConnectionInfo // All active connection details
func (r *ConnRegistry) ListByIP() map[string]int          // Source IP → connection count aggregation
func (r *ConnRegistry) ListByAgentId() map[string]int     // Agent → connection count aggregation
func (r *ConnRegistry) DisconnectByAgentId(agentId string) int
func (r *ConnRegistry) DisconnectByPrincipalUid(principal string) int
func (r *ConnRegistry) Stats() int

type ConnectionInfo struct {
    ID          uint64 // Internal registration ID
    AgentId     string
    PrincipalUid string
    SrcIP       string
    Protocol    string
    Serial      string
    Established int64 // Unix seconds
}
```

**Monitoring presentation layer endpoints** (2026-08-15, management API, lib/management.go):

| Endpoint | Method | Role | Description |
|----------|--------|------|-------------|
| `/api/v1/gateway/audit/search` | GET | audit/admin | Audit full-text/field search (`q` full-text, `action`, `agent_id`, `mapping`, `client_cn`, `since`, `until`, `limit`), depends on `ManagementServerConfig.AuditIndex`, returns 404 if unconfigured |
| `/api/v1/gateway/connections` | GET | ops/admin | Real-time connection details (`{"connections":[ConnectionInfo]}`) |
| `/api/v1/gateway/access-points` | GET | ops/admin | IP access point aggregation (`{"access_points":[{src_ip,connections,agents,protocols}]}`) |
| `/api/v1/gateway/agents` | GET | ops/admin | Agent directory real-time status (`{"agents":[{agent_id,principal,connections,protocols,src_ips,serial,last_seen}]}`) |
| `/api/v1/gateway/audit/chain` | GET | audit/admin | Cross-gateway audit chain DAG references (local chain head `local` + peer gateway chain references `peers`) |

### ChainRefs (Cross-Gateway Audit Chain DAG References, 2026-08-15)

```go
// Each gateway's local AuditChain (vertical hash chain) periodically syncs chain heads to peer gateways,
// peers record as ChainRef, forming horizontally anchored audit evidence DAG (no consensus ordering needed).
// Verification: check that peer's self-exposed chain head matches local reference; when advancing batches,
// verify new chain head previous == local record root (chain continuity), anti-tamper/anti-fork.
func NewChainRefStore() *ChainRefStore
func (s *ChainRefStore) Record(ref ChainRef)
func (s *ChainRefStore) PeerRefs() []ChainRef
func (s *ChainRefStore) Len() int
func (s *ChainRefStore) CompareRef(peer string, theirs *SealedTree) (bool, ChainRef, string)

type ChainRef struct {
    Peer        string // Peer gateway name
    BatchNumber int    // Peer's latest sealed batch number
    Root        string // Peer's latest batch root hash (hex)
    Previous    string // Peer's batch predecessor root hash
    Size        int
    Timestamp   string // Peer's batch timestamp (Unix seconds)
    CapturedAt  int64  // Local capture time (Unix seconds)
}

// Peer synchronization
type ChainPeerConfig struct {
    Name string
    URL  string // Peer management API base URL, e.g., https://gw2:9443
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

### RiskMonitor (High-Risk Agent Auto-Handling Closed Loop, 2026-08-15)

```go
// Behavioral risk signals (plugin_deny / parameter_overflow / out_of_cidr in pipeline
// auto-recorded) → rule threshold → disconnect + conditional revocation (OnAction callback injected by gateway).
func NewRiskMonitor(cfg RiskMonitorConfig) *RiskMonitor
func (m *RiskMonitor) RecordViolation(v RiskViolation) bool // Returns whether action was triggered
func (m *RiskMonitor) Violations(agentId string) int
func (m *RiskMonitor) Rules() []RiskRule
func (m *RiskMonitor) SetRules(rules []RiskRule) // SIGHUP hot-reload

type RiskMonitorConfig struct {
    Rules    []RiskRule
    OnAction func(agentId, action, reason string)
    Logger   *slog.Logger
}

type RiskRule struct {
    Name          string
    Signals       []string // Behavioral signals that trigger the rule (* = all)
    Threshold     int      // Violation count threshold within window
    WindowSeconds int      // Counting window (default 60)
    Action        string   // disconnect (kick) or revoke (kick + revoke)
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

**Control plane messages** (2026-08-12, mesh_control.go):

```go
type ControlMessageType string
const (
    ControlRevoke     ControlMessageType = "revoke"     // Revocation notification (serial/key_hash/agent_id)
    ControlDisconnect ControlMessageType = "disconnect" // Disconnect notification (agent_id/reason)
    ControlPeerSync   ControlMessageType = "peer_sync"  // State summary sync (version)
    ControlDedupWindow = 5 * time.Minute                 // Deduplication window
)

type ControlMessage struct {
    Type      ControlMessageType
    Source    string  // Source gateway name (loop prevention)
    MsgID     string  // Source+sequence unique ID (deduplication)
    Timestamp int64   // Unix milliseconds
    Serial    string  // Revoke payload: certificate serial number
    KeyHash   string  // Revoke payload: SPKI hash
    AgentId   string  // Revoke/disconnect payload: agent identifier
    Reason    string  // Disconnect payload: reason
    Version   uint64  // peer_sync payload: state version number
}

type ControlHandler func(msg ControlMessage) error

// Sender side
func (m *MeshManager) BroadcastRevoke(serial, keyHash string) error
func (m *MeshManager) BroadcastDisconnect(agentId, reason string) error
func (m *MeshManager) BroadcastPeerSync(version uint64) error
func (m *MeshManager) Broadcast(msg ControlMessage) error      // All healthy nodes
func (m *MeshManager) SendControl(peerName string, msg ControlMessage) error

// Receiver side
func (m *MeshManager) SetControlHandler(fn ControlHandler)   // Register callback (revocation evaluation/session management)
func (m *MeshManager) HandleControlMessage(conn io.ReadWriter) error
func (m *MeshManager) ServeControlListener(l net.Listener)   // Control listener accept loop
func (m *MeshManager) StartDedupCleanup(interval time.Duration)
```

Frame format: `0xC0` magic + 2-byte big-endian length + JSON payload. Distinguished from data plane 2-byte target length frame header (magic first byte != 0). Deduplication by `MsgID` (window `ControlDedupWindow`); messages from local node are ignored (loop prevention); message integrity and authenticity guaranteed by mTLS channel.

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

## OID Constants

```go
var OIDAlgorithmSuite, OIDAlgorithmTraditional asn1.ObjectIdentifier
var OIDSigECDSAWithSHA256, OIDSigECDSAWithSHA384, OIDSigECDSAWithSHA512 asn1.ObjectIdentifier
var OIDSigRSAWithSHA256, OIDSigRSAWithSHA384, OIDSigRSAWithSHA512 asn1.ObjectIdentifier
var OIDSigRSAPSSWithSHA256, OIDSigEd25519 asn1.ObjectIdentifier
var OIDOfflineRBAC asn1.ObjectIdentifier       // 1.3.6.1.4.1.66257.1.3
var OIDPrincipalProfile asn1.ObjectIdentifier  // 1.3.6.1.4.1.66257.1.4
var OIDRenewalToken asn1.ObjectIdentifier      // 1.3.6.1.4.1.66257.1.6
```

## RBAC Constants

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

## Pre-registered Metrics

```go
var MetricAICAdmissionTotal    *MetricCounter
var MetricAICActiveAgents      *MetricGauge
var MetricAICCertIssuedTotal   *MetricCounter
var MetricAICCertRevokedTotal  *MetricCounter
var MetricAICRenewalTotal      *MetricCounter
var MetricAICAdmissionDuration *MetricHistogram
var MetricAICBufferQueueDepth  *MetricGauge
```

## Error Types

```go
var (
    ErrOCSPRevoked      = errors.New("ocsp: certificate revoked")
    ErrOCSPUnavailable  = errors.New("ocsp: responder unavailable")
)
```

## Constants

```go
const DefaultRenewInterval = 30 * time.Second
const DefaultRenewWindow   = 2 * time.Minute
```
