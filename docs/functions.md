# gateway-core 函数参考

所有导出函数按模块分组。包别名: `gw`

## TLS/mTLS (tls.go)

```go
func LoadCert(certFile, keyFile string) (*tls.Certificate, error)
func LoadCA(caCertFile string) (*x509.CertPool, error)
func LoadCACert(caCertFile string) (*x509.Certificate, error)
func BaseTLSConfig(cipherSuites []string, minTLSVersion string) *tls.Config
func ServerTLSConfig(cert *tls.Certificate, cipherSuites []string, minTLSVersion string) *tls.Config
func MTLSServerConfig(caCertFile string, cert *tls.Certificate, cipherSuites []string, minTLSVersion string) (*tls.Config, error)
func ClientTLSConfig(caCertFile, certFile, keyFile string, cipherSuites []string, minTLSVersion string) (*tls.Config, error)
func BuildCipherSuites(names []string) []uint16
func TLSVersionFromString(s string) uint16
```

## CRL 缓存 (crl.go)

```go
func NewCRLCache(caCert *x509.Certificate, url string, refreshSec int, translator Translator, lang string) *CRLCache
func (c *CRLCache) Start(stop <-chan struct{})
func (c *CRLCache) ForceRefresh() error
func (c *CRLCache) IsRevoked(caDN string, serial *big.Int) (bool, error)
func (c *CRLCache) Stats() (revokedCount int, thisUpdate, nextUpdate time.Time)
func (c *CRLCache) LastRefresh() time.Time
```

## OCSP 缓存 (ocsp.go)

```go
func NewOCSPCache(ttl time.Duration, fallback string, translator Translator, lang string) *OCSPCache
func ExtractOCSPURL(cert *x509.Certificate) string
func (c *OCSPCache) Check(cert, issuer *x509.Certificate) error
func (c *OCSPCache) Stats() (good int, revoked int)
func (c *OCSPCache) Flush()
func FetchOCSPResponseRaw(cert, issuer *x509.Certificate, ocspURL string) ([]byte, error)
func StartOCSPStapling(tlsCert *tls.Certificate, cfg *tls.Config, caCertFile string, stopCh <-chan struct{}, translator Translator, lang string)
```

## RBAC (rbac.go)

```go
func ExtractRoles(cert *x509.Certificate) []string
func CheckRole(roles []string, allowed []string) bool
func PeerCertRoles(r *http.Request) []string
func RequireRoles(r *http.Request, allowedRoles []string) bool
func NewOfflineRBAC(roles []string) *OfflineRBAC
func NewOfflineRBACFromCert(cert *x509.Certificate) *OfflineRBAC
func (r *OfflineRBAC) CheckRole(allowed []string) bool
```

## AIC (aic.go)

```go
func ParseAIC(cert *x509.Certificate) (*AIC, error)
func ValidateAIC(aic *AIC) error
func ParsePrincipalUid(s string) (PrincipalUid, error)
func MakePrincipalUidFromCert(realm, identifier string, certDER []byte) PrincipalUid
func (pu PrincipalUid) String() string
func (a *AIC) Principal() string
func (a *AIC) CheckPermission(required string) bool
func (a *AIC) HasProtocol(protocol string) bool
func (a *AIC) IntersectPermissions(pa *PrincipalAuthorization) []string
func (a *AIC) IntersectPermissionsStr(upPerms []string) []string
func (a *AIC) IntersectPermissionsStrAny(upPerms string) []string
```

## GatewaySession (session.go)

```go
func ParseGatewaySessionExtension(cert *x509.Certificate) (*GatewaySessionExtension, error)
func (g *GatewaySessionExtension) MaxConcurrentLimit() int
func (g *GatewaySessionExtension) HardTimeoutLimit() int
func (g *GatewaySessionExtension) MaxRetriesLimit() int
func (g *GatewaySessionExtension) CIDRAllowed(ip string) bool
func (g *GatewaySessionExtension) ValidateKeyDerivation() error
```

## PrincipalAuthorization (user_permission.go)

```go
func ParseUserPermissionExtension(cert *x509.Certificate) (*PrincipalAuthorization, error)
func (pa *PrincipalAuthorization) GrantIds() []string
func (pa *PrincipalAuthorization) HasRole(role string) bool
func (pa *PrincipalAuthorization) AllowsRepresentative() bool
func (u *UserPermission) AllowsImpersonation() bool
func (u *UserPermission) PermIds() []string
```

## 准入决策 (decision.go)

```go
func CheckAdmission(cert *x509.Certificate, cfg AdmissionConfig) AdmissionResult
func (c AdmissionConfig) Validate() error
func VerifyDelegationAuth(aic *AIC, userCert *x509.Certificate) error
func CheckDAFreshness(ts time.Time, now time.Time, maxAge time.Duration) error // P1-B-13：DA timestamp 新鲜度校验（|now-ts| ≤ maxAge，≤0 用默认 30s）
func NeedRevoke(cert *x509.Certificate) bool
func HasDelegatedAgentOU(cert *x509.Certificate) bool
func CheckDelegatedAgentCert(cert *x509.Certificate, gs *GatewaySessionExtension) string
func CheckDelegatedAgentHeaders(cert *x509.Certificate, r *http.Request) string // Deprecated: B1 用户名路径，改用 X-Client-Cert-DER 证书透传（B2）
func DelegatedAgentServerIdentity(cert *x509.Certificate, principal string, gs *GatewaySessionExtension) (user string, expiry time.Time, reason string)
func LogAdmission(result AdmissionResult, clientIP string, logger *slog.Logger)
```

`AdmissionResult.EffectiveCaps []Capability`：P∩C（AIC 声明 ∩ PA grants）交集结果，保留完整
Capability（含 SchemeId/Parameters）；无 PA 时为 AIC 声明全量。供阶段二插件评估与参数边界
校验使用（P0-3 两阶段能力路由，P2-A-06/P2-A-07）。

## 统一准入管线 (pipeline.go)

```go
func RunAccessPipeline(chain []*x509.Certificate, cfg *PipelineConfig) *PipelineResult
```

## 插件系统 (plugin.go, pluginconfig.go)

```go
func NewPluginRegistry() *PluginRegistry
func (r *PluginRegistry) Register(p CapabilityPlugin) error
func (r *PluginRegistry) Find(schemeID string) (CapabilityPlugin, error)
func (r *PluginRegistry) Execute(schemeID string, cap *Capability, ctx *PluginContext) (*PluginResult, error)
func (r *PluginRegistry) Reset()
func (r *PluginRegistry) Len() int
func (r *PluginRegistry) Keys() []string
func (r *PluginRegistry) BuildFromConfig(cfgs PluginConfigs) error
func RegisterPlugin(p CapabilityPlugin) error
func ExecutePlugin(schemeID string, cap *Capability, ctx *PluginContext) (*PluginResult, error)
func ResetPlugins()
func PluginTypeName(p CapabilityPlugin) string
```

两阶段能力路由（P0-3）：阶段一连接层在 `RunAccessPipeline` 内用 `AdmissionResult.EffectiveCaps`
（P∩C 交集）按 scheme 对齐筛选——本网关不服务的 scheme 记录 `ignore` 审计并跳过、不阻断连接；
阶段二操作层调用 `CheckOperationCapability` 对"要执行的具体操作"做判定：
操作 scheme 无插件 → fail-closed 拒绝；插件 deny → 拒绝；allow/bypass → 放行。

```go
func CheckOperationCapability(reg *PluginRegistry, cap *Capability, ctx *PluginContext) (*PluginResult, error)
```

`AdmissionResult.EffectiveCaps`：P∩C 交集后的全量 Capability（含 SchemeId/Parameters）；
无 PrincipalAuthorization 时 = AIC 声明全量。插件评估与参数边界校验均以它为对象，
不再使用证书原始声明全量（避免多声明能力误杀/误放授权能力）。

## 审计 (audit.go)

```go
func NewAuditLogger(file string, tsa *TSAClient, maxSize int64, maxBak int) (*AuditLogger, error)
func (l *AuditLogger) Log(entry AuditEntry)
func (l *AuditLogger) Dropped() int64
func (l *AuditLogger) File() string
func (l *AuditLogger) Close() error
func NewAuditEntryFromConn(srcIP, mappingName, target string, cert *x509.Certificate) AuditEntry
func NewAuditEntryDenied(srcIP, mappingName, target, reason string, cert *x509.Certificate) AuditEntry
func AuditDuration(start time.Time, entry *AuditEntry)
func VerifyAuditEntry(data []byte, tsaClient *TSAClient) error
func LogPluginDecision(logger *AuditLogger, entry PluginAuditEntry)
func ReadAuditEntries(file string, filter AuditFilter) ([]AuditEntry, error)
func FilterAuditFile(file string, since time.Time, action string, cn, serial, mapping string) error
func FindStartOffsetByTime(file string, target time.Time) (int64, error)
func ArchiveAuditFile(path string) error
func NewRotatingFile(path string, maxSize int64, maxBak int) (*RotatingFile, error)
func (r *RotatingFile) Write(p []byte) (int, error)
func (r *RotatingFile) Close() error
func (e *AuditEntry) SetV12Fields(protocol, gatewayId, traceId, sessionId, decision string)
```

## 审计索引 (audit_index.go)

```go
func NewAuditIndex(path string) (*AuditIndex, error)
func (idx *AuditIndex) Close() error
func (idx *AuditIndex) Index(entry *AuditEntry) error
func (idx *AuditIndex) Search(q *AuditIndexQuery) ([]AuditIndexEntry, error)
func (idx *AuditIndex) IndexFTS(entry *AuditEntry) error
func (idx *AuditIndex) SearchFTS(query string, limit int) ([]AuditIndexEntry, error)
func (idx *AuditIndex) Size() (int64, error)
func (idx *AuditIndex) Drop() error
func (idx *AuditIndex) DBPath() string
```

## Merkle 哈希链 (merkle.go)

```go
func HashLeaf(data []byte) []byte
func HashNode(left, right []byte) []byte
func NewMerkleTree(leaves [][]byte) *MerkleTree
func (m *MerkleTree) Root() []byte
func (m *MerkleTree) RootHex() string
func (m *MerkleTree) Proof(leafIndex int) ([]ProofStep, error)
func VerifyProof(leaf []byte, proof []ProofStep, root []byte) bool
func NewAuditChain(batchSize int, onSeal func(root []byte)) *AuditChain
func (c *AuditChain) Seal(entries [][]byte, previousRoot string) *SealedTree
func (c *AuditChain) Verify(batchNumber int, leaf []byte, proof []ProofStep) (bool, error)
func (c *AuditChain) LatestRoot() string
func (c *AuditChain) LatestRootBytes() []byte
func (c *AuditChain) BatchCount() int
func (c *AuditChain) Dump() string
func (c *AuditChain) GetTree(batchNumber int) *SealedTree
func (c *AuditChain) VerifyJSON(req *VerifyRequest) *VerifyResponse
```

## 指标 (metrics.go)

```go
func NewMetricCounter(name, help string, labels ...string) *MetricCounter
func (c *MetricCounter) Inc(labelValues ...string)
func (c *MetricCounter) Add(n uint64, labelValues ...string)
func NewMetricGauge(name, help string, labels ...string) *MetricGauge
func (g *MetricGauge) Set(n int64, labelValues ...string)
func (g *MetricGauge) Add(delta int64, labelValues ...string)
func NewMetricHistogram(name, help string, labels []string, bounds ...float64) *MetricHistogram
func (h *MetricHistogram) Observe(v float64, labelValues ...string)
func RegisterCounter(m *MetricCounter)
func RegisterGauge(m *MetricGauge)
func RegisterHistogram(m *MetricHistogram)
func RenderMetrics(buildInfo string) string
func TrackDuration(start time.Time, d *DurationTracker)
func (d *DurationTracker) Add(dur time.Duration)
```

## TSA 客户端 (tsa.go)

```go
func NewTSAClient(url string) *TSAClient
func (t *TSAClient) SetCACert(certFile string) error
func (t *TSAClient) SetMaxTSTAge(d time.Duration)
func (t *TSAClient) Sign(data []byte) (tstDER []byte, err error)
func (t *TSAClient) Verify(entryJSON, tstDER []byte) error
func MarshalTSARequest(req TimeStampReq) ([]byte, error)
func UnmarshalTimestampToken(data []byte) (*TSTInfo, error)
func EncodeBase64(data []byte) string
func DecodeBase64(s string) ([]byte, error)
```

## TSA 证明日志 (tsa_proof.go)

```go
func NewTSAProofLogger(path string, tsa *TSAClient, chain *AuditChain, intervalSec int) *TSAProofLogger
func (l *TSAProofLogger) Start(stopCh chan struct{})
func (l *TSAProofLogger) Close() error
func (l *TSAProofLogger) SetAuditChain(chain *AuditChain)
func (l *TSAProofLogger) Stop()
```

 ## 短命证书 (shortlived.go)

```go
func NewIssueClient(cfg IssueConfig) (*IssueClient, error)
func (c *IssueClient) Issue(req *IssueRequest) (*IssueResult, error)
func (r *IssueResult) Certificate() (*x509.Certificate, error)
func AutoIssueCert(cfg *IssueConfig, cn, san string) (*AutoIssueResult, error)
func RenewalLoop(cfg *IssueConfig, cn, san, certFile, keyFile string, renewWindow, checkInterval time.Duration, stopCh <-chan struct{}, onRenew func())
func NeedRenew(cert *x509.Certificate, renewalWindow time.Duration) bool
func ParsePEMCert(data []byte) (*x509.Certificate, error)
```

## 确认续签 (confirmed_renewal.go)

说明书 P2-A-12/17（P0-2）：续签进入"等待责任主体确认"状态机，责任主体用其私钥重签
DA（新 nonce/timestamp/requestedLifetime），网关校验 DA 签名 + 权限复查（新 capabilities
⊆ 责任主体 PA grants）后签发新证书，旧证书标记过渡（连接关闭跳过吊销）。权限被削减
则拒绝续签。

```go
type RenewalState int
const RenewalIdle / RenewalAwaitingConfirmation / RenewalConfirmed / RenewalRejected RenewalState
func (s RenewalState) String() string
type RenewalRequest struct { SessionID, CA, CN, SAN, AgentId, PrincipalUid, OldSerial, Validity, Profile, Capabilities }
type RenewalConfirmation struct { SessionID, DA, PrincipalCert, KeyHash }
func NewConfirmedRenewalManager(issueCfg *IssueConfig, registry *ConnExpiryRegistry, onIssued func(*x509.Certificate)) *ConfirmedRenewalManager
func (m *ConfirmedRenewalManager) SetTimeout(d time.Duration)
func (m *ConfirmedRenewalManager) State() RenewalState
func (m *ConfirmedRenewalManager) CurrentSessionID() string
func (m *ConfirmedRenewalManager) RequestRenewal(req *RenewalRequest) error
func (m *ConfirmedRenewalManager) Confirm(conf *RenewalConfirmation) (*IssueResult, error)
func (m *ConfirmedRenewalManager) Reject(reason string)
func (m *ConfirmedRenewalManager) Reason() string
func (m *ConfirmedRenewalManager) Issued() *IssueResult
func (m *ConfirmedRenewalManager) Reset()
func SignRenewalDA(req *RenewalRequest, key crypto.Signer, nonce []byte, ts time.Time, lifetime int, reasonCode, reasonDesc string) (DelegationAuthorization, error)
func DAToPayload(da DelegationAuthorization) RenewalDAPayload
func KeyHashHex(cert *x509.Certificate) string
```

管理 API 端点（ManagementServer 标准路由）：`GET /renewal/status`、
`POST /renewal/request`、`POST /renewal/confirm`、`POST /renewal/reject`（见 gateway.md §2.10-2.13）。

## 吊销 (revoker.go)

```go
func NewRevoker(cfg RevokerConfig) (*Revoker, error)
func (r *Revoker) RevokeClientCert(cert *x509.Certificate, audit *AuditLogger)
func (r *Revoker) RevokeClientCertForced(cert *x509.Certificate, audit *AuditLogger)
func NormalizeSerial(serial *big.Int) string
```

`RevokeClientCert`：条件性吊销（未过期 + 未续期才吊销；ConnExpiryRegistry renewed 标记 → skip）。`RevokeClientCertForced`（G2(c)）：强制吊销，绕过 renewed 标记——主动安全吊销（risk monitor 踢线 / 任务完成"用完即吊销"）必须用它，否则攻击者使证书标记 renewed 即永久逃脱吊销。

## 统一准入管线 (pipeline.go)

```go
func RunAccessPipeline(chain []*x509.Certificate, cfg *PipelineConfig) *PipelineResult
func OfflineLifetimeFor(ocspFallback string) time.Duration
const OfflineLifetimeLimit = time.Hour
func HasAIC(cert *x509.Certificate) bool
```

`PipelineConfig.OfflineMaxCertLifetime`（G2(b)）：>0 时吊销检查走 fail-open 的离线场景强制证书剩余有效期 ≤ 该值，超限拒绝；网关用 `OfflineLifetimeFor(ocspFallback)` 计算（`OCSPFallbackAllow` → 1h，其余 0）。`HasAIC`（G2(a)）：判断证书是否携带合法 AIC 扩展（短时证书识别，数据面强制过期断开用）。


## 任务生命周期 (tasks.go)

```go
type TaskRegistry struct{ /* RWMutex + map[taskID]*TaskRecord */ }
func NewTaskRegistry() *TaskRegistry
func (r *TaskRegistry) Register(taskID, serial, agentID, note string, now int64) *TaskRecord
func (r *TaskRegistry) Complete(taskID string, now int64) *TaskRecord
func (r *TaskRegistry) Unregister(taskID string) *TaskRecord
func (r *TaskRegistry) Lookup(taskID string) *TaskRecord
func (r *TaskRegistry) List() []TaskRecord
func (r *TaskRegistry) Len() int

const HeaderTaskID = "X-AIC-Task-Id"
const HeaderTaskStatus = "X-AIC-Task-Status"
const CompletedHeaderValue = "completed"
func TaskIDFromHeader(h func(string) string) string
func TaskCompletedFromHeader(h func(string) string, fallbackID string) (id string, done bool)
```

## 连接跟踪 (tracker.go)

```go
func NewConnectionTracker() *ConnectionTracker
func (t *ConnectionTracker) Add(serial string, max int64) bool
func (t *ConnectionTracker) Remove(serial string)
func (t *ConnectionTracker) Count(serial string) int64
func (t *ConnectionTracker) Total() int64
func (t *ConnectionTracker) Snapshot() map[string]int64
func (t *ConnectionTracker) Render() string
```

## 连接注册 (registry.go)

```go
func NewConnRegistry() *ConnRegistry
func (r *ConnRegistry) Register(agentId, principalUid string, close CloseFunc) func()
func (r *ConnRegistry) RegisterConn(agentId, principalUid, srcIP, protocol, serial string, close CloseFunc) func()
func (r *ConnRegistry) DisconnectByAgentId(agentId string) int
func (r *ConnRegistry) DisconnectByPrincipalUid(principalUid string) int
func (r *ConnRegistry) ListConnections() []ConnectionInfo
func (r *ConnRegistry) ListByIP(srcIP string) []ConnectionInfo
func (r *ConnRegistry) Stats() int
func (r *ConnRegistry) ListByAgentId() map[string]int
```

## 风险监控 (riskmonitor.go)

```go
func NewRiskMonitor(cfg RiskMonitorConfig) *RiskMonitor
func (m *RiskMonitor) RecordViolation(v RiskViolation) bool
func (m *RiskMonitor) Violations(agentId string) int
func (m *RiskMonitor) Rules() []RiskRule
func (m *RiskMonitor) SetRules(rules []RiskRule)
```

## 管理服务器 (management.go)

```go
func NewManagementServer(cfg ManagementServerConfig) *ManagementServer
func (ms *ManagementServer) RegisterHandler(pattern string, handler http.HandlerFunc, allowedRoles ...string)
func (ms *ManagementServer) RegisterRawHandler(pattern string, handler http.HandlerFunc)
func (ms *ManagementServer) Start() error
func (ms *ManagementServer) Stop()
func (ms *ManagementServer) UpdatePluginRegistry(reg *PluginRegistry)
func MakeDisconnectByAgentHandler(registry *ConnRegistry, tr Translator, lang string) http.HandlerFunc
func MakeDisconnectByUserHandler(registry *ConnRegistry, tr Translator, lang string) http.HandlerFunc
func WriteMgmtJSON(w http.ResponseWriter, status int, v interface{})
func WriteMgmtError(w http.ResponseWriter, status int, message string)
```

## 幂等关闭 (stopher.go)

```go
func NewStopGuard() *StopGuard
func (s *StopGuard) Stop() bool
func (s *StopGuard) StopChan() <-chan struct{}
func (s *StopGuard) IsStopped() bool
func (s *StopGuard) Reset()
```

## 限速 (ratelimit.go)

```go
func NewTokenBucket(rate float64, burst int64) *TokenBucket
func (tb *TokenBucket) Allow(n int) bool
func (tb *TokenBucket) WaitN(n int)
func (tb *TokenBucket) SetRate(rate float64)
func (tb *TokenBucket) SetBurst(burst int64)
```

## 脱敏 (mask.go)

```go
func MaskString(s string, visible int) string
func MaskCertSerial(serial string) string
func MaskFilePath(path string) string
func MaskToken(token string) string
func MaskEmail(email string) string
func SanitizeString(s string) string
```

## 告警 (alarm.go)

```go
func NewAlarmClient(cfg *AlarmConfig) *AlarmClient
func (a *AlarmClient) AddSource(s AlarmSource)
func (a *AlarmClient) Start(stopCh chan struct{})
func (a *AlarmClient) Stop()
func NewMetricSource(name string, val float64) *MetricSource
func NewAggregateSource() *AggregateSource
func (a *AggregateSource) Set(name string, val float64)
func NewSnapshotSource(fn func() map[string]float64) *SnapshotSource
```

#### AlarmSource 实现

- `(m *MetricSource) Name() string` — 指标源名称
- `(m *MetricSource) Value() (float64, bool)` — 获取当前指标值
- `(a *AggregateSource) Name() string` — 聚合源名称
- `(a *AggregateSource) Value() (float64, bool)` — 获取聚合值
- `(s *SnapshotSource) Name() string` — 快照源名称
- `(s *SnapshotSource) Value() (float64, bool)` — 获取快照值

## Nonce 缓存 (nonce_cache.go)

```go
func NewNonceCache() *NonceCache
func (nc *NonceCache) CheckAndAdd(scope string, nonce []byte) bool
func (nc *NonceCache) Stop()
func (nc *NonceCache) Len() int
```

## 流多路复用 (streammux.go)

```go
func NewStreamMux(conn net.Conn) *StreamMux
func (m *StreamMux) Open() (*MuxStream, error)
func (m *StreamMux) Accept() (*MuxStream, error)
func (m *StreamMux) Close() error
```

#### MuxStream 方法

- `(s *MuxStream) LocalID() uint32` — 本地流 ID
- `(s *MuxStream) RemoteID() uint32` — 远端流 ID
- `(s *MuxStream) Read(b []byte) (int, error)` — 读取数据（实现 io.Reader）
- `(s *MuxStream) Write(b []byte) (int, error)` — 写入数据（实现 io.Writer）
- `(s *MuxStream) Close() error` — 关闭流
- `(s *MuxStream) LocalAddr() net.Addr` — 本地地址
- `(s *MuxStream) RemoteAddr() net.Addr` — 远端地址
- `(s *MuxStream) SetDeadline(t time.Time) error` — 设置读写截止时间
- `(s *MuxStream) SetReadDeadline(t time.Time) error` — 设置读取截止时间
- `(s *MuxStream) SetWriteDeadline(t time.Time) error` — 设置写入截止时间

## Mesh 联邦 (mesh.go)

```go
func NewMeshManager(cfg MeshConfig) *MeshManager
func (m *MeshManager) Start() error
func (m *MeshManager) Forward(peerName string, conn net.Conn) error
func (m *MeshManager) HealthyPeers() []MeshPeer
func (m *MeshManager) SelectPeer(tags map[string]string) *MeshPeer
func (m *MeshManager) Stop()
```

## 策略版本化 (policystore.go)

```go
type PolicySnapshot struct {
    Version        uint64        // 单调递增版本号
    Source         string        // "api" / "sighup"
    Operator       string        // API 操作者 CN
    RolledBackFrom uint64        // 回滚来源版本
    Timestamp      time.Time
    Configs        PluginConfigs // 完整配置快照
}

type PolicyBranch struct {
    ID       string // 分支唯一标识
    AgentID  string // 匹配串：精确 "a-123" / 前缀 "a-*" / 全量 "*"
    Version  uint64 // 命中分支后生效的策略版本
    Priority int    // 优先级，越大越先匹配
    Comment  string // 灰度范围/回退预案说明
}

type PolicyManager struct {
    MaxHistory         int    // 历史快照上限，默认 64
    MinRollbackVersion uint64 // 回滚下界，0=不启用
}

func NewPolicyManager(registry *PluginRegistry) *PolicyManager
func (pm *PolicyManager) Registry() *PluginRegistry
func (pm *PolicyManager) CurrentVersion() uint64
func (pm *PolicyManager) ActiveSnapshot() *PolicySnapshot
func (pm *PolicyManager) History() []*PolicySnapshot
func (pm *PolicyManager) Publish(configs PluginConfigs, source, operator string) (uint64, error)
func (pm *PolicyManager) Rollback(version uint64, source, operator string) (uint64, error)
func (pm *PolicyManager) SetBranches(branches []PolicyBranch) error // 全量替换分支规则（任务 5b）
func (pm *PolicyManager) Branches() []PolicyBranch
func (pm *PolicyManager) ClearBranches()
func (pm *PolicyManager) SelectRegistry(agentID string) (uint64, *PluginRegistry) // 按 Agent 选择版本注册表
func (pm *PolicyManager) Reset()
func (s *PolicySnapshot) SnapshotJSON() map[string]interface{}
```

### 分支控制（任务 5b）

`PolicyBranch` 按 Agent 标识路由到指定策略版本，实现金丝雀灰度。`SelectRegistry(agentID)` 命中分支返回该版本独立插件注册表与版本号（未污染 active），未命中返回当前版本。决策管线经 `PipelineConfig.CapabilityPluginResolver` 接线：命中分支的 Agent 插件评估与审计绑定均用分支版本，审计 `policy_version` 记录分支版本号。

## 配置热重载 (configwatch.go)

```go
func NewConfigWatcher(url string, tlsConfig *tls.Config, interval time.Duration, onChange func([]byte) error) *ConfigWatcher
func (w *ConfigWatcher) Start()
func (w *ConfigWatcher) Stop()
func ApplyJSONConfig[T any](target *T) func([]byte) error
func ConfigWatcherFromCLI(url string, tlsConfig *tls.Config, onChange func([]byte) error) *ConfigWatcher
```

## SPIFFE (spiffe.go)

```go
func ParseSPIFFEID(s string) (*SPIFFEID, error)
func (s *SPIFFEID) String() string
func (s *SPIFFEID) Equal(other *SPIFFEID) bool
func ExtractSPIFFEID(cert *x509.Certificate) *SPIFFEID
func ParseSPIFFEExtension(cert *x509.Certificate) (*SPIFFEID, error)
```

## Principal Profile (principal.go)

```go
func ParsePrincipalProfile(cert *x509.Certificate, aic *AIC, up *UserPermission) (*PrincipalProfile, error)
func (p *PrincipalProfile) HasRole(role string) bool
func (p *PrincipalProfile) AllowsDelegationMode(mode int) bool
func ParsePrincipalProfileExtension(cert *x509.Certificate) *PrincipalProfileExtension
```

## Renewal Token (renewal_token.go)

```go
func ParseRenewalToken(exts []pkix.Extension) (*RenewalTokenExt, error)
func (r *RenewalTokenExt) IsExpired() bool
func (r *RenewalTokenExt) VerifyNonce() bool
func (r *RenewalTokenExt) ValidateConstraints() error
```

## 离线 RBAC

- `func ParseOfflineRBAC(cert *x509.Certificate) *OfflineRbacExt` — 从证书扩展解析离线 RBAC
- `func OfflineRBACCheck(ext *OfflineRbacExt, opts OfflineRBACCheckOptions) OfflineRBACDecision` — 执行离线 RBAC 检查

## 连接过期注册表 (connexpiry.go)

```go
func NewConnExpiryRegistry() *ConnExpiryRegistry
func (r *ConnExpiryRegistry) Register(serial string, cert *x509.Certificate) func()
func (r *ConnExpiryRegistry) UpdateCert(serial string, cert *x509.Certificate) bool
func (r *ConnExpiryRegistry) Unregister(serial string)
func (r *ConnExpiryRegistry) ShouldSkipRevoke(serial string) bool
func (r *ConnExpiryRegistry) Connections(serial string) int64
func (r *ConnExpiryRegistry) Renewed(serial string) bool
func (r *ConnExpiryRegistry) Certificate(serial string) *x509.Certificate
func (r *ConnExpiryRegistry) StartExpiryLoop(interval time.Duration, stopCh <-chan struct{}) func()
func (r *ConnExpiryRegistry) Len() int
func (r *ConnExpiryRegistry) SerialNumbers() []string
```

以证书序列号为键跟踪活跃连接与续期标记（P2-A-14/15/16）：`Register` 返回注销函数，连接关闭调用；续期成功 `UpdateCert` 置 renewed=true，关闭吊销评估时 `ShouldSkipRevoke` 返回 true 则跳过吊销；5s 过期协程清理到期过渡条目（自动过期、不进 CRL）。

## 凭证包 (credential_bundle.go)

```go
func NewCredentialBundle(agentChain, principalChain, caCerts []*x509.Certificate) (*CredentialBundle, error)
func (b *CredentialBundle) Agent() *x509.Certificate
func (b *CredentialBundle) Principal() *x509.Certificate
func VerifyBundle(bundle *CredentialBundle, roots *x509.CertPool) error
func VerifyPrincipalKeyHash(agent, principal *x509.Certificate) error
func ParseCredentialBundlePEM(data []byte) (*CredentialBundle, error)
```

凭证包双链验证（P1-B-27/P2-A-01/P1-B-29）：Agent 链（含 AIC）与 Principal 链（含 PA）锚定同一信任根，keyHash 匹配主体 SPKI；缺失主体链/不同信任根/SPKI 不匹配均拒绝（Fail-Close）。

## 双证书 belong-to 强绑定 (belongto.go)

```go
func VerifyBelongTo(handshake, auth *x509.Certificate, roots *x509.CertPool) error
```

双证书部署（`08-dual-cert.md`）belong-to 强绑定（G4）：握手证书（TLS 层）与授权证书（应用层）必须同一密钥对（SPKI 逐字节相等，密码学绑定）+ 同一 CA（同签发者）+ 同一信任链（授权证书可被验证握手证书链的同一信任根池验证）。`agentId` 等标识字段不参与绑定（UTF8String 非密码学绑定，仅日志用）——替换任一证书或换签发 CA 即拒绝（Fail-Close）。

## 三层信任模型 (trust_model.go)

```go
func VerifyLayer1(chain []*x509.Certificate, cfg *PipelineConfig) *Layer1Result
func VerifyLayer2(chain []*x509.Certificate, cfg *PipelineConfig, roles []string) (AdmissionResult, *Layer2Result)
func VerifyLayer3(chain []*x509.Certificate, cfg *PipelineConfig) *Layer3Result
func VerifyTrustLayers(chain []*x509.Certificate, cfg *PipelineConfig) *PipelineResult
```

显式三层信任验证（P2-A-02）：L1 身份（有效期+RBAC）→ L2 代表关系（AIC/PA 解析+代表校验）→ L3 在线授权（CRL/OCSP + `PolicyServer.CheckOnline`）。`VerifyTrustLayers` 与 `RunAccessPipeline` 结果一致。

## 参数级边界校验 (parameters.go)

```go
type ParameterValidator interface { Scheme() string; Validate(granted, declared Capability) error }
type ParameterValidatorRegistry struct{}
func NewParameterValidatorRegistry() *ParameterValidatorRegistry
func (r *ParameterValidatorRegistry) Register(v ParameterValidator) error
func (r *ParameterValidatorRegistry) Find(schemeID string) (ParameterValidator, error)
func (r *ParameterValidatorRegistry) ValidateCapability(granted, declared Capability) error
func (r *ParameterValidatorRegistry) Reset() / Len() / Keys()
var MaxRowsValidator ParameterValidator
func RegisterParameterValidator(v ParameterValidator) error
func ResetParameterValidators()
```

参数级越界比对（P1-B-11/P2-B-05）：按 schemeId 注册参数边界校验器（示例 `MaxRowsValidator`：granted max_rows 边界 vs declared，越界拒绝）；`PipelineConfig.ParameterValidators` 在 P∩C 交集后逐条比对。

## 二进制自验证 (selfverify.go)

```go
func VerifySelf(exePath string, roots *x509.CertPool) (*x509.Certificate, error)
func VerifySelfWithOptions(exePath string, opts SelfVerifyOptions) (*x509.Certificate, error)
func VerifySignedBinary(data, sig []byte, roots *x509.CertPool) (*x509.Certificate, error)
func VerifyCurrentExecutable(roots *x509.CertPool) error
func MustVerifyCurrentExecutable(roots *x509.CertPool)
func PEMRootPool(pemData []byte) (*x509.CertPool, error)
```

用于"分离式 + 自验证"二进制部署：可执行文件保持原生格式，旁边放 `<name>.p7s` 分离签名；
目标程序在 `main()` 第一行调用 `gw.MustVerifyCurrentExecutable(roots)`，用 `os.Executable()`
定位自身并校验签名，失败即退出（fail-closed）。签名用 `pki sign <binary>` 生成。

## 信号处理 (signal_unix.go)

```go
func RegisterReloadSignal(sigCh chan os.Signal)
func IsReloadSignal(sig os.Signal) bool
```
