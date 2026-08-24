# gateway-core Function Reference

All exported functions grouped by module. Package alias: `gw`

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

## CRL Cache (crl.go)

```go
func NewCRLCache(caCert *x509.Certificate, url string, refreshSec int, translator Translator, lang string) *CRLCache
func (c *CRLCache) Start(stop <-chan struct{})
func (c *CRLCache) ForceRefresh() error
func (c *CRLCache) IsRevoked(caDN string, serial *big.Int) (bool, error)
func (c *CRLCache) Stats() (revokedCount int, thisUpdate, nextUpdate time.Time)
func (c *CRLCache) LastRefresh() time.Time
```

## OCSP Cache (ocsp.go)

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

## Admission Decisions (decision.go)

```go
func CheckAdmission(cert *x509.Certificate, cfg AdmissionConfig) AdmissionResult
func (c AdmissionConfig) Validate() error
func VerifyDelegationAuth(aic *AIC, userCert *x509.Certificate) error
func CheckDAFreshness(ts time.Time, now time.Time, maxAge time.Duration) error // P1-B-13: DA timestamp freshness check (|now-ts| ≤ maxAge; ≤0 uses the default 30s)
func NeedRevoke(cert *x509.Certificate) bool
func HasDelegatedAgentOU(cert *x509.Certificate) bool
func CheckDelegatedAgentCert(cert *x509.Certificate, gs *GatewaySessionExtension) string
func CheckDelegatedAgentHeaders(cert *x509.Certificate, r *http.Request) string // Deprecated: B1 username path; use X-Client-Cert-DER certificate passthrough instead (B2)
func DelegatedAgentServerIdentity(cert *x509.Certificate, principal string, gs *GatewaySessionExtension) (user string, expiry time.Time, reason string)
func LogAdmission(result AdmissionResult, clientIP string, logger *slog.Logger)
```

`AdmissionResult.EffectiveCaps []Capability`: the P∩C intersection result (AIC declared capabilities ∩ PA grants), preserving full Capabilities (including SchemeId/Parameters); when no PA is present it contains the full AIC declaration. Used by stage-two plugin evaluation and parameter boundary validation (P0-3 two-stage capability routing, P2-A-06/P2-A-07).

## Unified Admission Pipeline (pipeline.go)

```go
func RunAccessPipeline(chain []*x509.Certificate, cfg *PipelineConfig) *PipelineResult
```

## Plugin System (plugin.go, pluginconfig.go)

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

Two-stage capability routing (P0-3): stage one (connection layer) filters inside `RunAccessPipeline` using `AdmissionResult.EffectiveCaps` (the P∩C intersection) aligned by scheme — schemes not served by this gateway are recorded as `ignore` in the audit log and skipped without blocking the connection; stage two (operation layer) calls `CheckOperationCapability` to decide on "the specific operation to be executed": no plugin for the operation scheme → fail-closed rejection; plugin deny → rejection; allow/bypass → permitted.

```go
func CheckOperationCapability(reg *PluginRegistry, cap *Capability, ctx *PluginContext) (*PluginResult, error)
```

`AdmissionResult.EffectiveCaps`: the full set of Capabilities after the P∩C intersection (including SchemeId/Parameters); equals the full AIC declaration when no PrincipalAuthorization is present. Both plugin evaluation and parameter boundary validation operate on it rather than the raw certificate declaration set (avoiding wrongly rejecting/allowing authorized capabilities when multiple capabilities are declared).

## Audit (audit.go)

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

## Audit Index (audit_index.go)

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

## Merkle Hash Chain (merkle.go)

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

## Metrics (metrics.go)

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

## TSA Client (tsa.go)

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

## TSA Proof Log (tsa_proof.go)

```go
func NewTSAProofLogger(path string, tsa *TSAClient, chain *AuditChain, intervalSec int) *TSAProofLogger
func (l *TSAProofLogger) Start(stopCh chan struct{})
func (l *TSAProofLogger) Close() error
func (l *TSAProofLogger) SetAuditChain(chain *AuditChain)
func (l *TSAProofLogger) Stop()
```

## Short-Lived Certificates (shortlived.go)

```go
func NewIssueClient(cfg IssueConfig) (*IssueClient, error)
func (c *IssueClient) Issue(req *IssueRequest) (*IssueResult, error)
func (r *IssueResult) Certificate() (*x509.Certificate, error)
func AutoIssueCert(cfg *IssueConfig, cn, san string) (*AutoIssueResult, error)
func RenewalLoop(cfg *IssueConfig, cn, san, certFile, keyFile string, renewWindow, checkInterval time.Duration, stopCh <-chan struct{}, onRenew func())
func NeedRenew(cert *x509.Certificate, renewalWindow time.Duration) bool
func ParsePEMCert(data []byte) (*x509.Certificate, error)
```

## Confirmed Renewal (confirmed_renewal.go)

Spec P2-A-12/17 (P0-2): renewal enters an "awaiting principal confirmation" state machine. The principal re-signs the DA with its private key (new nonce/timestamp/requestedLifetime); the gateway verifies the DA signature plus a permission re-check (new capabilities ⊆ principal PA grants) before issuing the new certificate, and marks the old certificate as transitional (revocation skipped on connection close). Renewal is rejected if permissions were reduced.

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

Management API endpoints (standard ManagementServer routes): `GET /renewal/status`, `POST /renewal/request`, `POST /renewal/confirm`, `POST /renewal/reject` (see gateway.md §2.10-2.13).

## Revocation (revoker.go)

```go
func NewRevoker(cfg RevokerConfig) (*Revoker, error)
func (r *Revoker) RevokeClientCert(cert *x509.Certificate, audit *AuditLogger)
func (r *Revoker) RevokeClientCertForced(cert *x509.Certificate, audit *AuditLogger)
func NormalizeSerial(serial *big.Int) string
```

`RevokeClientCert`: conditional revocation (only revokes when the certificate is unexpired and not renewed; ConnExpiryRegistry renewed flag → skip). `RevokeClientCertForced` (G2(c)): forced revocation that bypasses the renewed flag — proactive security revocations (risk monitor kick / task-completion "revoke after use") must use it, otherwise an attacker who gets a certificate flagged as renewed permanently escapes revocation.

## Unified Admission Pipeline (pipeline.go)

```go
func RunAccessPipeline(chain []*x509.Certificate, cfg *PipelineConfig) *PipelineResult
func OfflineLifetimeFor(ocspFallback string) time.Duration
const OfflineLifetimeLimit = time.Hour
func HasAIC(cert *x509.Certificate) bool
```

`PipelineConfig.OfflineMaxCertLifetime` (G2(b)): when >0, in offline scenarios where revocation checks run fail-open, certificates with remaining validity exceeding this value are rejected; gateways compute it via `OfflineLifetimeFor(ocspFallback)` (`OCSPFallbackAllow` → 1h, otherwise 0). `HasAIC` (G2(a)): reports whether the certificate carries a valid AIC extension (short-lived certificate detection, used for data-plane forced disconnect on expiry).


## Task Lifecycle (tasks.go)

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

## Connection Tracking (tracker.go)

```go
func NewConnectionTracker() *ConnectionTracker
func (t *ConnectionTracker) Add(serial string, max int64) bool
func (t *ConnectionTracker) Remove(serial string)
func (t *ConnectionTracker) Count(serial string) int64
func (t *ConnectionTracker) Total() int64
func (t *ConnectionTracker) Snapshot() map[string]int64
func (t *ConnectionTracker) Render() string
```

## Connection Registry (registry.go)

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

## Risk Monitor (riskmonitor.go)

```go
func NewRiskMonitor(cfg RiskMonitorConfig) *RiskMonitor
func (m *RiskMonitor) RecordViolation(v RiskViolation) bool
func (m *RiskMonitor) Violations(agentId string) int
func (m *RiskMonitor) Rules() []RiskRule
func (m *RiskMonitor) SetRules(rules []RiskRule)
```

## Management Server (management.go)

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

## Idempotent Shutdown (stopher.go)

```go
func NewStopGuard() *StopGuard
func (s *StopGuard) Stop() bool
func (s *StopGuard) StopChan() <-chan struct{}
func (s *StopGuard) IsStopped() bool
func (s *StopGuard) Reset()
```

## Rate Limiting (ratelimit.go)

```go
func NewTokenBucket(rate float64, burst int64) *TokenBucket
func (tb *TokenBucket) Allow(n int) bool
func (tb *TokenBucket) WaitN(n int)
func (tb *TokenBucket) SetRate(rate float64)
func (tb *TokenBucket) SetBurst(burst int64)
```

## Masking (mask.go)

```go
func MaskString(s string, visible int) string
func MaskCertSerial(serial string) string
func MaskFilePath(path string) string
func MaskToken(token string) string
func MaskEmail(email string) string
func SanitizeString(s string) string
```

## Alarms (alarm.go)

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

#### AlarmSource Implementations

- `(m *MetricSource) Name() string` — metric source name
- `(m *MetricSource) Value() (float64, bool)` — returns the current metric value
- `(a *AggregateSource) Name() string` — aggregate source name
- `(a *AggregateSource) Value() (float64, bool)` — returns the aggregated value
- `(s *SnapshotSource) Name() string` — snapshot source name
- `(s *SnapshotSource) Value() (float64, bool)` — returns the snapshot value

## Nonce Cache (nonce_cache.go)

```go
func NewNonceCache() *NonceCache
func (nc *NonceCache) CheckAndAdd(scope string, nonce []byte) bool
func (nc *NonceCache) Stop()
func (nc *NonceCache) Len() int
```

## Stream Multiplexing (streammux.go)

```go
func NewStreamMux(conn net.Conn) *StreamMux
func (m *StreamMux) Open() (*MuxStream, error)
func (m *StreamMux) Accept() (*MuxStream, error)
func (m *StreamMux) Close() error
```

#### MuxStream Methods

- `(s *MuxStream) LocalID() uint32` — local stream ID
- `(s *MuxStream) RemoteID() uint32` — remote stream ID
- `(s *MuxStream) Read(b []byte) (int, error)` — reads data (implements io.Reader)
- `(s *MuxStream) Write(b []byte) (int, error)` — writes data (implements io.Writer)
- `(s *MuxStream) Close() error` — closes the stream
- `(s *MuxStream) LocalAddr() net.Addr` — local address
- `(s *MuxStream) RemoteAddr() net.Addr` — remote address
- `(s *MuxStream) SetDeadline(t time.Time) error` — sets read/write deadlines
- `(s *MuxStream) SetReadDeadline(t time.Time) error` — sets the read deadline
- `(s *MuxStream) SetWriteDeadline(t time.Time) error` — sets the write deadline

## Mesh Federation (mesh.go)

```go
func NewMeshManager(cfg MeshConfig) *MeshManager
func (m *MeshManager) Start() error
func (m *MeshManager) Forward(peerName string, conn net.Conn) error
func (m *MeshManager) HealthyPeers() []MeshPeer
func (m *MeshManager) SelectPeer(tags map[string]string) *MeshPeer
func (m *MeshManager) Stop()
```

## Policy Versioning (policystore.go)

```go
type PolicySnapshot struct {
    Version        uint64        // monotonically increasing version number
    Source         string        // "api" / "sighup"
    Operator       string        // CN of the API operator
    RolledBackFrom uint64        // version rolled back from
    Timestamp      time.Time
    Configs        PluginConfigs // full configuration snapshot
}

type PolicyBranch struct {
    ID       string // unique branch identifier
    AgentID  string // match pattern: exact "a-123" / prefix "a-*" / catch-all "*"
    Version  uint64 // policy version applied when the branch matches
    Priority int    // priority; higher values match first
    Comment  string // canary scope / rollback plan notes
}

type PolicyManager struct {
    MaxHistory         int    // history snapshot limit, default 64
    MinRollbackVersion uint64 // rollback lower bound, 0 = disabled
}

func NewPolicyManager(registry *PluginRegistry) *PolicyManager
func (pm *PolicyManager) Registry() *PluginRegistry
func (pm *PolicyManager) CurrentVersion() uint64
func (pm *PolicyManager) ActiveSnapshot() *PolicySnapshot
func (pm *PolicyManager) History() []*PolicySnapshot
func (pm *PolicyManager) Publish(configs PluginConfigs, source, operator string) (uint64, error)
func (pm *PolicyManager) Rollback(version uint64, source, operator string) (uint64, error)
func (pm *PolicyManager) SetBranches(branches []PolicyBranch) error // replace all branch rules (Task 5b)
func (pm *PolicyManager) Branches() []PolicyBranch
func (pm *PolicyManager) ClearBranches()
func (pm *PolicyManager) SelectRegistry(agentID string) (uint64, *PluginRegistry) // select the version registry by agent
func (pm *PolicyManager) Reset()
func (s *PolicySnapshot) SnapshotJSON() map[string]interface{}
```

### Branch Control (Task 5b)

`PolicyBranch` routes agents to specific policy versions by agent identifier, enabling canary rollouts. `SelectRegistry(agentID)` returns the isolated plugin registry and version of the matched branch (without polluting active); on no match it returns the current version. The decision pipeline wires in via `PipelineConfig.CapabilityPluginResolver`: plugin evaluation and audit binding for agents hitting a branch both use the branch version, and the audit field `policy_version` records the branch version number.

## Config Hot Reload (configwatch.go)

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

## Offline RBAC

- `func ParseOfflineRBAC(cert *x509.Certificate) *OfflineRbacExt` — parses offline RBAC from a certificate extension
- `func OfflineRBACCheck(ext *OfflineRbacExt, opts OfflineRBACCheckOptions) OfflineRBACDecision` — performs the offline RBAC check

## Connection Expiry Registry (connexpiry.go)

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

Tracks active connections and renewal flags keyed by certificate serial (P2-A-14/15/16): `Register` returns a deregistration function invoked on connection close; on successful renewal `UpdateCert` sets renewed=true, and `ShouldSkipRevoke` returning true skips revocation during close-time evaluation; a 5s expiry goroutine cleans up transitional entries past expiry (expires automatically, never enters the CRL).

## Credential Bundle (credential_bundle.go)

```go
func NewCredentialBundle(agentChain, principalChain, caCerts []*x509.Certificate) (*CredentialBundle, error)
func (b *CredentialBundle) Agent() *x509.Certificate
func (b *CredentialBundle) Principal() *x509.Certificate
func VerifyBundle(bundle *CredentialBundle, roots *x509.CertPool) error
func VerifyPrincipalKeyHash(agent, principal *x509.Certificate) error
func ParseCredentialBundlePEM(data []byte) (*CredentialBundle, error)
```

Credential bundle dual-chain verification (P1-B-27/P2-A-01/P1-B-29): the Agent chain (containing the AIC) and the Principal chain (containing the PA) must anchor to the same trust root, and the keyHash must match the principal's SPKI; missing principal chain / different trust root / SPKI mismatch are all rejected (fail-close).

## Dual-Certificate belong-to Binding (belongto.go)

```go
func VerifyBelongTo(handshake, auth *x509.Certificate, roots *x509.CertPool) error
```

Dual-certificate deployment (`08-dual-cert.md`) belong-to strong binding (G4): the handshake certificate (TLS layer) and the authorization certificate (application layer) must share the same key pair (byte-identical SPKI, cryptographic binding) + the same CA (same issuer) + the same trust chain (the authorization certificate must verify against the same trust root pool used to validate the handshake certificate chain). Identifier fields such as `agentId` do not participate in the binding (UTF8String is not cryptographically bound, log-only) — replacing either certificate or switching the issuing CA results in rejection (fail-close).

## Three-Layer Trust Model (trust_model.go)

```go
func VerifyLayer1(chain []*x509.Certificate, cfg *PipelineConfig) *Layer1Result
func VerifyLayer2(chain []*x509.Certificate, cfg *PipelineConfig, roles []string) (AdmissionResult, *Layer2Result)
func VerifyLayer3(chain []*x509.Certificate, cfg *PipelineConfig) *Layer3Result
func VerifyTrustLayers(chain []*x509.Certificate, cfg *PipelineConfig) *PipelineResult
```

Explicit three-layer trust verification (P2-A-02): L1 identity (validity + RBAC) → L2 representation relationship (AIC/PA parsing + representative verification) → L3 online authorization (CRL/OCSP + `PolicyServer.CheckOnline`). `VerifyTrustLayers` produces the same result as `RunAccessPipeline`.

## Parameter-Level Boundary Validation (parameters.go)

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

Parameter-level out-of-range comparison (P1-B-11/P2-B-05): parameter boundary validators are registered by schemeId (example `MaxRowsValidator`: granted max_rows boundary vs declared, out-of-range rejected); `PipelineConfig.ParameterValidators` compares entries one by one after the P∩C intersection.

## Binary Self-Verification (selfverify.go)

```go
func VerifySelf(exePath string, roots *x509.CertPool) (*x509.Certificate, error)
func VerifySelfWithOptions(exePath string, opts SelfVerifyOptions) (*x509.Certificate, error)
func VerifySignedBinary(data, sig []byte, roots *x509.CertPool) (*x509.Certificate, error)
func VerifyCurrentExecutable(roots *x509.CertPool) error
func MustVerifyCurrentExecutable(roots *x509.CertPool)
func PEMRootPool(pemData []byte) (*x509.CertPool, error)
```

Used for "detached + self-verifying" binary deployment: the executable stays in native format with a detached `<name>.p7s` signature placed alongside;
the target program calls `gw.MustVerifyCurrentExecutable(roots)` as the first line of `main()`, locates itself via `os.Executable()`
and verifies the signature, exiting on failure (fail-closed). Signatures are generated with `pki sign <binary>`.

## Signal Handling (signal_unix.go)

```go
func RegisterReloadSignal(sigCh chan os.Signal)
func IsReloadSignal(sig os.Signal) bool
```
