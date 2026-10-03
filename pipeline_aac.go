// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// ACPs AAC enforcement wrapper for the admission pipeline.
//
// RunAccessPipelineAAC is an opt-in envelope around RunAccessPipeline: when the
// AAC profile is not enabled it returns exactly what the existing pipeline
// returns (default behavior unchanged). When enabled it adds the AAC denied
// layer — identity binding (AIP §6.0), trusted context construction (AAC §7),
// audience/chain/replay checks, and the fail-closed PDP decision — before any
// business processing, then records the authorization audit event (AAC §13).
//
// This is a separate file on purpose: pipeline.go carries unrelated uncommitted
// SPIFFE work, so nothing in the existing pipeline is modified.
package gw

import (
	"crypto/x509"
	"sync"
	"time"

	"github.com/varwof/gateway-core/acps"
)

// ReplayGuard enforces one-time-use delegation token jti (AAC §14.3(2)). The
// pipeline's NonceCache by contract permits the *same* certificate to repeat the
// same nonce (transport retransmission on the DA path); a one-time-use jti must
// be refused on ANY second use, so the AAC wrapper keeps this dedicated guard
// and uses NonceCache as an additional cross-certificate check.
//
// The guard is bounded: entries are one-time-use and never resurrected, but
// stale entries are purged when the guard reaches capacity so memory does not
// grow without bound. It is still a single-process guard — sharing replay state
// across nodes requires an external store (v0 out of scope, see wiring-matrix).
type ReplayGuard struct {
	mu         sync.Mutex
	seen       map[string]time.Time
	maxEntries int
	ttl        time.Duration
	now        func() time.Time
}

// Defaults keep NewReplayGuard() safe for long-running processes.
const (
	DefaultReplayMaxEntries = 1_000_000
	DefaultReplayTTL        = 24 * time.Hour
)

// NewReplayGuard creates a bounded one-time-use guard with default limits.
func NewReplayGuard() *ReplayGuard {
	return NewReplayGuardLimited(DefaultReplayMaxEntries, DefaultReplayTTL)
}

// NewReplayGuardLimited creates a one-time-use guard capped at maxEntries
// (stale entries purged at capacity) with the given entry TTL for eviction.
// maxEntries <= 0 or ttl <= 0 fall back to the defaults.
func NewReplayGuardLimited(maxEntries int, ttl time.Duration) *ReplayGuard {
	if maxEntries <= 0 {
		maxEntries = DefaultReplayMaxEntries
	}
	if ttl <= 0 {
		ttl = DefaultReplayTTL
	}
	return &ReplayGuard{
		seen:       make(map[string]time.Time, 0),
		maxEntries: maxEntries,
		ttl:        ttl,
		now:        time.Now,
	}
}

// FirstUse records jti and reports false when it was already used (by anyone).
// A used jti is never resurrected, even after its TTL passes.
func (g *ReplayGuard) FirstUse(jti string) bool {
	if g == nil || jti == "" {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.seen[jti]; ok {
		return false
	}
	now := g.now()
	if len(g.seen) >= g.maxEntries {
		g.purgeExpiredLocked(now)
	}
	if len(g.seen) >= g.maxEntries {
		// Still at capacity: drop an arbitrary stale entry to remain bounded.
		for k := range g.seen {
			delete(g.seen, k)
			break
		}
	}
	g.seen[jti] = now.Add(g.ttl)
	return true
}

// Len is the number of recorded jti entries (test/observability helper).
func (g *ReplayGuard) Len() int {
	if g == nil {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.seen)
}

func (g *ReplayGuard) purgeExpiredLocked(now time.Time) {
	for k, exp := range g.seen {
		if !exp.After(now) {
			delete(g.seen, k)
		}
	}
}

// AAC slice observability. Label keys are stable for Prometheus consumption:
// aac_decision_total{decision=allow|deny, reason=<internal reason or "allow">}.
var (
	MetricAACDecisionsTotal = NewMetricCounter("aac_decision_total", "AAC authorization decisions", "decision", "reason")
	MetricAACDecisionDur    = NewMetricHistogram("aac_decision_duration_ms", "AAC decision duration in milliseconds", []string{}, 0.1, 1, 5, 25, 100, 500)
)

func init() {
	RegisterCounter(MetricAACDecisionsTotal)
	RegisterHistogram(MetricAACDecisionDur)
}

// aacWarned de-duplicates per-config config-warning emission (first run only).
var aacWarned sync.Map // *AACProfileConfig -> struct{}

// Validate returns operator-facing warnings for AAC profile controls that are
// off by default and therefore weaker than they may look. It never blocks a
// decision: structural-only checksum, unlimited chain depth and disabled
// one-time-use replay are valid opt-in v0 configurations (see
// docs/acps/wiring-matrix.md "安全默认与显式配置").
func (aac *AACProfileConfig) Validate() []string {
	if aac == nil {
		return nil
	}
	var ws []string
	if len(aac.AICSalt) == 0 {
		ws = append(ws, "AIC checksum: salt unset, only structural validation runs (AIC §4.2)")
	}
	if aac.MaxChainDepth <= 0 {
		ws = append(ws, "delegation chain depth: unlimited (set MaxChainDepth to cap, AAC §9.4(5))")
	}
	if aac.ReplayGuard == nil {
		ws = append(ws, "one-time-use jti replay: disabled (set ReplayGuard, AAC §14.3(2))")
	}
	if aac.NonceCache == nil {
		ws = append(ws, "cross-certificate jti replay: disabled (set NonceCache)")
	}
	if len(aac.ObligationEvaluators) == 0 {
		ws = append(ws, "obligations: none configured (AAC §6.6)")
	}
	return ws
}

// warnOnce surfaces config warnings at most once per profile, at INFO level on
// the pipeline audit logger, so a weak default is never silent.
func (aac *AACProfileConfig) warnOnce(cfg *PipelineConfig) {
	if aac == nil || cfg == nil || cfg.AuditLogger == nil {
		return
	}
	if _, loaded := aacWarned.LoadOrStore(aac, struct{}{}); loaded {
		return
	}
	for _, w := range aac.Validate() {
		cfg.AuditLogger.Log(AuditEntry{
			Action:     "aac_config_warning",
			Decision:   "none",
			DenyReason: w,
			Level:      "INFO",
		})
	}
}

// AACRequest carries the per-request facts the AAC profile needs beyond the
// certificate chain: the resource/action to authorize and the client-presented
// delegation token (already crypto-verified by the gateway JWT verifier).
type AACRequest struct {
	// Action is the AIP action (task.start / task.result / notification.start …).
	Action string
	// Resource is the target resource of this request (AAC §6.6).
	Resource acps.AuthorizationResource
	// Bearer is the client-presented delegation token binding the primary
	// subject and actor chain. nil = single-hop agent call (Profile B).
	Bearer *acps.DelegationRecord
	// SenderID is the AIP message senderId field (AIP §6.0). When non-empty
	// it must match the certificate peer AIC.
	SenderID string
}

// AACProfileConfig configures the ACPs AAC enforcement layer (opt-in).
type AACProfileConfig struct {
	// Enabled turns the AAC profile on. Default off: RunAccessPipelineAAC
	// degenerates to RunAccessPipeline.
	Enabled bool
	// RequireSAN demands the supplementary SAN URI:acps://{AIC} in the peer
	// certificate (AIP §6.0 strict mode).
	RequireSAN bool
	// AICSalt is the ARSP checksum salt; when set, full AIC checksum
	// verification runs (AIC §4.2). Empty → structural validation only.
	AICSalt []byte
	// Audience is this resource server's canonical audience (AAC §6.7). When
	// non-empty, token aud must equal it.
	Audience string
	// MaxChainDepth caps the delegation chain depth (AAC §9.4(5)).
	MaxChainDepth int
	// AllowImpersonation permits explicit impersonation (AAC §14.4). Default
	// false: any impersonation marker is denied.
	AllowImpersonation bool
	// Policy is the PDP decision engine (RBAC/Capability adjudication,
	// AAC §8). nil policy fails closed (AAC §5(6)).
	Policy acps.PolicyFunc
	// ObligationEvaluators must all pass for an allow (AAC §6.6).
	ObligationEvaluators []acps.ObligationEvaluator
	// AuditSink, when set, receives every authorization decision record
	// (AAC §13). When nil, the wrapper falls back to the pipeline audit
	// logger (DenyReason carried at WARN level).
	AuditSink func(acps.AuditRecord)
	// ReplayGuard enforces one-time-use delegation token jti (AAC §14.3(2)).
	// When nil, one-time-use jti replay protection is disabled (not recommended).
	ReplayGuard *ReplayGuard
	// NonceCache performs the cross-certificate replay check: a jti reused by a
	// different peer certificate is denied (the cache intentionally permits the
	// same certificate repeating the same nonce; ReplayGuard covers that).
	NonceCache *NonceCache
}

// RunAccessPipelineAAC runs the existing admission pipeline and, when the AAC
// profile is enabled, the AAC enforcement layer. The chain must be non-empty
// and the first certificate the client certificate.
//
// Decisions are enforced before any business handler: a non-allow outcome
// returns a PipelineResult with Granted=false whose DenyReason only carries the
// AIP public message (Authentication required / Authorization failed / Invalid
// access token); internal reason codes go exclusively to audit (AAC §12).
func RunAccessPipelineAAC(chain []*x509.Certificate, cfg *PipelineConfig, aac *AACProfileConfig, req *AACRequest) *PipelineResult {
	res := RunAccessPipeline(chain, cfg)
	if !res.Granted {
		return res
	}
	if aac == nil || !aac.Enabled {
		return res
	}
	aac.warnOnce(cfg)
	clientCert := chain[0]
	start := time.Now()

	record := func(decision, reason string) {
		MetricAACDecisionsTotal.Inc(decision, reason)
		MetricAACDecisionDur.Observe(float64(time.Since(start).Nanoseconds()) / 1e6)
	}

	fail := func(code int, reason string) *PipelineResult {
		aac.emitAudit(cfg, clientCert, req, code, reason)
		record("deny", reason)
		return deny(aacPublicMessage(code))
	}

	// 1. Peer identity (AIP §6.0): CN primary, SAN acps:// supplementary.
	peerAIC, err := acps.ExtractPeerAIC(clientCert, aac.RequireSAN)
	if err != nil {
		return fail(acps.CodeAuthenticationRequired, acps.ReasonInvalidPeerIdentity)
	}
	if _, err := acps.Verify(peerAIC, aac.AICSalt); err != nil {
		return fail(acps.CodeAuthenticationRequired, acps.ReasonInvalidPeerIdentity)
	}
	// 2. AIP senderId <-> peer AIC consistency (AIP §6.0; AAC §9.2).
	if req != nil && req.SenderID != "" {
		if err := acps.MatchPeerAIC(peerAIC, req.SenderID); err != nil {
			return fail(acps.CodeAuthorizationFailed, acps.ReasonActorMismatch)
		}
	}
	if req == nil {
		return fail(acps.CodeAuthorizationFailed, acps.ReasonContextInvalid)
	}

	// 3. Trusted context construction (AAC §4 step 3 / §7). provider failures
	// fail closed (§7.6(2)).
	providers := []acps.ContextProvider{&acps.MTLSProvider{RequireSAN: aac.RequireSAN, Salt: aac.AICSalt}}
	inputs := []any{clientCert}
	if req.Bearer != nil {
		providers = append(providers,
			&acps.TokenProvider{PresenterCert: clientCert})
		inputs = append(inputs, req.Bearer)
	}
	ctx, err := acps.BuildContext(acps.BuildOptions{
		Providers: providers,
		Inputs:    inputs,
		Action:    req.Action,
		Resource:  req.Resource,
	})
	if err != nil {
		return fail(acps.CodeAuthorizationFailed, acps.ReasonContextInvalid)
	}

	// 4. Token-side AAC checks: audience (§6.7), chain depth (§9.4), replay
	// (§14.3). These run before the PDP so no policy evaluation happens on a
	// token that is already invalid.
	if req.Bearer != nil {
		if aac.Audience != "" && req.Bearer.Token.Aud != aac.Audience {
			return fail(acps.CodeAccessTokenInvalid, acps.ReasonBadToken)
		}
		if aac.MaxChainDepth > 0 && req.Bearer.Token.ChainDepth > aac.MaxChainDepth {
			return fail(acps.CodeAuthorizationFailed, acps.ReasonDepthExceeded)
		}
		// One-time-use jti (AAC §14.3(2)): any reuse is a replay.
		if aac.ReplayGuard != nil && !aac.ReplayGuard.FirstUse(req.Bearer.JTI()) {
			return fail(acps.CodeAccessTokenInvalid, acps.ReasonReplayDetected)
		}
		// Cross-certificate replay (defense in depth): a jti presented by a
		// different peer is denied (gateway NonceCache scope semantics).
		if aac.NonceCache != nil {
			scope := "peer:" + peerAIC
			if !aac.NonceCache.CheckAndAdd(scope, []byte(req.Bearer.JTI())) {
				return fail(acps.CodeAccessTokenInvalid, acps.ReasonReplayDetected)
			}
		}
	}

	// 5. PDP decision (AAC §4 steps 4-5, §5(6)(7)); every decision is audited.
	pdp := &acps.PDP{
		Policy:               aac.Policy,
		ObligationEvaluators: aac.ObligationEvaluators,
		AllowImpersonation:   aac.AllowImpersonation,
		Sink:                 aac.sink(cfg, clientCert, peerAIC),
	}
	dec := pdp.Decide(ctx.ToRequest())
	if !dec.Allowed {
		return fail(acps.CodeAuthorizationFailed, dec.ReasonCode)
	}
	record("allow", "allow")
	return res
}

// aacPublicMessage maps an AIP code to its outward-safe message (AAC §12).
func aacPublicMessage(code int) string {
	switch code {
	case acps.CodeAuthenticationRequired:
		return "Authentication required"
	case acps.CodeAccessTokenInvalid:
		return "Invalid access token"
	default:
		return "Authorization failed"
	}
}

// emitAudit records an authorization decision at WARN with the internal reason
// code and never the token / chain details (AAC §13).
func (aac *AACProfileConfig) emitAudit(cfg *PipelineConfig, cert *x509.Certificate, req *AACRequest, code int, reason string) {
	providers := []string{"mtls"}
	if req != nil && req.Bearer != nil {
		providers = append(providers, "delegation:token")
	}
	rec := acps.AuditRecord{
		Event:      "authorization_decision",
		Decision:   "deny",
		ReasonCode: reason,
		Providers:  providers,
		HighRisk:   acps.HighRiskReasons[reason],
	}
	if req != nil {
		rec.Action = req.Action
		rec.Resource = req.Resource
		rec.Token.DelegationID = bearerDelegationID(req)
		if req.Bearer != nil {
			rec.Token.Issuer = req.Bearer.Token.Iss
			rec.Token.Audience = req.Bearer.Token.Aud
			rec.Token.Jti = req.Bearer.JTI()
		}
	}
	if aac.AuditSink != nil {
		aac.AuditSink(rec)
		return
	}
	if cfg.AuditLogger != nil {
		cfg.AuditLogger.Log(AuditEntry{
			Action:     "authorization_decision",
			Decision:   "deny",
			DenyReason: reason,
			Level:      "WARN",
			ClientCN:   cert.Subject.CommonName,
		})
	}
}

// sink adapts the acps audit contract to the configured sink (or the gateway
// audit logger) so every PDP decision is recorded (AAC §13).
func (aac *AACProfileConfig) sink(cfg *PipelineConfig, cert *x509.Certificate, peerAIC string) func(acps.AuditRecord) {
	if aac.AuditSink != nil {
		return aac.AuditSink
	}
	if cfg.AuditLogger == nil {
		return nil
	}
	return func(rec acps.AuditRecord) {
		level := "INFO"
		if rec.Decision == "deny" {
			level = "WARN"
		}
		cfg.AuditLogger.Log(AuditEntry{
			Action:       "authorization_decision",
			Decision:     rec.Decision,
			DenyReason:   rec.ReasonCode,
			Level:        level,
			ClientCN:     cert.Subject.CommonName,
			AgentId:      peerAIC,
			PrincipalUid: rec.PrimarySubject,
			Roles:        nil, // acps carriers no RBAC role concept; adjudication is capability-based (§8.3)
			Capabilities: aacRoleScopes(rec),
		})
	}
}

// aacRoleScopes extracts the AIP capability scopes proven by the decision. The
// AAC envelope authorizes exactly one skill per request (AAC §6.6), so the
// scope set is a single acps.skill.invoke:<skill> entry.
func aacRoleScopes(rec acps.AuditRecord) []string {
	if rec.Resource.SkillId != "" {
		return []string{"acps.skill.invoke:" + rec.Resource.SkillId}
	}
	return nil
}

// bearerDelegationID returns the delegation id of the presented bearer token.
func bearerDelegationID(req *AACRequest) string {
	if req == nil || req.Bearer == nil || req.Bearer.Token == nil {
		return ""
	}
	if req.Bearer.Token.DelegationID != "" {
		return req.Bearer.Token.DelegationID
	}
	return ""
}
