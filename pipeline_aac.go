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

	"github.com/varwof/gateway-core/acps"
)

// ReplayGuard enforces one-time-use delegation token jti (AAC §14.3(2)). The
// pipeline's NonceCache by contract permits the *same* certificate to repeat the
// same nonce (transport retransmission on the DA path); a one-time-use jti must
// be refused on ANY second use, so the AAC wrapper keeps this dedicated guard
// and uses NonceCache as an additional cross-certificate check.
type ReplayGuard struct {
	mu   sync.Mutex
	seen map[string]struct{}
}

// NewReplayGuard creates an empty one-time-use guard.
func NewReplayGuard() *ReplayGuard {
	return &ReplayGuard{seen: make(map[string]struct{})}
}

// FirstUse records jti and reports false when it was already used (by anyone).
func (g *ReplayGuard) FirstUse(jti string) bool {
	if g == nil || jti == "" {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.seen[jti]; ok {
		return false
	}
	g.seen[jti] = struct{}{}
	return true
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
	clientCert := chain[0]

	fail := func(code int, reason string) *PipelineResult {
		aac.emitAudit(cfg, clientCert, req, code, reason)
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
	rec := acps.AuditRecord{
		Event:      "authorization_decision",
		Decision:   "deny",
		ReasonCode: reason,
		Providers:  nil,
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
			Roles:        nil,
			Capabilities: aacRoleScopes(rec),
		})
	}
}

// aacRoleScopes extracts the subject scopes for the audit entry.
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
