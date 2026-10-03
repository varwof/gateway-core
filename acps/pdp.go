// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Policy decision point (AAC §4 steps 4-5, §5, §8).
//
// The PDP decides only over the verified AuthorizationRequest. Its contract is
// fail-closed: a request whose decision is not an explicit allow is denied
// (AAC §5(7)). Mandatory obligations returned with an allow must be satisfied
// by the enforcement point before business processing (AAC §6.6); this package
// exposes the evaluator hook so the gateway wiring (run through the PEP) can
// enforce them.
package acps

import (
	"strings"
	"time"
)

// Obligation is an additional requirement attached to an allow decision
// (AAC §6.6).
type Obligation struct {
	ID      string
	Payload map[string]string
}

// ObligationEvaluator checks whether the PEP can satisfy one obligation.
type ObligationEvaluator func(o Obligation) error

// AuthorizationDecision is the PDP result (AAC §6.6).
type AuthorizationDecision struct {
	Allowed     bool
	ReasonCode  string
	Obligations []Obligation
}

// Deny builds a denial with an internal reason code (audit side).
func Deny(reason string) *AuthorizationDecision {
	return &AuthorizationDecision{Allowed: false, ReasonCode: reason}
}

// Allow builds an allow decision that may carry obligations.
func Allow(obligations ...Obligation) *AuthorizationDecision {
	return &AuthorizationDecision{Allowed: true, Obligations: obligations}
}

// PolicyFunc is the injectable authorization model (ACL/RBAC/ABAC/ReBAC/OPA,
// AAC §8). Gateway wiring supplies the RBAC/capability adjudication here.
// A nil policy means "no decision possible" and is treated as deny (AAC §5(6)).
type PolicyFunc func(req *AuthorizationRequest) (*AuthorizationDecision, error)

// AuditSink records one authorization decision (AAC §13).
type AuditSink func(record AuditRecord)

// TokenAuditRef is the token metadata an audit entry may carry — never the
// token itself (AAC §13(1)).
type TokenAuditRef struct {
	Issuer       string
	Audience     string
	Jti          string
	DelegationID string
}

// AuditRecord is the authorization-decision audit event (AAC §13 example).
type AuditRecord struct {
	Event          string
	Decision       string // allow | deny
	ReasonCode     string
	PrimarySubject string
	ImmediateActor string
	ActorChain     []string
	Resource       AuthorizationResource
	Action         string
	Providers      []string
	Token          TokenAuditRef
	HighRisk       bool
	At             time.Time
}

// HighRiskReasons is the set of reason codes that must be logged at high risk /
// WARN level (AAC §13(4), §14.3(4)).
var HighRiskReasons = map[string]bool{
	ReasonImpersonation:     true,
	ReasonDepthExceeded:     true,
	ReasonActorMismatch:     true,
	ReasonChainTailMismatch: true,
	ReasonReplayDetected:    true,
	ReasonUnsignedDelegate:  true,
	ReasonUnboundDelegate:   true,
	ReasonSelfClaimed:       true,
	ReasonBoundaryViolation: true,
}

// PDP is the policy decision point (AAC §8). It is stateless after
// construction: concurrent calls are safe as long as the injected PolicyFunc
// and evaluators are themselves safe.
type PDP struct {
	// Policy is the decision engine; nil policy fails closed (AAC §5(6)).
	Policy PolicyFunc
	// ObligationEvaluators must all pass for an allow to hold (AAC §6.6).
	ObligationEvaluators []ObligationEvaluator
	// AllowImpersonation gates explicit impersonation (AAC §14.4).
	AllowImpersonation bool
	// Sink reports decisions; a nil sink silences audit (not recommended;
	// the enforcement wiring supplies one).
	Sink AuditSink
}

// Decide evaluates one request and returns the fail-closed decision. It
// records an audit event for every decision when a sink is configured.
func (p *PDP) Decide(req *AuthorizationRequest) *AuthorizationDecision {
	if req == nil {
		return p.deny(ReasonContextInvalid, req, nil)
	}
	// Impersonation is denied unless an explicit policy permits it (AAC
	// §14.4): the marker only arrives via a verified context fact, never a
	// payload field.
	if !p.AllowImpersonation {
		if req.VerifiedCtx != nil && req.VerifiedCtx["impersonation"] == "true" {
			return p.deny(ReasonImpersonation, req, nil)
		}
		for _, e := range req.Actor.Events {
			if e.Type == "impersonation" && e.Verified() {
				return p.deny(ReasonImpersonation, req, nil)
			}
		}
	}
	pol := p.Policy
	if pol == nil {
		return p.deny(ReasonPDPUnavailable, req, nil)
	}
	dec, err := pol(req)
	if err != nil {
		return p.deny(ReasonPDPUnavailable, req, err)
	}
	if dec == nil || !dec.Allowed {
		return p.deny(ReasonPolicyDenied, req, nil)
	}
	for _, eval := range p.ObligationEvaluators {
		for _, o := range dec.Obligations {
			if eval != nil {
				if err := eval(o); err != nil {
					return p.deny(ReasonObligationFailed, req, err)
				}
			}
		}
	}
	p.audit(req, &AuthorizationDecision{Allowed: true})
	return dec
}

// deny converts any non-allow situation into a denied decision and audits it.
func (p *PDP) deny(reason string, req *AuthorizationRequest, err error) *AuthorizationDecision {
	dec := Deny(reason)
	p.audit(req, dec)
	return dec
}

// audit emits the decision record when a sink is configured.
func (p *PDP) audit(req *AuthorizationRequest, dec *AuthorizationDecision) {
	if p.Sink == nil {
		return
	}
	rec := AuditRecord{
		Event:          "authorization_decision",
		Decision:       "deny",
		ReasonCode:     dec.ReasonCode,
		PrimarySubject: req.PrimarySubject.SubjectID,
		ImmediateActor: req.Actor.ImmediateActor.SubjectID,
		ActorChain:     append([]string(nil), req.Actor.ActorChain...),
		Resource:       req.Resource,
		Action:         req.Action,
		Token:          tokenRefFromReq(req),
		At:             time.Now().UTC(),
	}
	if dec.Allowed {
		rec.Decision = "allow"
		rec.ReasonCode = ""
	}
	rec.HighRisk = HighRiskReasons[dec.ReasonCode]
	if req.VerifiedCtx != nil {
		rec.Providers = providerList(req.VerifiedCtx["providers"])
	}
	p.Sink(rec)
}

// providerList splits the comma-joined provider list recorded by BuildContext.
func providerList(raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	for _, s := range strings.Split(raw, ",") {
		if strings.TrimSpace(s) != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}

// tokenRefFromReq reconstructs the audit-safe token reference from verified
// context facts (never the token text, AAC §13(1)).
func tokenRefFromReq(req *AuthorizationRequest) TokenAuditRef {
	ref := TokenAuditRef{}
	if req.VerifiedCtx == nil {
		return ref
	}
	ref.Issuer = req.VerifiedCtx["token_iss"]
	ref.Audience = req.VerifiedCtx["token_aud"]
	ref.Jti = req.VerifiedCtx["token_jti"]
	ref.DelegationID = req.VerifiedCtx["delegation_id"]
	return ref
}

// EvaluateObligations is a convenience evaluator runner for the PEP.
func EvaluateObligations(evaluators []ObligationEvaluator, obligations []Obligation) error {
	for _, eval := range evaluators {
		if eval == nil {
			continue
		}
		for _, o := range obligations {
			if err := eval(o); err != nil {
				return err
			}
		}
	}
	return nil
}
