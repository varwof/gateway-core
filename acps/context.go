// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Trusted authorization context (AAC §6) and context providers (AAC §7).
//
// Context providers prove what is true; the PDP decides what is allowed; the
// PEP makes it happen. This file builds the VerifiedAuthorizationContext out of
// provider-verified claims only — anything self-asserted in an unprotected
// request payload is rejected here (§14.5), not merely discounted.
package acps

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"
)

// Subject types (AAC §6.1).
const (
	SubjectTypeHuman   = "human"
	SubjectTypeAgent   = "agent"
	SubjectTypeService = "service"
	SubjectTypeRelated = "related"
	SubjectTypeUnknown = "unknown"
)

// Related subject types usable for authorities/owners (AAC §6.1).
const (
	RelatedOrg    = "org"
	RelatedTenant = "tenant"
)

// AuthorizationSubject is the normalized subject a policy reasons about
// (AAC §6.1/§6.6). SubjectID uses the canonical forms
// `human:{issuer}#{sub}` / `agent:{aic}` / `service:{issuer}#{client_id}`.
type AuthorizationSubject struct {
	SubjectID   string
	SubjectType string
	Roles       []string
	Scopes      []string
	Attributes  map[string]string
}

// Key implements comparator-friendly identity (agreement checks).
func (s AuthorizationSubject) Key() string { return s.SubjectID }

// String renders the subject as its canonical subject ID.
func (s AuthorizationSubject) String() string { return s.SubjectID }

// HumanSubject builds `human:{issuer}#{sub}` (AAC §6.1). sub is only unique
// within the issuer, so the issuer is mandatory.
func HumanSubject(issuer, sub string) AuthorizationSubject {
	return AuthorizationSubject{
		SubjectID:   "human:" + issuer + "#" + sub,
		SubjectType: SubjectTypeHuman,
		Attributes:  map[string]string{"issuer": issuer, "sub": sub},
	}
}

// AgentSubject builds `agent:{aic}` after validating the AIC (AAC §6.1; the
// AIC must be a structurally valid code).
func AgentSubject(aic string) (AuthorizationSubject, error) {
	if _, err := ParseAIC(aic); err != nil {
		return AuthorizationSubject{}, err
	}
	norm := NormalizeAICText(aic)
	return AuthorizationSubject{
		SubjectID:   "agent:" + norm,
		SubjectType: SubjectTypeAgent,
		Attributes:  map[string]string{"aic": norm},
	}, nil
}

// ServiceSubject builds `service:{issuer}#{client_id}` for OAuth clients and
// service accounts (AAC §6.1).
func ServiceSubject(issuer, clientID string) AuthorizationSubject {
	return AuthorizationSubject{
		SubjectID:   "service:" + issuer + "#" + clientID,
		SubjectType: SubjectTypeService,
		Attributes:  map[string]string{"issuer": issuer, "client_id": clientID},
	}
}

// RelatedSubject builds `org:{id}` / `tenant:{id}` style related subjects
// (associates, not executable principals, AAC §6.1).
func RelatedSubject(kind, id string) AuthorizationSubject {
	return AuthorizationSubject{
		SubjectID:   kind + ":" + id,
		SubjectType: SubjectTypeRelated,
		Attributes:  map[string]string{"kind": kind, "id": id},
	}
}

// ParseSubjectID parses a canonical subject ID back into its components.
func ParseSubjectID(s string) (kind string, id string, ok bool) {
	i := strings.IndexByte(s, ':')
	if i <= 0 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// AuthorizationEvent records a verified human consent / approval / break-glass
// event along the authorization chain (AAC §9.5). Events enter the context only
// through providers (Token Exchange / STS / signed approval); a payload-asserted
// "someone consented" claim is rejected (AAC §9.5, §14.5).
type AuthorizationEvent struct {
	Type    string // human_consent | human_approval | mfa | org_authz | break_glass
	Subject string // subject the event is about
	Purpose string
	Scope   []string
	At      time.Time
	Issuer  string
	// Source names the verifying provider (set via NewVerifiedAuthorizationEvent).
	Source string
}

// NewVerifiedAuthorizationEvent constructs an event that a provider has
// verified (carries the verifying provider name). Used exclusively by context
// providers; request payloads cannot fabricate a Source here.
func NewVerifiedAuthorizationEvent(source string, e AuthorizationEvent) AuthorizationEvent {
	e.Source = source
	return e
}

// Verified reports whether the event carries a verifier identity.
func (e AuthorizationEvent) Verified() bool { return e.Source != "" }

// AuthorizationResource is the resource being acted on (AAC §6.6).
type AuthorizationResource struct {
	ResourceType string
	ResourceID   string
	OwnerSubject string // e.g. org:{org_id} / tenant:{tenant_id}
	AgentAic     string // the target resource agent's AIC (acps_target_aic)
	SkillId      string
	TenantId     string
	Attributes   map[string]string
}

// ActorContext carries the immediate caller and the verified delegation path
// (AAC §6.3/§6.4/§6.6).
type ActorContext struct {
	ImmediateActor AuthorizationSubject
	ActorChain     []string // canonical subject IDs, origin → immediate
	DelegationID   string
	Events         []AuthorizationEvent
	ClientActor    *AuthorizationSubject // browser/CLI/service OAuth client, never overrides immediate
}

// AuthorizationRequest is the normalized input to the PDP (AAC §6.6). PEP
// builds it from the VerifiedAuthorizationContext; PDP must not parse raw
// payloads or tokens.
type AuthorizationRequest struct {
	PrimarySubject AuthorizationSubject
	Actor          ActorContext
	Action         string
	Resource       AuthorizationResource
	Environment    map[string]string
	VerifiedCtx    map[string]string // pointers to verified context facts for the policy
}

// VerifiedAuthorizationContext is the result of putting together all verified
// context sources (AAC §6 concept; provider results §7).
type VerifiedAuthorizationContext struct {
	PrimarySubject      AuthorizationSubject
	ImmediateActor      AuthorizationSubject
	ActorChain          []string
	DelegationID        string
	AuthorizationEvents []AuthorizationEvent
	Resource            AuthorizationResource
	Action              string
	Environment         map[string]string
	ClientActor         *AuthorizationSubject
	Providers           []string
	Boundary            *BoundaryState
	PeerAIC             string
}

// ToRequest lowers the verified context into the PDP input shape.
func (c *VerifiedAuthorizationContext) ToRequest() *AuthorizationRequest {
	req := &AuthorizationRequest{
		PrimarySubject: c.PrimarySubject,
		Actor: ActorContext{
			ImmediateActor: c.ImmediateActor,
			ActorChain:     append([]string(nil), c.ActorChain...),
			DelegationID:   c.DelegationID,
			Events:         c.AuthorizationEvents,
			ClientActor:    c.ClientActor,
		},
		Action:      c.Action,
		Resource:    c.Resource,
		Environment: c.Environment,
		VerifiedCtx: map[string]string{
			"peer_aic":      c.PeerAIC,
			"providers":     strings.Join(c.Providers, ","),
			"delegation_id": c.DelegationID,
		},
	}
	return req
}

// ContextProvider proves a fact about identity (AAC §7). Results are claims
// already verified by the provider; downstream code trusts only these.
type ContextProvider interface {
	Name() string
	Verify(input any) (*ProviderResult, error)
}

// ProviderResult is the verified output of one context provider.
type ProviderResult struct {
	Provider        string
	ImmediateActor  AuthorizationSubject
	PrimarySubject  AuthorizationSubject
	ActorChain      []string
	DelegationID    string
	Events          []AuthorizationEvent
	Boundary        *BoundaryState
	VerifiedContext map[string]string
}

// MTLSProvider derives the peer identity from the mTLS client certificate
// (AAC §7.1 / AIP §6.0): peer AIC comes from Subject CN + optional SAN
// acps:// URI, validated against the AIC grammar and (optionally) the ARSP
// checksum salt. Profile B items: primary == immediate == agent:{peer_aic}.
type MTLSProvider struct {
	// RequireSAN demands the supplementary SAN acps:// URI (AIP §6.0 strict).
	RequireSAN bool
	// Salt, when set, enables full AIC checksum verification.
	Salt []byte
}

// Name reports the provider identifier used in audit (AAC §13).
func (p *MTLSProvider) Name() string { return "mtls-aic" }

// Verify extracts and validates the peer AIC from the certificate and yields
// the single-hop agent context (AAC §9.2 Profile B).
func (p *MTLSProvider) Verify(input any) (*ProviderResult, error) {
	cert, ok := input.(*x509.Certificate)
	if !ok || cert == nil {
		return nil, ErrMissingPeerIdentity
	}
	rawAIC, err := ExtractPeerAIC(cert, p.RequireSAN)
	if err != nil {
		return nil, AuthenticationRequiredError(ReasonInvalidPeerIdentity, err)
	}
	verifyAIC, err := Verify(rawAIC, p.Salt)
	if err != nil {
		return nil, AuthenticationRequiredError(ReasonInvalidPeerIdentity, err)
	}
	subject, err := AgentSubject(verifyAIC.Code)
	if err != nil {
		return nil, AuthenticationRequiredError(ReasonInvalidPeerIdentity, err)
	}
	return &ProviderResult{
		Provider:       p.Name(),
		ImmediateActor: subject,
		PrimarySubject: subject,
		ActorChain:     []string{subject.SubjectID},
		VerifiedContext: map[string]string{
			"peer_aic": verifyAIC.Code,
		},
	}, nil
}

// TokenProvider proves delegation facts from an already crypto-verified
// delegation token (AAC §7.4/§10). Signature/expiry/aud verification happens
// upstream (gateway JWT verifier / aicjwt); this provider then enforces the
// AAC trust semantics: required claims (§10.2), binding (§14.2), actor-chain
// tail == immediate actor (§6.4), and the delegation boundary (§10.6/§10.7).
type TokenProvider struct {
	// PresenterCert is the mTLS peer certificate whose SPKI the token cnf
	// binding is checked against (AAC §14.2). When absent the record must be
	// bound through another verified means.
	PresenterCert *x509.Certificate
}

// Name reports the provider identifier used in audit (AAC §13).
func (p *TokenProvider) Name() string { return "oauth2-token-exchange" }

// Verify validates the delegation record and lowers it into provider claims.
func (p *TokenProvider) Verify(input any) (*ProviderResult, error) {
	rec, ok := input.(*DelegationRecord)
	if !ok || rec == nil {
		return nil, AccessTokenInvalidError(ReasonBadToken, nil)
	}
	var presenter *x509.Certificate
	if p != nil {
		presenter = p.PresenterCert
	}
	if err := rec.Validate(presenter); err != nil {
		return nil, AccessTokenInvalidError(ReasonBadToken, err)
	}
	tok := rec.Token
	if tok == nil {
		return nil, AccessTokenInvalidError(ReasonBadToken, ErrMissingTokenClaims)
	}
	primary, err := tokenSubject(tok)
	if err != nil {
		return nil, AccessTokenInvalidError(ReasonBadToken, err)
	}
	actor, err := agentSubjectFromAct(tok.Act)
	if err != nil {
		return nil, AccessTokenInvalidError(ReasonBadToken, err)
	}
	chain := rec.EffectiveActorChain()
	out := &ProviderResult{
		Provider:       p.Name(),
		ImmediateActor: actor,
		PrimarySubject: primary,
		ActorChain:     chain,
		DelegationID:   tok.DelegationID,
		Boundary:       rec.Boundary(),
		VerifiedContext: map[string]string{
			"token_iss":     tok.Iss,
			"token_aud":     tok.Aud,
			"token_jti":     tok.Jti,
			"delegation_id": tok.DelegationID,
		},
	}
	return out, nil
}

// tokenSubject derives the primary subject from the delegation token sub and
// acps_subject_type (AAC §10.2/§10.3).
func tokenSubject(tok *DelegationToken) (AuthorizationSubject, error) {
	switch tok.SubjectType {
	case SubjectTypeHuman:
		iss, sub := splitIssSub(tok.Sub)
		return HumanSubject(iss, sub), nil
	case SubjectTypeAgent:
		return AgentSubject(tok.Sub)
	case "", SubjectTypeService:
		iss, sub := splitIssSub(tok.Sub)
		return ServiceSubject(iss, sub), nil
	default:
		return AuthorizationSubject{}, errUnknownSubjectType{typ: tok.SubjectType}
	}
}

type errUnknownSubjectType struct{ typ string }

func (e errUnknownSubjectType) Error() string {
	return fmt.Sprintf("acps: unknown acps_subject_type %q", e.typ)
}

// splitIssSub splits `{issuer}#{sub}`; missing '#' keeps the whole string on
// the subject side.
func splitIssSub(s string) (iss, sub string) {
	i := strings.LastIndexByte(s, '#')
	if i < 0 {
		return "", s
	}
	return s[:i], s[i+1:]
}

// agentSubjectFromAct requires act to be an agent subject (the immediate actor
// on Agent->Agent hops, AIP binding).
func agentSubjectFromAct(act string) (AuthorizationSubject, error) {
	kind, id, ok := ParseSubjectID(act)
	if !ok || kind != SubjectTypeAgent {
		return AuthorizationSubject{}, fmt.Errorf("acps: act %q not an agent subject", act)
	}
	return AgentSubject(id)
}

// BuildOptions parametrize VerifiedAuthorizationContext construction.
type BuildOptions struct {
	Providers   []ContextProvider
	Inputs      []any
	Action      string
	Resource    AuthorizationResource
	Environment map[string]string
	ClientActor *AuthorizationSubject
}

// BuildContext assembles the trusted authorization context from verified
// provider results (AAC §4 step 3, §7). It enforces the invariant checks that
// keep the context trustworthy:
//
//   - every provider must verify (fail closed, §7.6/§5);
//   - exactly one immediate actor, no contradicted identities;
//   - actor_chain tail == immediate actor (§6.4(3));
//   - authorization events must carry a verifier (§9.5).
func BuildContext(opts BuildOptions) (*VerifiedAuthorizationContext, error) {
	if len(opts.Providers) != len(opts.Inputs) {
		return nil, ErrContextInvalid
	}
	var (
		immediate  *AuthorizationSubject
		primary    *AuthorizationSubject
		pdls       = map[string]string{}
		chain      []string
		delegID    string
		events     []AuthorizationEvent
		providers  []string
		boundary   *BoundaryState
		peerAIC    string
		delegChain []string
	)
	for i, prov := range opts.Providers {
		res, err := prov.Verify(opts.Inputs[i])
		if err != nil {
			return nil, fmt.Errorf("%w: provider %s: %v", ErrContextInvalid, prov.Name(), err)
		}
		providers = append(providers, res.Provider)
		if res.ImmediateActor.SubjectID != "" && res.PrimarySubject.SubjectID != "" {
			if immediate != nil && immediate.Key() != res.ImmediateActor.Key() {
				return nil, fmt.Errorf("%w: providers disagree on immediate actor (%s vs %s)",
					ErrContextInvalid, immediate.Key(), res.ImmediateActor.Key())
			}
			immediate = &res.ImmediateActor
			if primary == nil {
				primary = &res.PrimarySubject
			}
		}
		// A delegation provider (Token Exchange / STS) owns the verified
		// actor chain; the single-hop mTLS chain is the fallback.
		if res.DelegationID != "" && len(res.ActorChain) > 0 {
			delegID = res.DelegationID
			delegChain = res.ActorChain
		}
		if res.Boundary != nil {
			boundary = res.Boundary
		}
		for k, v := range res.VerifiedContext {
			if v != "" {
				pdls[k] = v
			}
		}
		for _, e := range res.Events {
			if !e.Verified() {
				return nil, fmt.Errorf("%w: provider %s emitted unverified event", ErrContextInvalid, res.Provider)
			}
			events = append(events, e)
		}
		if peerAIC == "" {
			peerAIC = res.VerifiedContext["peer_aic"]
		}
	}
	if immediate == nil {
		return nil, fmt.Errorf("%w: no verified immediate actor", ErrContextInvalid)
	}
	if primary == nil {
		primary = immediate
	}
	switch {
	case delegID != "":
		chain = delegChain
	case primary.SubjectID != "":
		chain = []string{primary.SubjectID, immediate.SubjectID}
	}
	// Deduplicate the single-hop case (primary == immediate).
	if len(chain) == 2 && chain[0] == chain[1] {
		chain = chain[:1]
	}
	if len(chain) > 0 {
		if chain[len(chain)-1] != immediate.Key() {
			return nil, fmt.Errorf("%w: chain tail %q != immediate %q",
				ErrChainTailMismatch, chain[len(chain)-1], immediate.Key())
		}
	}
	if len(chain) == 0 {
		chain = []string{immediate.SubjectID}
	}
	env := map[string]string{}
	for k, v := range opts.Environment {
		env[k] = v
	}
	for k, v := range pdls {
		if _, dup := env[k]; !dup {
			env[k] = v
		}
	}
	return &VerifiedAuthorizationContext{
		PrimarySubject:      *primary,
		ImmediateActor:      *immediate,
		ActorChain:          chain,
		DelegationID:        delegID,
		AuthorizationEvents: events,
		Resource:            opts.Resource,
		Action:              opts.Action,
		Environment:         env,
		ClientActor:         opts.ClientActor,
		Providers:           providers,
		Boundary:            boundary,
		PeerAIC:             peerAIC,
	}, nil
}

// immKey returns a stable chain seed for subjects (single-hop default).
func immKey(p *AuthorizationSubject) string {
	if p == nil {
		return ""
	}
	return p.SubjectID
}
