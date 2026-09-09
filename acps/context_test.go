// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package acps

import (
	"errors"
	"testing"
)

func TestSubjectBuilders(t *testing.T) {
	h := HumanSubject("https://idp.example.com/realm", "user-123")
	if h.SubjectID != "human:https://idp.example.com/realm#user-123" || h.Key() != h.SubjectID {
		t.Fatalf("HumanSubject = %q", h.SubjectID)
	}
	a, err := AgentSubject(aicSpecExample)
	if err != nil {
		t.Fatal(err)
	}
	if a.SubjectID != "agent:"+aicSpecExample {
		t.Fatalf("AgentSubject = %q", a.SubjectID)
	}
	if _, err := AgentSubject("not-a-real-aic"); !errors.Is(err, ErrInvalidAIC) {
		t.Fatalf("AgentSubject(invalid) err = %v", err)
	}
	s := ServiceSubject("https://issuer.example.com", "client-1")
	if s.SubjectID != "service:https://issuer.example.com#client-1" {
		t.Fatalf("ServiceSubject = %q", s.SubjectID)
	}
	r := RelatedSubject(RelatedTenant, "t-1")
	if r.SubjectID != "tenant:t-1" {
		t.Fatalf("RelatedSubject = %q", r.SubjectID)
	}
}

func TestParseSubjectID(t *testing.T) {
	kind, id, ok := ParseSubjectID("agent:" + aicSpecExample)
	if !ok || kind != "agent" || id != aicSpecExample {
		t.Fatalf("ParseSubjectID = (%q,%q,%v)", kind, id, ok)
	}
	if _, _, ok := ParseSubjectID("nocolon"); ok {
		t.Fatal("expected no-colon subject to fail parsing")
	}
}

func TestAuthorizationEvent_VerifiedFlag(t *testing.T) {
	provEvidence := NewVerifiedAuthorizationEvent("sts.example.com", AuthorizationEvent{Type: "human_consent"})
	if !provEvidence.Verified() || provEvidence.Source != "sts.example.com" {
		t.Fatalf("provider event not marked verified: %+v", provEvidence)
	}
	if (AuthorizationEvent{Type: "human_consent"}).Verified() {
		t.Fatal("payload-asserted event must not look verified")
	}
}

func TestMTLSProvider_Verify(t *testing.T) {
	p := &MTLSProvider{}
	cert := testPeerCert(t, aicSpecExample, []string{"acps://" + aicSpecExample})
	res, err := p.Verify(cert)
	if err != nil {
		t.Fatal(err)
	}
	if res.Provider != "mtls-aic" {
		t.Fatalf("provider = %q", res.Provider)
	}
	if res.PrimarySubject.SubjectID != "agent:"+aicSpecExample ||
		res.ImmediateActor.SubjectID != "agent:"+aicSpecExample {
		t.Fatalf("primary=%q immediate=%q", res.PrimarySubject.SubjectID, res.ImmediateActor.SubjectID)
	}
	if len(res.ActorChain) != 1 || res.ActorChain[0] != "agent:"+aicSpecExample {
		t.Fatalf("chain = %v", res.ActorChain)
	}
	if res.VerifiedContext["peer_aic"] != aicSpecExample {
		t.Fatalf("peer_aic = %q", res.VerifiedContext["peer_aic"])
	}
}

func TestMTLSProvider_Verify_NoIdentity(t *testing.T) {
	p := &MTLSProvider{}
	cert := testPeerCert(t, "", nil)
	_, err := p.Verify(cert)
	if !errors.Is(err, ErrMissingPeerIdentity) && !errors.Is(err, ErrInvalidAIC) {
		var aacErr *AACError
		if !errors.As(err, &aacErr) {
			t.Fatalf("expected AuthenticationRequiredError, got %T %v", err, err)
		}
		if aacErr.Code != CodeAuthenticationRequired {
			t.Fatalf("code = %d, want %d", aacErr.Code, int(CodeAuthenticationRequired))
		}
	}
}

func TestMTLSProvider_Verify_RequireSAN(t *testing.T) {
	strict := &MTLSProvider{RequireSAN: true}
	if _, err := strict.Verify(testPeerCert(t, aicSpecExample, nil)); err == nil {
		t.Fatal("strict mode should require the SAN acps:// URI")
	}
	if _, err := strict.Verify(testPeerCert(t, aicSpecExample, []string{"acps://" + aicSpecExample})); err != nil {
		t.Fatalf("strict mode with SAN should pass: %v", err)
	}
}

func TestTokenProvider_Verify(t *testing.T) {
	rec := signedRecord(t, nil)
	presenter := testPeerCert(t, aicSpecExample, []string{"acps://" + aicSpecExample})
	p := &TokenProvider{PresenterCert: presenter}
	res, err := p.Verify(rec)
	if err != nil {
		t.Fatal(err)
	}
	if res.Provider != "oauth2-token-exchange" {
		t.Fatalf("provider = %q", res.Provider)
	}
	if res.ImmediateActor.SubjectID != "agent:"+partnerAIC {
		t.Fatalf("immediate = %q, want agent:%s", res.ImmediateActor.SubjectID, partnerAIC)
	}
	if res.PrimarySubject.SubjectType != SubjectTypeHuman {
		t.Fatalf("primary type = %q", res.PrimarySubject.SubjectType)
	}
	if res.DelegationID != "dlg-123" || res.Boundary == nil {
		t.Fatalf("DelegationID=%q Boundary=%v", res.DelegationID, res.Boundary)
	}
	if len(res.ActorChain) != 2 || res.ActorChain[1] != "agent:"+partnerAIC {
		t.Fatalf("chain = %v", res.ActorChain)
	}
}

func TestTokenProvider_Verify_SelfClaimed(t *testing.T) {
	p := &TokenProvider{}
	claims := defaultClaims(t)
	if _, err := p.Verify(FromSelfClaimedPayload(claims)); err == nil {
		t.Fatal("self-claimed delegation must be rejected")
	}
}

func TestTokenProvider_Verify_WrongInputType(t *testing.T) {
	p := &TokenProvider{}
	if _, err := p.Verify("not-a-record"); err == nil {
		t.Fatal("wrong input type should error")
	}
}

func TestBuildContext_SingleMTLS(t *testing.T) {
	cert := testPeerCert(t, aicSpecExample, nil)
	res, err := BuildContext(BuildOptions{
		Providers: []ContextProvider{&MTLSProvider{}},
		Inputs:    []any{cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.ActorChain) != 1 || res.ActorChain[0] != "agent:"+aicSpecExample {
		t.Fatalf("chain = %v", res.ActorChain)
	}
	if res.PeerAIC != aicSpecExample {
		t.Fatalf("PeerAIC = %q", res.PeerAIC)
	}
}

func TestBuildContext_DelegationOverridesChain(t *testing.T) {
	// Peer identity (cert CN/SAN) must agree with the token's immediate actor
	// (act) — AAC §6.4(3) chain-tail invariant enforced by BuildContext.
	cert := testPeerCert(t, partnerAIC, []string{"acps://" + partnerAIC})
	rec := signedRecord(t, func(m map[string]any) {
		m["acps_target_aic"] = partnerAIC
		m["acps_allowed_partner_aics"] = []string{partnerAIC}
	})
	res, err := BuildContext(BuildOptions{
		Providers: []ContextProvider{&MTLSProvider{}, &TokenProvider{PresenterCert: cert}},
		Inputs:    []any{cert, rec},
	})
	if err != nil {
		t.Fatal(err)
	}
	// The Token Exchange provider owns the verified chain (human -> agent).
	if len(res.ActorChain) != 2 {
		t.Fatalf("chain = %v", res.ActorChain)
	}
	if res.ActorChain[len(res.ActorChain)-1] != "agent:"+partnerAIC {
		t.Fatalf("chain tail = %q, want agent:%s", res.ActorChain[1], partnerAIC)
	}
	if res.ImmediateActor.SubjectID != "agent:"+partnerAIC {
		t.Fatalf("immediate = %q", res.ImmediateActor.SubjectID)
	}
	if res.DelegationID != "dlg-123" {
		t.Fatalf("DelegationID = %q", res.DelegationID)
	}
	req := res.ToRequest()
	if req.VerifiedCtx["delegation_id"] != "dlg-123" || req.VerifiedCtx["peer_aic"] != partnerAIC {
		t.Fatalf("ToRequest VerifiedCtx = %v", req.VerifiedCtx)
	}
	if req.VerifiedCtx["providers"] != "mtls-aic,oauth2-token-exchange" {
		t.Fatalf("providers = %q", req.VerifiedCtx["providers"])
	}
}

type disagreeingProvider struct {
	label   string
	subject AuthorizationSubject
}

func (p disagreeingProvider) Name() string { return p.label }
func (p disagreeingProvider) Verify(any) (*ProviderResult, error) {
	return &ProviderResult{
		Provider:        p.label,
		ImmediateActor:  p.subject,
		PrimarySubject:  p.subject,
		ActorChain:      []string{p.subject.SubjectID},
		VerifiedContext: map[string]string{"peer_aic": p.subject.Attributes["aic"]},
	}, nil
}

func TestBuildContext_DisagreeingImmediateActor(t *testing.T) {
	a, _ := AgentSubject(aicSpecExample)
	b, _ := AgentSubject(partnerAIC)
	_, err := BuildContext(BuildOptions{
		Providers: []ContextProvider{
			disagreeingProvider{"a", a},
			disagreeingProvider{"b", b},
		},
		Inputs: []any{1, 2},
	})
	if !errors.Is(err, ErrContextInvalid) {
		t.Fatalf("err = %v, want ErrContextInvalid (providers disagree on immediate actor)", err)
	}
}

func TestBuildContext_UnverifiedEventRejected(t *testing.T) {
	// A provider result claiming an event without a verifier source must be
	// rejected by BuildContext (AAC §9.5).
	_, err := BuildContext(BuildOptions{
		Providers: []ContextProvider{attrProv{res: &ProviderResult{
			Provider: "event-prov",
			Events:   []AuthorizationEvent{{Type: "human_consent"}},
		}}},
		Inputs: []any{nil},
	})
	if !errors.Is(err, ErrContextInvalid) {
		t.Fatalf("err = %v, want ErrContextInvalid (unverified event)", err)
	}
}

func TestBuildContext_MismatchedInputs(t *testing.T) {
	_, err := BuildContext(BuildOptions{
		Providers: []ContextProvider{&MTLSProvider{}},
		Inputs:    []any{},
	})
	if !errors.Is(err, ErrContextInvalid) {
		t.Fatalf("err = %v, want ErrContextInvalid", err)
	}
}

func TestBuildContext_NoProviders(t *testing.T) {
	_, err := BuildContext(BuildOptions{})
	if err == nil {
		t.Fatal("empty provider list must fail (no verified actor)")
	}
}

// attrProv is a tiny provider that supplies a canned result (used to test
// event rejection without a real implementation).
type attrProv struct {
	t   *testing.T
	res *ProviderResult
}

func (p attrProv) Name() string { return "attr-prov" }
func (p attrProv) Verify(any) (*ProviderResult, error) {
	res := *p.res
	if res.ImmediateActor.SubjectID == "" {
		res.ImmediateActor, _ = AgentSubject(aicSpecExample)
	}
	if len(res.ActorChain) == 0 {
		res.ActorChain = []string{res.ImmediateActor.SubjectID}
	}
	return &res, nil
}
