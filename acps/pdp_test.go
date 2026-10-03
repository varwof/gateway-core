// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package acps

import (
	"errors"
	"strings"
	"testing"
)

func testRequest() *AuthorizationRequest {
	human := HumanSubject("https://idp.example.com/realm", "user-123")
	agent, _ := AgentSubject(partnerAIC)
	return &AuthorizationRequest{
		PrimarySubject: human,
		Actor: ActorContext{
			ImmediateActor: agent,
			ActorChain:     []string{human.SubjectID, agent.SubjectID},
			DelegationID:   "dlg-123",
		},
		Action: "acps.skill.invoke:data.export",
		Resource: AuthorizationResource{
			ResourceType: "skill",
			ResourceID:   "data.export",
			AgentAic:     aicSpecExample,
		},
		Environment: map[string]string{"ip": "10.0.0.1"},
		VerifiedCtx: map[string]string{
			"providers":     "mtls-aic,oauth2-token-exchange",
			"peer_aic":      aicSpecExample,
			"delegation_id": "dlg-123",
			"token_iss":     "https://sts.example.com",
			"token_jti":     "jti-0001",
		},
	}
}

func allowAll(dec *AuthorizationDecision) PolicyFunc {
	return func(req *AuthorizationRequest) (*AuthorizationDecision, error) { return dec, nil }
}

func alwaysDenyPolicy(req *AuthorizationRequest) (*AuthorizationDecision, error) {
	return Deny(ReasonPolicyDenied), nil
}

func TestPDP_NilRequest(t *testing.T) {
	p := &PDP{Policy: allowAll(Allow())}
	dec := p.Decide(nil)
	if dec.Allowed || dec.ReasonCode != ReasonContextInvalid {
		t.Fatalf("nil request decision = %+v", dec)
	}
}

func TestPDP_NilPolicyFailsClosed(t *testing.T) {
	p := &PDP{} // no policy
	dec := p.Decide(testRequest())
	if dec.Allowed || dec.ReasonCode != ReasonPDPUnavailable {
		t.Fatalf("nil-policy decision = %+v", dec)
	}
}

func TestPDP_PolicyReturnsNilFailsClosed(t *testing.T) {
	p := &PDP{Policy: func(req *AuthorizationRequest) (*AuthorizationDecision, error) { return nil, nil }}
	if dec := p.Decide(testRequest()); dec.Allowed || dec.ReasonCode != ReasonPolicyDenied {
		t.Fatalf("nil-result decision = %+v", dec)
	}
}

func TestPDP_PolicyErrorFailsClosed(t *testing.T) {
	p := &PDP{Policy: func(req *AuthorizationRequest) (*AuthorizationDecision, error) {
		return nil, errors.New("policy backend down")
	}}
	if dec := p.Decide(testRequest()); dec.Allowed || dec.ReasonCode != ReasonPDPUnavailable {
		t.Fatalf("policy-error decision = %+v", dec)
	}
}

func TestPDP_AllowWithObligationsSatisfied(t *testing.T) {
	audit := []AuditRecord{}
	p := &PDP{
		Policy: allowAll(Allow(Obligation{ID: "data.use.audit"})),
		ObligationEvaluators: []ObligationEvaluator{
			func(o Obligation) error {
				if o.ID != "data.use.audit" {
					t.Fatalf("unexpected obligation %q", o.ID)
				}
				return nil
			},
		},
		Sink: func(r AuditRecord) { audit = append(audit, r) },
	}
	dec := p.Decide(testRequest())
	if !dec.Allowed {
		t.Fatalf("allow decision = %+v", dec)
	}
	if len(audit) != 1 {
		t.Fatalf("audit records = %d", len(audit))
	}
	rec := audit[0]
	if rec.Decision != "allow" || rec.ReasonCode != "" || rec.HighRisk {
		t.Fatalf("audit record = %+v", rec)
	}
	if rec.Action != "acps.skill.invoke:data.export" || rec.ImmediateActor != "agent:"+partnerAIC {
		t.Fatalf("audit record context = %+v", rec)
	}
	if len(rec.Providers) != 2 || rec.Token.Jti != "jti-0001" {
		t.Fatalf("audit providers=%v token=%+v", rec.Providers, rec.Token)
	}
}

func TestPDP_AllowObligationUnsatisfied(t *testing.T) {
	evals := []ObligationEvaluator{
		func(o Obligation) error { return errors.New("obligation transport unavailable") },
	}
	p := &PDP{Policy: allowAll(Allow(Obligation{ID: "data.use.log"})), ObligationEvaluators: evals}
	dec := p.Decide(testRequest())
	if dec.Allowed || dec.ReasonCode != ReasonObligationFailed {
		t.Fatalf("unsatisfied obligation decision = %+v", dec)
	}
}

func TestPDP_DenyAudit(t *testing.T) {
	audit := []AuditRecord{}
	p := &PDP{Policy: alwaysDenyPolicy, Sink: func(r AuditRecord) { audit = append(audit, r) }}
	dec := p.Decide(testRequest())
	if dec.Allowed || dec.ReasonCode != ReasonPolicyDenied {
		t.Fatalf("deny decision = %+v", dec)
	}
	if len(audit) != 1 || audit[0].Decision != "deny" || audit[0].ReasonCode != ReasonPolicyDenied {
		t.Fatalf("audit = %+v", audit)
	}
}

func TestPDP_ImpersonationDeniedByDefault(t *testing.T) {
	audit := []AuditRecord{}
	req := testRequest()
	req.VerifiedCtx["impersonation"] = "true"
	p := &PDP{Policy: allowAll(Allow()), Sink: func(r AuditRecord) { audit = append(audit, r) }}
	dec := p.Decide(req)
	if dec.Allowed || dec.ReasonCode != ReasonImpersonation {
		t.Fatalf("impersonation decision = %+v", dec)
	}
	if len(audit) != 1 || !audit[0].HighRisk {
		t.Fatalf("impersonation denial must be high-risk: %+v", audit)
	}
	if !strings.Contains(pdpReasonsSummary(dec), ReasonImpersonation) {
		t.Fatalf("unexpected reason summary %q", dec.ReasonCode)
	}
}

func TestPDP_ImpersonationAllowedWhenGated(t *testing.T) {
	p := &PDP{
		Policy:             allowAll(Allow()),
		AllowImpersonation: true,
	}
	req := testRequest()
	req.VerifiedCtx["impersonation"] = "true"
	if dec := p.Decide(req); !dec.Allowed {
		t.Fatalf("gated impersonation decision = %+v", dec)
	}
}

func TestPDP_NoSinkSilent(t *testing.T) {
	p := &PDP{Policy: alwaysDenyPolicy}
	if dec := p.Decide(testRequest()); dec == nil || dec.Allowed {
		t.Fatal("decision should still be produced without a sink")
	}
}

func pdpReasonsSummary(dec *AuthorizationDecision) string { return dec.ReasonCode }
