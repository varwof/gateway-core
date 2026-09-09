// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package acps

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// defaultClaims returns a valid delegation-token claim set (AAC §10.2 all
// required fields present).
func defaultClaims(t *testing.T) map[string]any {
	t.Helper()
	now := time.Now().Unix()
	return map[string]any{
		"iss":                       "https://sts.example.com",
		"sub":                       "https://idp.example.com/realm#user-123",
		"aud":                       CanonicalAudience(aicSpecExample),
		"exp":                       now + 3600,
		"iat":                       now - 60,
		"jti":                       "jti-0001",
		"scope":                     "acps.skill.invoke:data.export",
		"act":                       "agent:" + partnerAIC,
		"acps_subject_type":         "human",
		"acps_delegation_id":        "dlg-123",
		"acps_delegation_mode":      DelegationModeDynamic,
		"acps_target_aic":           aicSpecExample,
		"acps_chain_depth":          1,
		"acps_max_chain_depth":      5,
		"acps_allowed_partner_aics": []string{aiC(2)},
	}
}

// aiC returns a structurally-valid helper AIC with a distinct arsp-level.
func aiC(n int) string {
	levels := strings.Split(aicSpecExample, ".")
	levels[5] = fmt.Sprintf("%d", n)
	return strings.Join(levels, ".")
}

// signedRecord builds a signed delegation record from (possibly mutated)
// claims.
func signedRecord(t *testing.T, mutate func(map[string]any)) *DelegationRecord {
	t.Helper()
	claims := defaultClaims(t)
	if mutate != nil {
		mutate(claims)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, sig, err := SignRecord(payload, priv)
	if err != nil {
		t.Fatal(err)
	}
	return NewSignedDelegation(FromTokenClaims(claims), payload, sig, pub)
}

func TestDelegation_Validate_SignedAndBound(t *testing.T) {
	rec := signedRecord(t, nil)
	presenter := testPeerCert(t, aicSpecExample, []string{"acps://" + aicSpecExample})
	if err := rec.Validate(presenter); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !rec.Verified || !rec.Bound {
		t.Fatalf("Verified=%v Bound=%v, want true/true", rec.Verified, rec.Bound)
	}
	if !rec.PresenterMatches(presenter) {
		t.Fatal("PresenterMatches = false")
	}
}

func TestDelegation_Validate_Unsigned(t *testing.T) {
	claims := defaultClaims(t)
	payload, _ := json.Marshal(claims)
	rec := NewSignedDelegation(FromTokenClaims(claims), payload, nil, nil)
	presenter := testPeerCert(t, aicSpecExample, nil)
	if err := rec.Validate(presenter); !errors.Is(err, ErrUnsignedDelegation) {
		t.Fatalf("Validate(unsigned) err = %v, want ErrUnsignedDelegation", err)
	}
}

func TestDelegation_Validate_TamperedSignature(t *testing.T) {
	rec := signedRecord(t, nil)
	sig := append([]byte(nil), rec.Signature...)
	sig[0] ^= 0xFF
	rec.Signature = sig
	presenter := testPeerCert(t, aicSpecExample, nil)
	if err := rec.Validate(presenter); !errors.Is(err, ErrUnsignedDelegation) {
		t.Fatalf("err = %v, want ErrUnsignedDelegation", err)
	}
}

func TestDelegation_Validate_Unbound(t *testing.T) {
	// Signed and structurally complete, but never bound to a presenter.
	rec := signedRecord(t, nil)
	if err := rec.Validate(nil); !errors.Is(err, ErrUnboundDelegation) {
		t.Fatalf("Validate(nil) err = %v, want ErrUnboundDelegation", err)
	}
}

func TestDelegation_Validate_SelfClaimedPayload(t *testing.T) {
	// AAC §14.5(6): an unsigned/unbound record reconstructed from the request
	// body. Only the payload itself claims the delegation.
	claims := defaultClaims(t)
	rec := FromSelfClaimedPayload(claims)
	if err := rec.Validate(nil); !errors.Is(err, ErrSelfClaimed) {
		t.Fatalf("Validate(self-claimed) err = %v, want ErrSelfClaimed", err)
	}
	if err := rec.VerifyDelegation(); !errors.Is(err, ErrSelfClaimed) {
		t.Fatalf("VerifyDelegation(self-claimed) err = %v, want ErrSelfClaimed", err)
	}
}

func TestDelegation_Validate_MissingRequiredClaim(t *testing.T) {
	rec := signedRecord(t, func(m map[string]any) { delete(m, "act") })
	presenter := testPeerCert(t, aicSpecExample, nil)
	err := rec.Validate(presenter)
	if !errors.Is(err, ErrMissingTokenClaims) {
		t.Fatalf("err = %v, want ErrMissingTokenClaims", err)
	}
	if !strings.Contains(err.Error(), "act") {
		t.Fatalf("error should name the missing claim: %v", err)
	}
}

func TestDelegation_Validate_Expired(t *testing.T) {
	rec := signedRecord(t, func(m map[string]any) {
		m["iat"] = time.Now().Unix() - 7200
		m["exp"] = time.Now().Unix() - 3600
	})
	presenter := testPeerCert(t, aicSpecExample, nil)
	if err := rec.Validate(presenter); err == nil {
		t.Fatal("expired token accepted")
	}
}

func TestDelegation_Validate_CNFBinding(t *testing.T) {
	presenter := testPeerCert(t, aicSpecExample, nil)
	spki, _ := x509.MarshalPKIXPublicKey(presenter.PublicKey)
	h := sha256.Sum256(spki)
	cnf := base64.RawURLEncoding.EncodeToString(h[:])

	match := signedRecord(t, func(m map[string]any) { m["cnf"] = cnf })
	if err := match.Validate(presenter); err != nil {
		t.Fatalf("cnf match should Validate: %v", err)
	}
	if !match.PresenterMatches(presenter) {
		t.Fatal("PresenterMatches = false after cnf binding")
	}

	wrong := signedRecord(t, func(m map[string]any) { m["cnf"] = "AAAA-bad-bad" })
	if err := wrong.Validate(presenter); !errors.Is(err, ErrUnboundDelegation) {
		t.Fatalf("cnf mismatch err = %v, want ErrUnboundDelegation", err)
	}
}

func TestDelegation_EffectiveActorChain(t *testing.T) {
	rec := signedRecord(t, nil)
	chain := rec.EffectiveActorChain()
	want := []string{"human:https://idp.example.com/realm#user-123", "agent:" + partnerAIC}
	if len(chain) != len(want) {
		t.Fatalf("chain = %v, want %v", chain, want)
	}
	for i := range want {
		if chain[i] != want[i] {
			t.Fatalf("chain[%d] = %q, want %q", i, chain[i], want[i])
		}
	}
}

func TestDelegation_EffectiveActorChain_SingleHopCollapse(t *testing.T) {
	rec := signedRecord(t, func(m map[string]any) {
		m["acps_subject_type"] = "agent"
		m["sub"] = partnerAIC
		m["act"] = "agent:" + partnerAIC
	})
	chain := rec.EffectiveActorChain()
	if len(chain) != 1 || chain[0] != "agent:"+partnerAIC {
		t.Fatalf("chain = %v, want [agent:%s]", chain, partnerAIC)
	}
}

func TestBoundaryState_ValidateNext_DynamicPartner(t *testing.T) {
	tok := tokenFromClaims(t, func(m map[string]any) {
		m["acps_delegation_mode"] = DelegationModeDynamic
		m["acps_allowed_partner_aics"] = []string{aiC(2), aiC(3)}
	})

	okNext := tokenWithTarget(t, aiC(2))
	if err := tok.Boundary().ValidateNext(okNext); err != nil {
		t.Fatalf("in-partner target should pass: %v", err)
	}
	badNext := tokenWithTarget(t, aiC(9))
	if err := tok.Boundary().ValidateNext(badNext); !errors.Is(err, ErrBoundaryViolation) {
		t.Fatalf("out-of-partner target err = %v, want ErrBoundaryViolation", err)
	}
}

func TestBoundaryState_ValidateNext_FixedRoute(t *testing.T) {
	tok := tokenFromClaims(t, func(m map[string]any) {
		m["acps_delegation_mode"] = DelegationModeFixed
		m["acps_allowed_route"] = []string{"agent:" + aiC(5), "agent:" + aiC(6)}
	})
	onRoute := tokenWithAct(t, "agent:"+aiC(6))
	if err := tok.Boundary().ValidateNext(onRoute); err != nil {
		t.Fatalf("on-route hop should pass: %v", err)
	}
	offRoute := tokenWithAct(t, "agent:"+aiC(7))
	if err := tok.Boundary().ValidateNext(offRoute); !errors.Is(err, ErrBoundaryViolation) {
		t.Fatalf("off-route hop err = %v, want ErrBoundaryViolation", err)
	}
}

func TestBoundaryState_ValidateNext_Depth(t *testing.T) {
	tok := tokenFromClaims(t, func(m map[string]any) {
		m["acps_max_chain_depth"] = 3
		m["acps_allowed_partner_aics"] = []string{aicSpecExample}
	})
	deep := tokenWithDepth(t, 4)
	if err := tok.Boundary().ValidateNext(deep); !errors.Is(err, ErrDepthExceeded) {
		t.Fatalf("deep hop err = %v, want ErrDepthExceeded", err)
	}
	ok := tokenWithDepth(t, 3)
	if err := tok.Boundary().ValidateNext(ok); err != nil {
		t.Fatalf("depth-3 hop should pass: %v", err)
	}
}

func TestBoundaryState_ValidateNext_AudienceAndScope(t *testing.T) {
	tok := tokenFromClaims(t, func(m map[string]any) {
		m["acps_target_aic"] = aicSpecExample
		m["acps_allowed_partner_aics"] = []string{aicSpecExample}
		m["scope"] = "acps.skill.invoke:data.export acps.skill.invoke:data.import"
	})
	// aud must stay the canonical audience of the target (AAC §6.7/§10.7).
	badAud := tokenWithTarget(t, aicSpecExample)
	badAud.Aud = "acps:agent:" + partnerAIC
	if err := tok.Boundary().ValidateNext(badAud); !errors.Is(err, ErrBoundaryViolation) {
		t.Fatalf("aud mismatch err = %v, want ErrBoundaryViolation", err)
	}
	// scope must not expand (AAC §14.1(2)).
	wider := tokenWithTarget(t, aicSpecExample)
	wider.Scope = "acps.skill.invoke:data.export acps.skill.invoke:data.import extra.scope"
	if err := tok.Boundary().ValidateNext(wider); !errors.Is(err, ErrBoundaryViolation) {
		t.Fatalf("scope expansion err = %v, want ErrBoundaryViolation", err)
	}
	// narrowed scope is fine.
	narrow := tokenWithTarget(t, aicSpecExample)
	narrow.Scope = "acps.skill.invoke:data.export"
	if err := tok.Boundary().ValidateNext(narrow); err != nil {
		t.Fatalf("narrowed scope should pass: %v", err)
	}
}

func TestScopeNarrowed(t *testing.T) {
	prev := ScopeTokens("a b")
	for next, want := range map[string]bool{
		"a":     true,
		"a b":   true,
		"":      true,
		"a b c": false,
		"b a c": false,
		"c":     false,
	} {
		if got := ScopeNarrowed(prev, ScopeTokens(next)); got != want {
			t.Fatalf("ScopeNarrowed(%q) = %v, want %v", next, got, want)
		}
	}
}

// helpers ---------------------------------------------------------------

func tokFromClaims(t *testing.T, mutate func(map[string]any)) (*DelegationToken, *DelegationRecord) {
	t.Helper()
	rec := signedRecord(t, mutate)
	return rec.Token, rec
}

func tokenFromClaims(t *testing.T, mutate func(map[string]any)) *DelegationToken {
	t.Helper()
	tok, _ := tokFromClaims(t, mutate)
	return tok
}

func tokenWithTarget(t *testing.T, aic string) *DelegationToken {
	_, rec := tokFromClaims(t, func(m map[string]any) { m["acps_target_aic"] = aic })
	return rec.Token
}

func tokenWithAct(t *testing.T, act string) *DelegationToken {
	_, rec := tokFromClaims(t, func(m map[string]any) { m["act"] = act })
	return rec.Token
}

func tokenWithDepth(t *testing.T, depth int) *DelegationToken {
	_, rec := tokFromClaims(t, func(m map[string]any) { m["acps_chain_depth"] = depth })
	return rec.Token
}
