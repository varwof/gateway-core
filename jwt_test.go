// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package gw

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	pki "github.com/varwof/types"
	"github.com/varwof/types/aicjwt"
)

// jwtTestCA builds a self-signed CA and returns it with its key.
func jwtTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "jwt-test-ca"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// jwtTestToken signs an AIC-JWT (authorized mode) under the given CA.
func jwtTestToken(t *testing.T, ca *x509.Certificate, key *ecdsa.PrivateKey, kid, agentID, realm, principalID string, caps []aicjwt.Capability) string {
	t.Helper()
	hb, err := json.Marshal(map[string]any{"alg": "ES256", "typ": aicjwt.TypOuter, "kid": kid})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	outer := aicjwt.OuterClaims{
		Iss: "test-issuer",
		Sub: agentID,
		Aud: []string{"test-aud"},
		Iat: now,
		Exp: now + 3600,
		Jti: "test-jti",
		Cnf: &aicjwt.Cnf{Jkt: "dGVzdA"},
		Aic: &aicjwt.AICClaims{
			Ver:            1,
			Principal:      aicjwt.Principal{Realm: realm, ID: principalID, KeyHash: "dGVzdA", HashAlg: "sha-256"},
			DelegationMode: aicjwt.ModeAuthorized,
			Capabilities:   caps,
		},
	}
	pb, err := json.Marshal(&outer)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := aicjwt.SignCompact(hb, pb, "ES256", key)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestJWTVerifier_Valid(t *testing.T) {
	caCert, caKey := jwtTestCA(t)
	kid, err := aicjwt.SPKIHash(caCert, "sha-256")
	if err != nil {
		t.Fatal(err)
	}

	verifier := NewJWTVerifier([]*x509.Certificate{caCert})
	tok := jwtTestToken(t, caCert, caKey, kid, "agent-a", "r", "principal-a", []aicjwt.Capability{
		{Scheme: "std/database-v1", ID: "SELECT:*"},
	})

	cert, outer, err := verifier.VerifyBearer(tok, time.Now())
	if err != nil {
		t.Fatalf("VerifyBearer: %v", err)
	}
	if cert == nil || outer == nil {
		t.Fatal("nil cert/outer on success")
	}
	// The synthesized certificate must carry the AIC extension.
	aic, err := ParseAIC(cert)
	if err != nil {
		t.Fatalf("ParseAIC(synthesized): %v", err)
	}
	if aic.AgentId != "agent-a" {
		t.Fatalf("agentId = %q, want agent-a", aic.AgentId)
	}
	if aic.PrincipalUid.Realm != "r" || aic.PrincipalUid.Identifier != "principal-a" {
		t.Fatalf("principalUid = %+v", aic.PrincipalUid)
	}
	if len(aic.Capabilities) != 1 || aic.Capabilities[0].CapabilityId != "SELECT:*" {
		t.Fatalf("capabilities = %+v", aic.Capabilities)
	}
	if aic.DelegationMode != pki.DelegationAuthorized {
		t.Fatalf("delegationMode = %v", aic.DelegationMode)
	}
}

func TestJWTVerifier_UnknownKid(t *testing.T) {
	caCert, caKey := jwtTestCA(t)
	otherCA, _ := jwtTestCA(t)
	verifier := NewJWTVerifier([]*x509.Certificate{otherCA})
	kid, _ := aicjwt.SPKIHash(caCert, "sha-256")

	tok := jwtTestToken(t, caCert, caKey, kid, "agent-a", "r", "principal-a", nil)
	if _, _, err := verifier.VerifyBearer(tok, time.Now()); err == nil {
		t.Fatal("token signed by untrusted CA must be rejected")
	}
}

func TestJWTVerifier_Tampered(t *testing.T) {
	caCert, caKey := jwtTestCA(t)
	kid, _ := aicjwt.SPKIHash(caCert, "sha-256")
	verifier := NewJWTVerifier([]*x509.Certificate{caCert})

	tok := jwtTestToken(t, caCert, caKey, kid, "agent-a", "r", "principal-a", nil)
	tampered := tok[:len(tok)-4] + "AAAA"
	if _, _, err := verifier.VerifyBearer(tampered, time.Now()); err == nil {
		t.Fatal("tampered token must be rejected")
	}
}

func TestJWTVerifier_Expired(t *testing.T) {
	caCert, caKey := jwtTestCA(t)
	kid, _ := aicjwt.SPKIHash(caCert, "sha-256")
	verifier := NewJWTVerifier([]*x509.Certificate{caCert})

	tok := jwtTestToken(t, caCert, caKey, kid, "agent-a", "r", "principal-a", nil)
	if _, _, err := verifier.VerifyBearer(tok, time.Now().Add(2*time.Hour)); err == nil {
		t.Fatal("expired token must be rejected")
	}
}

// TestJWTVerifier_IssuerAudienceBinding (finding 5): a verifier configured with
// an expected issuer/audience rejects tokens that do not match.
func TestJWTVerifier_IssuerAudienceBinding(t *testing.T) {
	caCert, caKey := jwtTestCA(t)
	kid, _ := aicjwt.SPKIHash(caCert, "sha-256")
	caps := []aicjwt.Capability{{Scheme: "std/database-v1", ID: "SELECT:*"}}
	tok := jwtTestToken(t, caCert, caKey, kid, "agent-a", "r", "principal-a", caps)

	verifier := NewJWTVerifier([]*x509.Certificate{caCert})
	verifier.SetBearerPolicy("test-issuer", []string{"test-aud"}, nil)
	if _, _, err := verifier.VerifyBearer(tok, time.Now()); err != nil {
		t.Fatalf("matching issuer/audience should verify: %v", err)
	}

	badIssuer := NewJWTVerifier([]*x509.Certificate{caCert})
	badIssuer.SetBearerPolicy("other-issuer", []string{"test-aud"}, nil)
	if _, _, err := badIssuer.VerifyBearer(tok, time.Now()); err == nil {
		t.Fatal("issuer confusion must be rejected")
	}

	badAud := NewJWTVerifier([]*x509.Certificate{caCert})
	badAud.SetBearerPolicy("test-issuer", []string{"other-aud"}, nil)
	if _, _, err := badAud.VerifyBearer(tok, time.Now()); err == nil {
		t.Fatal("audience confusion must be rejected")
	}
}

// TestJWTVerifier_ReplayProtection (finding 5): a bearer token with replay
// protection enabled cannot be used twice.
func TestJWTVerifier_ReplayProtection(t *testing.T) {
	caCert, caKey := jwtTestCA(t)
	kid, _ := aicjwt.SPKIHash(caCert, "sha-256")
	caps := []aicjwt.Capability{{Scheme: "std/database-v1", ID: "SELECT:*"}}
	tok := jwtTestToken(t, caCert, caKey, kid, "agent-a", "r", "principal-a", caps)

	store := NewReplayNonceStore(0, 0)
	verifier := NewJWTVerifier([]*x509.Certificate{caCert})
	verifier.SetBearerPolicy("test-issuer", []string{"test-aud"}, store)

	if _, _, err := verifier.VerifyBearer(tok, time.Now()); err != nil {
		t.Fatalf("first use should verify: %v", err)
	}
	if _, _, err := verifier.VerifyBearer(tok, time.Now()); err == nil {
		t.Fatal("replayed bearer token must be rejected")
	}
}

// TestJWTVerifier_ProofOfPossession (finding 5): a token whose cnf is bound to a
// different presenter key must be rejected when PresenterKey is supplied.
func TestJWTVerifier_ProofOfPossession(t *testing.T) {
	caCert, caKey := jwtTestCA(t)
	kid, _ := aicjwt.SPKIHash(caCert, "sha-256")
	verifier := NewJWTVerifier([]*x509.Certificate{caCert})

	// Token without a cnf claim (helper sets Cnf to a static jkt) must be
	// rejected once a presenter key is required.
	caps := []aicjwt.Capability{{Scheme: "std/database-v1", ID: "SELECT:*"}}
	tok := jwtTestToken(t, caCert, caKey, kid, "agent-a", "r", "principal-a", caps)

	// Build a real present-key binding so a correct presenter passes.
	presenterKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jkt, err := aicjwt.KeyHashOf(&presenterKey.PublicKey, "jkt")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	hb, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": aicjwt.TypOuter, "kid": kid})
	outer := aicjwt.OuterClaims{
		Iss: "test-issuer",
		Sub: "agent-a",
		Aud: []string{"test-aud"},
		Iat: now,
		Exp: now + 3600,
		Jti: "jti-pop",
		Cnf: &aicjwt.Cnf{Jkt: jkt},
		Aic: &aicjwt.AICClaims{
			Ver:            1,
			Principal:      aicjwt.Principal{Realm: "r", ID: "principal-a", KeyHash: "dGVzdA", HashAlg: "sha-256"},
			DelegationMode: aicjwt.ModeAuthorized,
			Capabilities:   caps,
		},
	}
	pb, _ := json.Marshal(&outer)
	boundTok, err := aicjwt.SignCompact(hb, pb, "ES256", caKey)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := verifier.VerifyBearer(boundTok, time.Now(), JWTVerifyOptions{PresenterKey: &presenterKey.PublicKey}); err != nil {
		t.Fatalf("matching presenter should verify: %v", err)
	}
	// Static-jkt token presented with a real key must fail POP.
	if _, _, err := verifier.VerifyBearer(tok, time.Now(), JWTVerifyOptions{PresenterKey: &presenterKey.PublicKey}); err == nil {
		t.Fatal("token not bound to the presented key must be rejected")
	}
}
