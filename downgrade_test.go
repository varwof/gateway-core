package gw

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// TestPrincipalDowngradeRevokesAgentPermissions reproduces the
// real-world downgrade scenario:
//
//	zhangsan's key pair K issues principal cert C1 (grants SELECT+INSERT);
//	his agent gets an AIC anchored to hash(SPKI K) with caps SELECT+INSERT.
//	Later zhangsan is downgraded: a NEW cert C2 for the SAME key pair K
//	carries fewer grants (SELECT only). The OLD agent AIC is still
//	cryptographically valid (same keyHash), but EffectiveCaps must drop
//	INSERT — the agent loses permission without reissuing the AIC.
func TestPrincipalDowngradeRevokesAgentPermissions(t *testing.T) {
	sel := Capability{SchemeId: "std/database-v1", CapabilityId: "query:SELECT"}
	ins := Capability{SchemeId: "std/database-v1", CapabilityId: "query:INSERT"}

	// Principal key pair K (unchanged across C1 -> C2).
	pkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&pkey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	kh := sha256.Sum256(spki)

	c1 := principalCertWithGrants(t, &pkey.PublicKey, []Capability{sel, ins})
	c2 := principalCertWithGrants(t, &pkey.PublicKey, []Capability{sel})

	agentCert := agentAICCert(t, kh[:], []Capability{sel, ins})

	// Before downgrade (C1): both capabilities effective.
	r1 := CheckAdmission(agentCert, AdmissionConfig{UserCert: c1})
	if !hasCapability(r1.EffectiveCaps, ins) {
		t.Fatalf("INSERT should be effective with C1, got %v", r1.EffectiveCaps)
	}
	if !hasCapability(r1.EffectiveCaps, sel) {
		t.Fatalf("SELECT should be effective with C1, got %v", r1.EffectiveCaps)
	}

	// After downgrade (C2, same key pair): the old AIC still validates
	// (keyHash unchanged) but INSERT is dropped from the intersection.
	r2 := CheckAdmission(agentCert, AdmissionConfig{UserCert: c2})
	if r2.Decision == DecisionDeny {
		t.Fatalf("AIC should remain valid after downgrade: %s", r2.Reason)
	}
	if hasCapability(r2.EffectiveCaps, ins) {
		t.Fatalf("INSERT must be dropped after downgrade, got %v", r2.EffectiveCaps)
	}
	if !hasCapability(r2.EffectiveCaps, sel) {
		t.Fatalf("SELECT should remain after downgrade, got %v", r2.EffectiveCaps)
	}
}

func principalCertWithGrants(t *testing.T, pub *ecdsa.PublicKey, grants []Capability) *x509.Certificate {
	t.Helper()
	val, err := asn1.Marshal(PrincipalAuthorization{
		Grants:           grants,
		DelegationPolicy: DelegationPolicy{AllowedMode: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "zhangsan"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(2 * time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: oidUserPermission, Value: val},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func agentAICCert(t *testing.T, keyHash []byte, caps []Capability) *x509.Certificate {
	t.Helper()
	aic := AIC{
		AgentId: "agent-zhangsan",
		PrincipalUid: PrincipalUid{
			KeyHash:    keyHash,
			Version:    1,
			Realm:      "corp.com",
			Identifier: "zhangsan",
		},
		Capabilities:   caps,
		DelegationMode: DelegationRepresentative,
		DelegationAuthorization: DelegationAuthorization{
			Reason:             Reason{ReasonCode: "TEST", Description: "downgrade scenario"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
	val, err := asn1.Marshal(aic)
	if err != nil {
		t.Fatal(err)
	}
	return makeCertWithExt(t, oidAIC, val)
}

func hasCapability(caps []Capability, want Capability) bool {
	for _, c := range caps {
		if c.SchemeId == want.SchemeId && c.CapabilityId == want.CapabilityId {
			return true
		}
	}
	return false
}
