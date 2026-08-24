// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestCheckAdmission_NilCert(t *testing.T) {
	result := CheckAdmission(nil, AdmissionConfig{})
	if result.Decision != DecisionDeny {
		t.Fatalf("expected Deny for nil cert, got %v", result.Decision)
	}
	if result.Reason != "nil certificate" {
		t.Fatalf("expected 'nil certificate', got %s", result.Reason)
	}
}

func TestCheckAdmission_AllowNoAIC(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-ou", OrganizationalUnit: []string{"ops"}},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	result := CheckAdmission(cert, AdmissionConfig{})
	if result.Decision != DecisionAllow {
		t.Fatalf("expected Allow, got %v", result.Decision)
	}
	if result.PrincipalUid != "test-ou" {
		t.Fatalf("expected fallback principal test-ou, got %s", result.PrincipalUid)
	}
}

func TestCheckAdmission_RequireAIC(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "no-aic"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	result := CheckAdmission(cert, AdmissionConfig{RequireAIC: true})
	if result.Decision != DecisionDeny {
		t.Fatalf("expected Deny when RequireAIC, got %v", result.Decision)
	}
}

func TestCheckAdmission_RequireGatewaySession(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "no-gs"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	result := CheckAdmission(cert, AdmissionConfig{RequireGatewaySession: true})
	if result.Decision != DecisionDeny {
		t.Fatalf("expected Deny when RequireGatewaySession, got %v", result.Decision)
	}
}

func TestCheckAdmission_AICWithBasicInfo(t *testing.T) {
	aic := AIC{
		AgentId:      "agent-1",
		PrincipalUid: PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "admin@varwof.com"},
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
	val, _ := asn1.Marshal(aic)
	cert := makeCertWithExt(t, oidAIC, val)

	result := CheckAdmission(cert, AdmissionConfig{})
	if result.Decision != DecisionAllow {
		t.Fatalf("expected Allow, got %v", result.Decision)
	}
	if result.PrincipalUid != "varwof:admin@varwof.com:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
		t.Fatalf("expected varwof:admin@varwof.com:<keyhash>, got %s", result.PrincipalUid)
	}
}

func TestCheckAdmission_ProtocolCheck(t *testing.T) {
	aic := AIC{
		AgentId:      "agent-1",
		PrincipalUid: PrincipalUid{Version: 1, Realm: "varwof", Identifier: "agent-1", KeyHash: make([]byte, 32)},
		Capabilities: []Capability{
			{SchemeId: "http", CapabilityId: "gateway:read"},
		},
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
	val, _ := asn1.Marshal(aic)
	cert := makeCertWithExt(t, oidAIC, val)

	result := CheckAdmission(cert, AdmissionConfig{RequiredProtocol: "http"})
	if result.Decision != DecisionAllow {
		t.Fatalf("expected Allow for http protocol, got %v", result.Decision)
	}

	result2 := CheckAdmission(cert, AdmissionConfig{RequiredProtocol: "tcp"})
	if result2.Decision != DecisionDeny {
		t.Fatalf("expected Deny for missing tcp protocol, got %v", result2.Decision)
	}
}

func TestCheckAdmission_RuleIdCheck(t *testing.T) {
	aic := AIC{
		AgentId:      "agent-1",
		PrincipalUid: PrincipalUid{Version: 1, Realm: "varwof", Identifier: "agent-1", KeyHash: make([]byte, 32)},
		Capabilities: []Capability{
			{SchemeId: "http", CapabilityId: "gateway:admin"},
		},
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
	val, _ := asn1.Marshal(aic)
	cert := makeCertWithExt(t, oidAIC, val)

	// FullID semantics: RequiredRuleId uses full identifier scheme:capabilityId matching
	result := CheckAdmission(cert, AdmissionConfig{RequiredRuleId: "http:gateway:admin"})
	if result.Decision != DecisionAllow {
		t.Fatalf("expected Allow for http:gateway:admin, got %v", result.Decision)
	}

	result2 := CheckAdmission(cert, AdmissionConfig{RequiredRuleId: "http:gateway:audit"})
	if result2.Decision != DecisionDeny {
		t.Fatalf("expected Deny for missing http:gateway:audit, got %v", result2.Decision)
	}
}

func TestCheckAdmission_MalformedAIC(t *testing.T) {
	cert := makeCertWithExt(t, oidAIC, []byte{0xff, 0xff})
	result := CheckAdmission(cert, AdmissionConfig{})
	if result.Decision != DecisionDeny {
		t.Fatalf("expected Deny for malformed AIC, got %v", result.Decision)
	}
}

func TestCheckAdmission_RequiredCapabilities(t *testing.T) {
	aic := AIC{
		AgentId:      "agent-1",
		PrincipalUid: PrincipalUid{Version: 1, Realm: "varwof", Identifier: "agent-1", KeyHash: make([]byte, 32)},
		Capabilities: []Capability{
			{SchemeId: "http", CapabilityId: "gateway:read"},
			{SchemeId: "tcp", CapabilityId: "gateway:ops"},
		},
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
	val, _ := asn1.Marshal(aic)
	cert := makeCertWithExt(t, oidAIC, val)

	result := CheckAdmission(cert, AdmissionConfig{
		RequiredCapabilities: []string{"gateway:read", "gateway:ops"},
	})
	if result.Decision != DecisionAllow {
		t.Fatalf("expected Allow, got %v: %s", result.Decision, result.Reason)
	}

	result2 := CheckAdmission(cert, AdmissionConfig{
		RequiredCapabilities: []string{"gateway:read", "gateway:admin"},
	})
	if result2.Decision != DecisionDeny {
		t.Fatalf("expected Deny for missing capability, got %v", result2.Decision)
	}
	if result2.Reason != "missing capabilities: [gateway:admin]" {
		t.Fatalf("expected 'missing capabilities: [gateway:admin]', got %s", result2.Reason)
	}
}

func TestCheckAdmission_RequiredCapabilitiesWithSchemePrefix(t *testing.T) {
	aic := AIC{
		AgentId:      "agent-1",
		PrincipalUid: PrincipalUid{Version: 1, Realm: "varwof", Identifier: "agent-1", KeyHash: make([]byte, 32)},
		Capabilities: []Capability{
			{SchemeId: "varwof/demo-mysql-v1", CapabilityId: "SELECT:*"},
			{SchemeId: "varwof/demo-mysql-v1", CapabilityId: "INSERT:*"},
		},
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
	val, _ := asn1.Marshal(aic)
	cert := makeCertWithExt(t, oidAIC, val)

	// scheme-prefixed requirement must match aic.CapabilityId (SELECT:*)
	result := CheckAdmission(cert, AdmissionConfig{
		RequiredCapabilities: []string{"varwof/demo-mysql-v1:SELECT:*", "varwof/demo-mysql-v1:INSERT:*"},
	})
	if result.Decision != DecisionAllow {
		t.Fatalf("expected Allow for scheme-prefixed caps, got %v: %s", result.Decision, result.Reason)
	}

	// missing scheme-prefixed capability must be denied
	result2 := CheckAdmission(cert, AdmissionConfig{
		RequiredCapabilities: []string{"varwof/demo-mysql-v1:SELECT:*", "varwof/demo-mysql-v1:DELETE:*"},
	})
	if result2.Decision != DecisionDeny {
		t.Fatalf("expected Deny for missing scheme-prefixed cap, got %v", result2.Decision)
	}
	if result2.Reason != "missing capabilities: [varwof/demo-mysql-v1:DELETE:*]" {
		t.Fatalf("expected 'missing capabilities: [varwof/demo-mysql-v1:DELETE:*]', got %s", result2.Reason)
	}
}

func TestCheckAdmission_DisallowRepresentative(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Representative: AIC with DelegationMode=1
	aic := AIC{
		AgentId:        "agent-1",
		PrincipalUid:   PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "admin@varwof.com"},
		DelegationMode: DelegationRepresentative,
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
	aicVal, _ := asn1.Marshal(aic)
	up := PrincipalAuthorization{
		DelegationPolicy: DelegationPolicy{AllowedMode: 1},
	}
	upVal, _ := asn1.Marshal(up)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: oidAIC, Value: aicVal},
			{Id: oidUserPermission, Value: upVal},
		},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	result := CheckAdmission(cert, AdmissionConfig{DisallowRepresentative: true})
	if result.Decision != DecisionDeny {
		t.Fatalf("expected Deny for representative, got %v", result.Decision)
	}
	if result.Reason != "representative delegation mode not allowed by gateway policy" {
		t.Fatalf("expected 'representative delegation mode not allowed by gateway policy', got %s", result.Reason)
	}

	// Authorized mode should still pass
	aic2 := AIC{
		AgentId:      "agent-2",
		PrincipalUid: PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "user@varwof.com"},
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
	aicVal2, _ := asn1.Marshal(aic2)
	up2 := PrincipalAuthorization{
		DelegationPolicy: DelegationPolicy{AllowedMode: 0},
	}
	upVal2, _ := asn1.Marshal(up2)
	tmpl2 := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: oidAIC, Value: aicVal2},
			{Id: oidUserPermission, Value: upVal2},
		},
	}
	der2, _ := x509.CreateCertificate(rand.Reader, tmpl2, tmpl2, &key.PublicKey, key)
	cert2, _ := x509.ParseCertificate(der2)

	result2 := CheckAdmission(cert2, AdmissionConfig{DisallowRepresentative: true})
	if result2.Decision != DecisionAllow {
		t.Fatalf("expected Allow for authorized mode, got %v", result2.Decision)
	}

	// No UP at all should also pass (default authorized)
	aic3 := AIC{
		AgentId:      "agent-3",
		PrincipalUid: PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "user2@varwof.com"},
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
	aicVal3, _ := asn1.Marshal(aic3)
	cert3 := makeCertWithExt(t, oidAIC, aicVal3)

	result3 := CheckAdmission(cert3, AdmissionConfig{DisallowRepresentative: true})
	if result3.Decision != DecisionAllow {
		t.Fatalf("expected Allow when no UP, got %v", result3.Decision)
	}
}

func TestCheckAdmission_RequireUserPermission(t *testing.T) {
	aic := AIC{
		AgentId:      "agent-1",
		PrincipalUid: PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "user@varwof.com"},
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
	val, _ := asn1.Marshal(aic)
	cert := makeCertWithExt(t, oidAIC, val)

	result := CheckAdmission(cert, AdmissionConfig{RequireUserPermission: true})
	if result.Decision != DecisionDeny {
		t.Fatalf("expected Deny when RequireUserPermission without UP, got %v", result.Decision)
	}
	if result.Reason != "principal_authorization extension required" {
		t.Fatalf("expected 'principal_authorization extension required', got %s", result.Reason)
	}

	// With UserPermission extension should pass
	up := PrincipalAuthorization{
		Grants: []Capability{{CapabilityId: "gateway:read"}},
	}
	upVal, _ := asn1.Marshal(up)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: oidAIC, Value: val},
			{Id: oidUserPermission, Value: upVal},
		},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert2, _ := x509.ParseCertificate(der)

	result2 := CheckAdmission(cert2, AdmissionConfig{RequireUserPermission: true})
	if result2.Decision != DecisionAllow {
		t.Fatalf("expected Allow with UserPermission, got %v: %s", result2.Decision, result2.Reason)
	}
	if result2.PrincipalAuthorization == nil {
		t.Fatal("expected PrincipalAuthorization in result")
	}
	if len(result2.PrincipalAuthorization.Grants) != 1 || result2.PrincipalAuthorization.Grants[0].CapabilityId != "gateway:read" {
		t.Fatalf("Grants: expected [gateway:read], got %v", result2.PrincipalAuthorization.GrantIds())
	}
}

func TestCheckAdmission_PAOnlyNoAIC(t *testing.T) {
	// User cert without AIC directly carries PA grants (direct authorization scenario).
	pa := PrincipalAuthorization{
		Grants: []Capability{
			{SchemeId: "varwof/demo-mysql-v1", CapabilityId: "SELECT:*"},
			{SchemeId: "varwof/demo-mysql-v1", CapabilityId: "INSERT:*"},
		},
	}
	paVal, err := asn1.Marshal(pa)
	if err != nil {
		t.Fatal(err)
	}
	cert := makeCertWithExt(t, oidPrincipalAuthorization, paVal)

	// Basic admission allowed, PA is parsed, EffectiveCaps = full PA grants.
	res := CheckAdmission(cert, AdmissionConfig{})
	if res.Decision != DecisionAllow {
		t.Fatalf("expected Allow, got %v: %s", res.Decision, res.Reason)
	}
	if res.PrincipalAuthorization == nil {
		t.Fatal("expected PrincipalAuthorization parsed without AIC")
	}
	if len(res.EffectiveCaps) != 2 {
		t.Fatalf("ExpectedCaps: expected 2 PA grants, got %d: %v", len(res.EffectiveCaps), res.EffectiveCaps)
	}
	if res.EffectiveCaps[0].FullID() != "varwof/demo-mysql-v1:SELECT:*" {
		t.Fatalf("ExpectedCaps[0] = %s, want varwof/demo-mysql-v1:SELECT:*", res.EffectiveCaps[0].FullID())
	}

	// RequiredCapabilities hits PA grants -> allow.
	res2 := CheckAdmission(cert, AdmissionConfig{RequiredCapabilities: []string{"varwof/demo-mysql-v1:SELECT:*"}})
	if res2.Decision != DecisionAllow {
		t.Fatalf("expected Allow when required cap in PA grants, got %v: %s", res2.Decision, res2.Reason)
	}

	// RequiredCapabilities does not hit PA grants -> deny.
	res3 := CheckAdmission(cert, AdmissionConfig{RequiredCapabilities: []string{"varwof/demo-mysql-v1:DELETE:*"}})
	if res3.Decision != DecisionDeny {
		t.Fatal("expected Deny when required cap not in PA grants")
	}
}

func TestCheckAdmission_UserPermissionIntersection(t *testing.T) {
	aic := AIC{
		AgentId:        "agent-1",
		PrincipalUid:   PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "user@varwof.com"},
		DelegationMode: DelegationRepresentative,
		Capabilities: []Capability{
			{SchemeId: "http", CapabilityId: "gateway:read"},
			{SchemeId: "http", CapabilityId: "gateway:write"},
		},
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
	aicVal, _ := asn1.Marshal(aic)

	// UserPermission only grants "gateway:read" (subset)
	up := PrincipalAuthorization{
		DelegationPolicy: DelegationPolicy{AllowedMode: 1},
		Grants:           []Capability{{SchemeId: "http", CapabilityId: "gateway:read"}},
	}
	upVal, _ := asn1.Marshal(up)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: oidAIC, Value: aicVal},
			{Id: oidUserPermission, Value: upVal},
		},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	// Should allow with intersection
	result := CheckAdmission(cert, AdmissionConfig{RequireAIC: true, RequireUserPermission: true})
	if result.Decision != DecisionAllow {
		t.Fatalf("expected Allow with non-empty intersection, got %v: %s", result.Decision, result.Reason)
	}
	// EffectiveCaps only retains intersection hits (read), write is excluded by PA boundary
	ids := make([]string, 0, len(result.EffectiveCaps))
	for _, c := range result.EffectiveCaps {
		ids = append(ids, c.CapabilityId)
	}
	if len(ids) != 1 || ids[0] != "gateway:read" {
		t.Fatalf("EffectiveCaps = %v, want [gateway:read]", ids)
	}
}

func TestCheckAdmission_RejectOverflow(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	aic := AIC{
		AgentId:        "agent-overflow",
		PrincipalUid:   PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "user@varwof.com"},
		DelegationMode: DelegationRepresentative,
		Capabilities: []Capability{
			{SchemeId: "http", CapabilityId: "gateway:admin"},
			{SchemeId: "http", CapabilityId: "gateway:ops"},
		},
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
	aicVal, _ := asn1.Marshal(aic)
	up := PrincipalAuthorization{
		DelegationPolicy: DelegationPolicy{AllowedMode: 1},
		Grants:           []Capability{{SchemeId: "http", CapabilityId: "gateway:ops"}},
	}
	upVal, _ := asn1.Marshal(up)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: oidAIC, Value: aicVal},
			{Id: oidUserPermission, Value: upVal},
		},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	// Without RejectOverflow, intersection is non-empty so should pass
	result := CheckAdmission(cert, AdmissionConfig{
		RequireAIC: true, RequireUserPermission: true,
	})
	if result.Decision != DecisionAllow {
		t.Fatalf("expected Allow without RejectOverflow, got %v: %s", result.Decision, result.Reason)
	}

	// With RejectOverflow, aic has gateway:admin which UP doesn't authorize
	result2 := CheckAdmission(cert, AdmissionConfig{
		RequireAIC: true, RequireUserPermission: true, RejectOverflow: true,
	})
	if result2.Decision != DecisionDeny {
		t.Fatalf("expected Deny with RejectOverflow, got %v", result2.Decision)
	}
	if result2.Reason != "aic has capabilities not authorized by principal_authorization" {
		t.Fatalf("expected overflow reason, got %s", result2.Reason)
	}

	// When AIC doesn't have overflow (all caps in UP), should pass
	aic2 := AIC{
		AgentId:      "agent-exact",
		PrincipalUid: PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "user@varwof.com"},
		Capabilities: []Capability{
			{SchemeId: "http", CapabilityId: "gateway:ops"},
		},
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
	aicVal2, _ := asn1.Marshal(aic2)
	tmpl2 := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: oidAIC, Value: aicVal2},
			{Id: oidUserPermission, Value: upVal},
		},
	}
	der2, _ := x509.CreateCertificate(rand.Reader, tmpl2, tmpl2, &key.PublicKey, key)
	cert2, _ := x509.ParseCertificate(der2)

	result3 := CheckAdmission(cert2, AdmissionConfig{
		RequireAIC: true, RequireUserPermission: true, RejectOverflow: true,
	})
	if result3.Decision != DecisionAllow {
		t.Fatalf("expected Allow when no overflow, got %v: %s", result3.Decision, result3.Reason)
	}
}

func TestCheckAdmission_UserPermissionNoIntersection(t *testing.T) {
	aic := AIC{
		AgentId:        "agent-1",
		PrincipalUid:   PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "user@varwof.com"},
		DelegationMode: DelegationRepresentative,
		Capabilities: []Capability{
			{SchemeId: "http", CapabilityId: "gateway:admin"},
		},
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
	aicVal, _ := asn1.Marshal(aic)

	// UserPermission only grants "gateway:read" — disjoint
	up := PrincipalAuthorization{
		DelegationPolicy: DelegationPolicy{AllowedMode: 1},
		Grants:           []Capability{{SchemeId: "http", CapabilityId: "gateway:read"}},
	}
	upVal, _ := asn1.Marshal(up)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: oidAIC, Value: aicVal},
			{Id: oidUserPermission, Value: upVal},
		},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	// Should deny with empty intersection
	result := CheckAdmission(cert, AdmissionConfig{RequireAIC: true, RequireUserPermission: true})
	if result.Decision != DecisionDeny {
		t.Fatalf("expected Deny for empty intersection, got %v", result.Decision)
	}
	if result.Reason != "aic and principal_authorization capabilities have no intersection" {
		t.Fatalf("expected intersection deny reason, got %s", result.Reason)
	}
}

func TestAdmissionConfig_Validate(t *testing.T) {
	// No conflict
	noErr := (AdmissionConfig{RequireAIC: true}).Validate()
	if noErr != nil {
		t.Fatalf("unexpected error: %v", noErr)
	}

	// DisallowRepresentative without RequireAIC
	err := (AdmissionConfig{DisallowRepresentative: true}).Validate()
	if err == nil {
		t.Fatal("expected error for DisallowRepresentative without RequireAIC")
	}

	// RequireUserPermission without RequireAIC
	err2 := (AdmissionConfig{RequireUserPermission: true}).Validate()
	if err2 == nil {
		t.Fatal("expected error for RequireUserPermission without RequireAIC")
	}

	// Both valid
	err3 := (AdmissionConfig{RequireAIC: true, DisallowRepresentative: true}).Validate()
	if err3 != nil {
		t.Fatalf("unexpected error: %v", err3)
	}
}

func TestNeedRevoke(t *testing.T) {
	now := time.Now()
	if NeedRevoke(nil) {
		t.Fatal("nil cert should not need revoke")
	}

	expired := &x509.Certificate{NotAfter: now.Add(-1 * time.Hour)}
	if NeedRevoke(expired) {
		t.Fatal("expired cert should not need revoke")
	}

	valid := &x509.Certificate{NotAfter: now.Add(time.Hour)}
	if !NeedRevoke(valid) {
		t.Fatal("valid cert should need revoke")
	}
}

func TestHasDelegatedAgentOU(t *testing.T) {
	if hasDelegatedAgentOU(nil) {
		t.Fatal("nil cert should not have Delegated-Agent OU")
	}
	withOU := &x509.Certificate{
		Subject: pkix.Name{OrganizationalUnit: []string{"Delegated-Agent", "admin"}},
	}
	if !hasDelegatedAgentOU(withOU) {
		t.Fatal("expected Delegated-Agent OU to be found")
	}
	withoutOU := &x509.Certificate{
		Subject: pkix.Name{OrganizationalUnit: []string{"admin", "ops"}},
	}
	if hasDelegatedAgentOU(withoutOU) {
		t.Fatal("expected no Delegated-Agent OU")
	}
	emptyOU := &x509.Certificate{}
	if hasDelegatedAgentOU(emptyOU) {
		t.Fatal("expected no Delegated-Agent OU in empty cert")
	}
}

func TestCheckDelegatedAgentHeaders_NoAgentOU(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{OrganizationalUnit: []string{"admin"}},
	}
	r, _ := http.NewRequest("GET", "/", nil)
	if reason := CheckDelegatedAgentHeaders(cert, r); reason != "" {
		t.Fatalf("expected no reason for non-agent cert, got %s", reason)
	}
}

func TestCheckDelegatedAgentHeaders_MissingXAgentUser(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{OrganizationalUnit: []string{"Delegated-Agent", "admin"}},
	}
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("X-Agent-TTL", "2027-01-01T00:00:00Z")
	reason := CheckDelegatedAgentHeaders(cert, r)
	if reason == "" {
		t.Fatal("expected rejection for missing X-Agent-User")
	}
}

func TestCheckDelegatedAgentHeaders_MissingXAgentTTL(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{OrganizationalUnit: []string{"Delegated-Agent", "admin"}},
	}
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("X-Agent-User", "admin@test.com")
	reason := CheckDelegatedAgentHeaders(cert, r)
	if reason == "" {
		t.Fatal("expected rejection for missing X-Agent-TTL")
	}
}

func TestCheckDelegatedAgentHeaders_InvalidTTL(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{OrganizationalUnit: []string{"Delegated-Agent", "admin"}},
	}
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("X-Agent-User", "admin@test.com")
	r.Header.Set("X-Agent-TTL", "not-a-timestamp")
	reason := CheckDelegatedAgentHeaders(cert, r)
	if reason == "" {
		t.Fatal("expected rejection for invalid X-Agent-TTL")
	}
}

func TestCheckDelegatedAgentHeaders_ExpiredTTL(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{OrganizationalUnit: []string{"Delegated-Agent", "admin"}},
	}
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("X-Agent-User", "admin@test.com")
	r.Header.Set("X-Agent-TTL", "2020-01-01T00:00:00Z")
	reason := CheckDelegatedAgentHeaders(cert, r)
	if reason == "" {
		t.Fatal("expected rejection for expired X-Agent-TTL")
	}
}

func TestCheckDelegatedAgentHeaders_Valid(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{OrganizationalUnit: []string{"Delegated-Agent", "admin"}},
	}
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("X-Agent-User", "admin@test.com")
	r.Header.Set("X-Agent-TTL", "2030-01-01T00:00:00Z")
	reason := CheckDelegatedAgentHeaders(cert, r)
	if reason != "" {
		t.Fatalf("expected no rejection for valid headers, got %s", reason)
	}
}

func TestCheckDelegatedAgentHeaders_NilCert(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	if reason := CheckDelegatedAgentHeaders(nil, r); reason != "" {
		t.Fatalf("expected no reason for nil cert, got %s", reason)
	}
}

func TestOUFallbackPrincipal(t *testing.T) {
	if got := ouFallbackPrincipal(nil); got != "" {
		t.Fatalf("nil cert: expected '', got %s", got)
	}
	if got := ouFallbackPrincipal(&x509.Certificate{Subject: pkix.Name{CommonName: "cn-only"}}); got != "cn-only" {
		t.Fatalf("CN only: expected 'cn-only', got %s", got)
	}
	if got := ouFallbackPrincipal(&x509.Certificate{
		Subject: pkix.Name{OrganizationalUnit: []string{"ops-unit"}},
	}); got != "ops-unit" {
		t.Fatalf("OU only: expected 'ops-unit', got %s", got)
	}
	if got := ouFallbackPrincipal(&x509.Certificate{}); got != "" {
		t.Fatalf("empty subject: expected '', got %s", got)
	}
}

func TestCheckDelegatedAgentCert_NoAgentOU(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{OrganizationalUnit: []string{"admin"}},
	}
	if reason := CheckDelegatedAgentCert(cert, nil); reason != "" {
		t.Fatalf("expected no reason for non-agent cert, got %s", reason)
	}
}

func TestCheckDelegatedAgentCert_MissingGS(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{OrganizationalUnit: []string{"Delegated-Agent", "admin"}},
	}
	if reason := CheckDelegatedAgentCert(cert, nil); reason == "" {
		t.Fatal("expected rejection for Delegated-Agent without GS")
	}
}

func TestCheckDelegatedAgentCert_MissingHardTimeout(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{OrganizationalUnit: []string{"Delegated-Agent", "admin"}},
	}
	gs := &GatewaySessionExtension{MaxConcurrent: 1}
	if reason := CheckDelegatedAgentCert(cert, gs); reason == "" {
		t.Fatal("expected rejection for Delegated-Agent without hardTimeout")
	}
}

func TestCheckDelegatedAgentCert_Valid(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{OrganizationalUnit: []string{"Delegated-Agent", "admin"}},
	}
	gs := &GatewaySessionExtension{HardTimeout: 3600}
	if reason := CheckDelegatedAgentCert(cert, gs); reason != "" {
		t.Fatalf("expected no reason for valid Delegated-Agent, got %s", reason)
	}
}

func TestCheckDelegatedAgentCert_NilCert(t *testing.T) {
	if reason := CheckDelegatedAgentCert(nil, nil); reason != "" {
		t.Fatalf("expected no reason for nil cert, got %s", reason)
	}
}

func TestVerifyDelegationAuth_NilAIC(t *testing.T) {
	err := VerifyDelegationAuth(nil, &x509.Certificate{Raw: []byte("cert")})
	if err == nil {
		t.Fatal("expected error for nil AIC")
	}
}

func TestVerifyDelegationAuth_NilUserCert(t *testing.T) {
	aic := &AIC{DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"}, SignatureValue: []byte("sig")}}
	err := VerifyDelegationAuth(aic, nil)
	if err == nil {
		t.Fatal("expected error for nil user cert")
	}
}

func TestVerifyDelegationAuth_EmptySignature(t *testing.T) {
	aic := &AIC{DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"}}}
	err := VerifyDelegationAuth(aic, &x509.Certificate{Raw: []byte("cert")})
	if err == nil {
		t.Fatal("expected error for empty signature")
	}
}

func TestVerifyDelegationAuth_HashMismatch(t *testing.T) {
	userCert, userKey := mustGenerateTestCert(t)
	_ = userKey
	aic := &AIC{
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			SignatureValue:     []byte("sig"),
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
	err := VerifyDelegationAuth(aic, userCert)
	if err == nil {
		t.Fatal("expected error for hash mismatch")
	}
}

func mustGenerateTestCert(t *testing.T) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-user"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"test.example.com"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func TestVerifyDelegationAuth_ECDSA_Success(t *testing.T) {
	userCert, userKey := mustGenerateTestCert(t)
	ecKey, ok := userKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("key is not *ecdsa.PrivateKey")
	}
	aic := AIC{
		AgentId: "test-agent",
	}
	nonce := make([]byte, 32)
	tbs := DelegationAuthTBS{
		Reason:            Reason{ReasonCode: "TEST", Description: "test"},
		AgentId:           "test-agent",
		RequestedLifetime: 3600,
		Timestamp:         time.Now(),
		Nonce:             nonce,
	}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(tbsDER)
	sig, err := ecdsa.SignASN1(rand.Reader, ecKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	aic.DelegationAuthorization = DelegationAuthorization{
		Reason:             Reason{ReasonCode: "TEST", Description: "test"},
		RequestedLifetime:  3600,
		Timestamp:          time.Now(),
		Nonce:              nonce,
		SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		SignatureValue:     sig,
	}
	err = VerifyDelegationAuth(&aic, userCert)
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
}

func TestVerifyDelegationAuth_ECDSA_Expired(t *testing.T) {
	userCert, userKey := mustGenerateTestCert(t)
	ecKey, ok := userKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("key is not *ecdsa.PrivateKey")
	}
	ts := time.Now().Add(-2 * time.Hour)
	nonce := make([]byte, 32)
	tbs := DelegationAuthTBS{
		Reason:            Reason{ReasonCode: "TEST", Description: "test"},
		AgentId:           "test-agent",
		RequestedLifetime: 3600, // 1 hour
		Timestamp:         ts,
		Nonce:             nonce,
	}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(tbsDER)
	sig, err := ecdsa.SignASN1(rand.Reader, ecKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	aic := AIC{
		AgentId: "test-agent",
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			RequestedLifetime:  3600,
			Timestamp:          ts,
			Nonce:              nonce,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
			SignatureValue:     sig,
		},
	}
	// Gateway does not check Timestamp + Lifetime (only CA verifies at issuance), signature valid is sufficient
	err = VerifyDelegationAuth(&aic, userCert)
	if err != nil {
		t.Fatalf("expected success (gateway does not enforce lifetime), got: %v", err)
	}
}

func TestVerifyDelegationAuth_SPKIHashMismatch(t *testing.T) {
	userCert, userKey := mustGenerateTestCert(t)
	ecKey, ok := userKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("key is not *ecdsa.PrivateKey")
	}
	nonce := make([]byte, 32)
	tbs := DelegationAuthTBS{
		Reason:    Reason{ReasonCode: "TEST", Description: "test"},
		AgentId:   "test-agent",
		Timestamp: time.Now(),
		Nonce:     nonce,
	}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(tbsDER)
	sig, err := ecdsa.SignASN1(rand.Reader, ecKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	wrongHash := sha256.Sum256([]byte("wrong-key"))
	aic := AIC{
		AgentId: "test-agent",
		PrincipalUid: PrincipalUid{
			KeyHash: wrongHash[:],
		},
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Timestamp:          time.Now(),
			Nonce:              nonce,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
			SignatureValue:     sig,
		},
	}
	// Signature is correct, but PrincipalUid.KeyHash does not match userCert's SPKI -> should deny
	err = VerifyDelegationAuth(&aic, userCert)
	if err == nil {
		t.Fatal("expected SPKI hash mismatch error")
	}
}

func TestVerifyDelegationAuth_ECDSA_Failure(t *testing.T) {
	userCert, userKey := mustGenerateTestCert(t)
	ecKey, ok := userKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("key is not *ecdsa.PrivateKey")
	}
	aic := AIC{
		AgentId: "test-agent",
	}
	nonce := make([]byte, 32)
	tbs := DelegationAuthTBS{
		Reason:            Reason{ReasonCode: "TEST", Description: "test"},
		AgentId:           "test-agent",
		RequestedLifetime: 3600,
		Timestamp:         time.Now(),
		Nonce:             nonce,
	}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(tbsDER)
	sig, err := ecdsa.SignASN1(rand.Reader, ecKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	aic.DelegationAuthorization = DelegationAuthorization{
		Reason:             Reason{ReasonCode: "TEST", Description: "test"},
		RequestedLifetime:  3600,
		Timestamp:          time.Now(),
		Nonce:              nonce,
		SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		SignatureValue:     sig,
	}
	// Tamper with AIC content (causes TBS constructed during verification to differ from signing time)
	aic.AgentId = "tampered-agent"
	err = VerifyDelegationAuth(&aic, userCert)
	if err == nil {
		t.Fatal("expected error for tampered AIC")
	}
}

func makeCertWithSignedAIC(t *testing.T, aicMod func(*AIC)) (*x509.Certificate, *x509.Certificate) {
	t.Helper()
	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	aic := AIC{
		AgentId:      "agent-001",
		PrincipalUid: PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "user-001"},
		Capabilities: []Capability{
			{SchemeId: "svc", CapabilityId: "svc:read"},
		},
	}
	if aicMod != nil {
		aicMod(&aic)
	}

	// aicMod can preset DA.timestamp (for freshness testing); defaults to now if not set.
	daTS := aic.DelegationAuthorization.Timestamp
	if daTS.IsZero() {
		daTS = time.Now()
	}

	userCert, userKey := mustGenerateTestCert(t)
	// Backfill KeyHash with userCert's SPKI SHA-256, ensuring consistency with user cert
	// (SPKI cross-check requires hashAlgo(subject cert SPKI)==keyHash).
	spkiHash := sha256.Sum256(userCert.RawSubjectPublicKeyInfo)
	aic.PrincipalUid.KeyHash = spkiHash[:]
	nonce := make([]byte, 32)

	tbs := DelegationAuthTBS{
		Reason:            Reason{ReasonCode: "TEST", Description: "test"},
		Version:           aic.Version,
		AgentId:           aic.AgentId,
		PrincipalUid:      aic.PrincipalUid,
		Capabilities:      aic.Capabilities,
		DelegationMode:    aic.DelegationMode,
		RequestedLifetime: 3600,
		Timestamp:         daTS,
		Nonce:             nonce,
	}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(tbsDER)
	ecKey, ok := userKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("user key is not ECDSA")
	}
	sig, err := ecdsa.SignASN1(rand.Reader, ecKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	aic.DelegationAuthorization = DelegationAuthorization{
		SignatureValue:     sig,
		SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		Timestamp:          daTS,
		Nonce:              nonce,
		RequestedLifetime:  3600,
		Reason:             aic.DelegationAuthorization.Reason,
	}

	aicDER, err := asn1.Marshal(aic)
	if err != nil {
		t.Fatal(err)
	}

	agentTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "agent-001"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 1}, Value: aicDER},
		},
	}
	agentDER, err := x509.CreateCertificate(rand.Reader, agentTmpl, agentTmpl, &agentKey.PublicKey, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	agentCert, err := x509.ParseCertificate(agentDER)
	if err != nil {
		t.Fatal(err)
	}
	return agentCert, userCert
}

func TestCheckAdmission_RequireUserAuth_NoSignature(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	aic := AIC{AgentId: "no-sig"}
	aicDER, _ := asn1.Marshal(aic)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 1}, Value: aicDER},
		},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	result := CheckAdmission(cert, AdmissionConfig{
		RequireUserAuth: true,
	})
	if result.Decision != DecisionDeny {
		t.Fatalf("expected Deny for missing signature, got %v", result.Decision)
	}
}

func TestCheckAdmission_RequireUserAuth_NilProvider(t *testing.T) {
	agentCert, _ := makeCertWithSignedAIC(t, func(aic *AIC) {
		aic.DelegationAuthorization.Reason = Reason{ReasonCode: "TEST", Description: "test"}
	})
	result := CheckAdmission(agentCert, AdmissionConfig{
		RequireUserAuth: true,
	})
	if result.Decision != DecisionDeny {
		t.Fatalf("expected Deny for nil provider, got %v", result.Decision)
	}
	// G5: missing authorization certificate must explicitly fail-close, deny reason must be clear, not silent degradation.
	if !strings.Contains(result.Reason, "authorization certificate required") {
		t.Fatalf("expected explicit fail-close reason, got %q", result.Reason)
	}
}

// TestCheckAdmission_RequireUserAuth_SelfAuthAllow agent==user self-auth
// (cert SPKI == KeyHash): when authorization cert is missing, can verify DA signature
// using peer cert -> Allow.
func TestCheckAdmission_RequireUserAuth_SelfAuthAllow(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki := sha256.Sum256(mustSPKI(t, &key.PublicKey))
	nonce := make([]byte, 32)
	aic := AIC{
		AgentId: "self-agent",
		PrincipalUid: PrincipalUid{
			Version:    1,
			Realm:      "varwof",
			Identifier: "self@varwof.com",
			KeyHash:    spki[:],
			HashAlgo:   AlgorithmIdentifier{Algorithm: OIDSHA256},
		},
		Capabilities: []Capability{{SchemeId: "svc", CapabilityId: "svc:read"}},
	}
	// DA signed by agent's own private key (self-authorization).
	tbs := DelegationAuthTBS{
		Reason:            Reason{ReasonCode: "SELF", Description: "self-auth"},
		Version:           aic.Version,
		AgentId:           aic.AgentId,
		PrincipalUid:      aic.PrincipalUid,
		Capabilities:      aic.Capabilities,
		DelegationMode:    aic.DelegationMode,
		RequestedLifetime: 3600,
		Timestamp:         time.Now(),
		Nonce:             nonce,
	}
	tbsDER, _ := asn1.Marshal(tbs)
	digest := sha256.Sum256(tbsDER)
	sig, _ := ecdsa.SignASN1(rand.Reader, key, digest[:])
	aic.DelegationAuthorization = DelegationAuthorization{
		SignatureValue:     sig,
		SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		Timestamp:          time.Now(),
		Nonce:              nonce,
		RequestedLifetime:  3600,
		Reason:             Reason{ReasonCode: "SELF", Description: "self-auth"},
	}

	aicDER, _ := asn1.Marshal(aic)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 1}, Value: aicDER},
		},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	result := CheckAdmission(cert, AdmissionConfig{
		RequireUserAuth: true,
	})
	if result.Decision != DecisionAllow {
		t.Fatalf("agent==user self-auth should Allow, got %v (%s)", result.Decision, result.Reason)
	}
}

// mustSPKI returns the SubjectPublicKeyInfo DER encoding of a certificate.
func mustSPKI(t *testing.T, pub any) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// TestCheckAdmission_CheckDAAge_Allow CheckDAAge enabled and fresh timestamp -> Allow.
func TestCheckAdmission_CheckDAAge_Allow(t *testing.T) {
	agentCert, userCert := makeCertWithSignedAIC(t, func(aic *AIC) {
		aic.DelegationAuthorization.Reason = Reason{ReasonCode: "TEST", Description: "test"}
	})
	result := CheckAdmission(agentCert, AdmissionConfig{
		RequireUserAuth: true,
		UserCert:        userCert,
		CheckDAAge:      true,
	})
	if result.Decision != DecisionAllow {
		t.Fatalf("fresh DA timestamp should Allow, got %v (%s)", result.Decision, result.Reason)
	}
}

// TestCheckAdmission_CheckDAAge_Stale CheckDAAge enabled and stale timestamp -> Deny.
func TestCheckAdmission_CheckDAAge_Stale(t *testing.T) {
	stale := time.Now().Add(-10 * time.Minute)
	agentCert, userCert := makeCertWithSignedAIC(t, func(aic *AIC) {
		aic.DelegationAuthorization.Reason = Reason{ReasonCode: "TEST", Description: "test"}
		aic.DelegationAuthorization.Timestamp = stale
	})
	result := CheckAdmission(agentCert, AdmissionConfig{
		RequireUserAuth: true,
		UserCert:        userCert,
		CheckDAAge:      true,
	})
	if result.Decision != DecisionDeny {
		t.Fatalf("stale DA timestamp should Deny, got %v (%s)", result.Decision, result.Reason)
	}
	if !strings.Contains(result.Reason, "user_auth") {
		t.Fatalf("deny reason should mention user_auth, got %q", result.Reason)
	}
}

// TestCheckAdmission_CheckDAAge_Disabled CheckDAAge not enabled allows stale timestamp
// (default behavior, consistent with spec: lifetime validation is handled by NotAfter).
func TestCheckAdmission_CheckDAAge_Disabled(t *testing.T) {
	stale := time.Now().Add(-10 * time.Minute)
	agentCert, userCert := makeCertWithSignedAIC(t, func(aic *AIC) {
		aic.DelegationAuthorization.Reason = Reason{ReasonCode: "TEST", Description: "test"}
		aic.DelegationAuthorization.Timestamp = stale
	})
	result := CheckAdmission(agentCert, AdmissionConfig{
		RequireUserAuth: true,
		UserCert:        userCert,
		CheckDAAge:      false,
	})
	if result.Decision != DecisionAllow {
		t.Fatalf("CheckDAAge disabled should Allow stale ts, got %v (%s)", result.Decision, result.Reason)
	}
}

func TestVerifyDelegationAuth_UnsupportedKeyType(t *testing.T) {
	cert := &x509.Certificate{Raw: []byte("cert")}
	// Use Ed25519 as unsupported key type
	edKey := ed25519.PrivateKey(make([]byte, ed25519.SeedSize))
	_ = edKey
	aic := &AIC{
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			SignatureValue:     []byte("sig"),
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
	err := VerifyDelegationAuth(aic, cert)
	if err == nil {
		t.Fatal("expected error for unsupported key type (nil key)")
	}
}

func TestValidateCapSizeConstraints_Valid(t *testing.T) {
	caps := []Capability{
		{SchemeId: "http", CapabilityId: "gateway:read"},
		{SchemeId: "tcp", CapabilityId: "gateway:ops", Parameters: []byte{1, 2, 3}},
	}
	if err := validateCapSizeConstraints(caps); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateCapSizeConstraints_EmptySchemeID(t *testing.T) {
	caps := []Capability{
		{SchemeId: "", CapabilityId: "gateway:read"},
	}
	if err := validateCapSizeConstraints(caps); err == nil {
		t.Fatal("expected error for empty schemeId")
	}
}

func TestValidateCapSizeConstraints_SchemeIDTooLong(t *testing.T) {
	scheme := make([]byte, 129)
	for i := range scheme {
		scheme[i] = 'a'
	}
	caps := []Capability{
		{SchemeId: string(scheme), CapabilityId: "test"},
	}
	if err := validateCapSizeConstraints(caps); err == nil {
		t.Fatal("expected error for too long schemeId")
	}
}

func TestValidateCapSizeConstraints_ParametersTooLong(t *testing.T) {
	params := make([]byte, 4097)
	caps := []Capability{
		{SchemeId: "http", CapabilityId: "test", Parameters: params},
	}
	if err := validateCapSizeConstraints(caps); err == nil {
		t.Fatal("expected error for too long parameters")
	}
}

func TestCheckAdmission_CapSizeConstraint_Reject(t *testing.T) {
	caps := []Capability{
		{SchemeId: "", CapabilityId: "gateway:read"},
	}
	aic := AIC{
		AgentId:      "cap-size-test",
		PrincipalUid: PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "user@test.com"},
		Capabilities: caps,
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
	aicVal, _ := asn1.Marshal(aic)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "cap-size-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: oidAIC, Value: aicVal},
		},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	result := CheckAdmission(cert, AdmissionConfig{
		EnforceCapSizeConstraints: true,
	})
	if result.Decision != DecisionDeny {
		t.Fatalf("expected Deny, got %v", result.Decision)
	}
}

func TestCheckAdmission_CapSizeConstraint_Pass(t *testing.T) {
	caps := []Capability{
		{SchemeId: "http", CapabilityId: "gateway:read"},
	}
	aic := AIC{
		AgentId:      "cap-size-ok",
		PrincipalUid: PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "user@test.com"},
		Capabilities: caps,
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
	aicVal, _ := asn1.Marshal(aic)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "cap-size-ok"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: oidAIC, Value: aicVal},
		},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	result := CheckAdmission(cert, AdmissionConfig{
		EnforceCapSizeConstraints: true,
	})
	if result.Decision != DecisionAllow {
		t.Fatalf("expected Allow, got %v: %s", result.Decision, result.Reason)
	}
}

func TestCheckAdmission_Size32_NonceTooShort(t *testing.T) {
	aic := AIC{
		AgentId:      "size32-test",
		PrincipalUid: PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "user@test.com"},
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			SignatureValue:     make([]byte, 64),
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
			Timestamp:          time.Now(),
			Nonce:              []byte{1, 2, 3}, // 3 bytes, not 32
			RequestedLifetime:  3600,
		},
	}
	aicVal, _ := asn1.Marshal(aic)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "size32-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: oidAIC, Value: aicVal},
		},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	result := CheckAdmission(cert, AdmissionConfig{EnforceSize32: true})
	if result.Decision != DecisionDeny {
		t.Fatalf("expected Deny for short nonce, got %v", result.Decision)
	}
	if result.Reason != "aic validation: aic: delegationAuth.nonce length 3: must be exactly 32 bytes" {
		t.Fatalf("expected nonce size reason, got %s", result.Reason)
	}
}

func TestCheckAdmission_Size32_NonceOK(t *testing.T) {
	nonce := make([]byte, 32)
	copy(nonce, []byte("01234567890123456789012345678901"))
	aic := AIC{
		AgentId:      "size32-ok",
		PrincipalUid: PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "user@test.com"},
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			SignatureValue:     make([]byte, 64),
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
			Timestamp:          time.Now(),
			Nonce:              nonce,
			RequestedLifetime:  3600,
		},
	}
	aicVal, _ := asn1.Marshal(aic)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "size32-ok"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: oidAIC, Value: aicVal},
		},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	result := CheckAdmission(cert, AdmissionConfig{EnforceSize32: true})
	if result.Decision != DecisionAllow {
		t.Fatalf("expected Allow, got %v: %s", result.Decision, result.Reason)
	}
}

func TestCheckAdmission_AICValidationError(t *testing.T) {
	caps := make([]Capability, 257)
	for i := range caps {
		caps[i] = Capability{SchemeId: "s", CapabilityId: "c"}
	}
	aic := AIC{
		Version:      1,
		AgentId:      "agent-overflow",
		PrincipalUid: PrincipalUid{Version: 1, Realm: "r", Identifier: "i", KeyHash: make([]byte, 32)},
		Capabilities: caps,
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}},
			RequestedLifetime:  3600,
		},
	}
	val, _ := asn1.Marshal(aic)
	cert := makeCertWithExt(t, oidAIC, val)

	result := CheckAdmission(cert, AdmissionConfig{RequireAIC: true})
	if result.Decision != DecisionDeny {
		t.Fatalf("expected Deny for AIC validation error, got %v: %s", result.Decision, result.Reason)
	}
	if result.Reason != "aic validation: aic: capabilities count 257 exceeds max 256" {
		t.Fatalf("unexpected reason: %s", result.Reason)
	}
}

// TestDelegatedAgentServerIdentity suppresses the client-supplied header (G4).
func TestDelegatedAgentServerIdentity(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:         "gateway-agent",
			OrganizationalUnit: []string{"Delegated-Agent", "admin"},
		},
	}
	// Principal is the server-asserted identity derived from the signed cert/AIC.
	user, _, reason := DelegatedAgentServerIdentity(cert, "verified-user@core", nil)
	if reason != "" {
		t.Fatalf("unexpected reason: %s", reason)
	}
	if user != "verified-user@core" {
		t.Fatalf("expected server-asserted principal, got %q", user)
	}
	// Non-delegated cert yields empty identity (no injection).
	plain := &x509.Certificate{Subject: pkix.Name{OrganizationalUnit: []string{"admin"}}}
	if u, _, _ := DelegatedAgentServerIdentity(plain, "x", nil); u != "" {
		t.Fatalf("non-delegated cert must not yield identity, got %q", u)
	}
}

// TestCheckAdmission_AuthorizedModeNoIntersection verifies P1-B-07/P1-17 semantics:
// authorized mode (DelegationMode=0/default) does not perform P∩C intersection
// or P_grants runtime upper bound check even when PA is present --
// EffectiveCaps = full AIC declarations (P2-A-04).
func TestCheckAdmission_AuthorizedModeNoIntersection(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	aic := AIC{
		AgentId:      "agent-auth",
		PrincipalUid: PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "user@varwof.com"},
		// DelegationMode defaults to DelegationAuthorized
		Capabilities: []Capability{
			{SchemeId: "http", CapabilityId: "gateway:read"},
			{SchemeId: "http", CapabilityId: "gateway:write"},
		},
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
	aicVal, _ := asn1.Marshal(aic)
	// PA only authorizes read -- authorized mode should not constrain AIC declarations
	up := PrincipalAuthorization{
		Grants: []Capability{{CapabilityId: "gateway:read"}},
	}
	upVal, _ := asn1.Marshal(up)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: oidAIC, Value: aicVal},
			{Id: oidUserPermission, Value: upVal},
		},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	// Even with RejectOverflow=true, authorized mode does not deny (no runtime upper bound check)
	result := CheckAdmission(cert, AdmissionConfig{
		RequireAIC: true, RequireUserPermission: true, RejectOverflow: true,
	})
	if result.Decision != DecisionAllow {
		t.Fatalf("expected Allow in authorized mode regardless of PA bounds, got %v: %s", result.Decision, result.Reason)
	}
	// EffectiveCaps = full AIC declarations (read + write)
	if len(result.EffectiveCaps) != 2 {
		t.Fatalf("EffectiveCaps = %v, want both declared caps (len 2)", result.EffectiveCaps)
	}
}

// TestCheckAdmission_RepresentativeModeRequiresPA verifies representative mode
// rejects without PA extension (decision.go pre-check), intersection logic only
// applies in representative mode.
func TestCheckAdmission_RepresentativeModeRequiresPA(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	aic := AIC{
		AgentId:        "agent-rep",
		PrincipalUid:   PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "user@varwof.com"},
		DelegationMode: DelegationRepresentative,
		Capabilities: []Capability{
			{SchemeId: "http", CapabilityId: "gateway:read"},
		},
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
	aicVal, _ := asn1.Marshal(aic)
	// AIC only, no PA extension
	der, _ := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber:    big.NewInt(8),
		Subject:         pkix.Name{CommonName: "test"},
		NotBefore:       time.Now().Add(-1 * time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: oidAIC, Value: aicVal}},
	}, &x509.Certificate{
		SerialNumber: big.NewInt(8),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	result := CheckAdmission(cert, AdmissionConfig{RequireAIC: true})
	if result.Decision != DecisionDeny {
		t.Fatalf("expected Deny for representative mode without PA, got %v", result.Decision)
	}
	if result.Reason != "representative mode requires principal_authorization extension" {
		t.Fatalf("reason = %q", result.Reason)
	}
}
