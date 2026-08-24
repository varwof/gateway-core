package gw

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
)

func TestParsePrincipalProfile_NilCert(t *testing.T) {
	_, err := ParsePrincipalProfile(nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for nil cert")
	}
}

func TestParsePrincipalProfile_Basic(t *testing.T) {
	cert := makeTestCert("test-user", []string{"gateway:admin"})
	p, err := ParsePrincipalProfile(cert, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.CommonName != "test-user" {
		t.Fatalf("expected test-user, got %s", p.CommonName)
	}
	if len(p.Roles) != 1 || p.Roles[0] != "gateway:admin" {
		t.Fatalf("expected [gateway:admin], got %v", p.Roles)
	}
	if p.CertHash == "" {
		t.Fatal("expected non-empty cert hash")
	}
	if p.UserPermission != nil {
		t.Fatal("expected nil UserPermission")
	}
}

func TestParsePrincipalProfile_WithUP(t *testing.T) {
	cert := makeTestCert("principal", []string{"gateway:ops"})
	up := &UserPermission{
		AgentDelegation: DelegationPolicy{
			AllowedMode: 1,
		},
	}
	p, err := ParsePrincipalProfile(cert, nil, up)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.PrincipalUID != "principal" {
		t.Fatalf("expected principal (CN fallback), got %s", p.PrincipalUID)
	}
	if p.UserPermission != up {
		t.Fatal("UserPermission pointer mismatch")
	}
}

func TestParsePrincipalProfile_WithAICPrincipalUID(t *testing.T) {
	cert := makeTestCert("user-cn", []string{"gateway:ops"})
	aic := &AIC{
		PrincipalUid: PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "p-999"},
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
	p, err := ParsePrincipalProfile(cert, aic, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.PrincipalUID != "varwof:p-999:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
		t.Fatalf("expected varwof:p-999:<keyhash>, got %s", p.PrincipalUID)
	}
}

func TestPrincipalProfile_HasRole(t *testing.T) {
	cert := makeTestCert("user", []string{"gateway:audit"})
	p, err := ParsePrincipalProfile(cert, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !p.HasRole("gateway:audit") {
		t.Fatal("should have audit role")
	}
	if p.HasRole("gateway:admin") {
		t.Fatal("should not have admin role")
	}
}

func TestPrincipalProfile_AllowsDelegationMode(t *testing.T) {
	cert := makeTestCert("user", []string{"gateway:admin"})
	up := &UserPermission{
		AgentDelegation: DelegationPolicy{
			AllowedMode: 1,
		},
	}
	p, err := ParsePrincipalProfile(cert, nil, up)
	if err != nil {
		t.Fatal(err)
	}
	if !p.AllowsDelegationMode(0) {
		t.Fatal("AllowedMode 1 should allow mode 0")
	}
	if !p.AllowsDelegationMode(1) {
		t.Fatal("AllowedMode 1 should allow mode 1")
	}
	if p.AllowsDelegationMode(2) {
		t.Fatal("AllowedMode 1 should not allow mode 2")
	}
}

func TestPrincipalProfile_AllowsDelegationMode_NilUP(t *testing.T) {
	cert := makeTestCert("user", []string{})
	p, err := ParsePrincipalProfile(cert, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.AllowsDelegationMode(0) {
		t.Fatal("nil UP should not allow any delegation")
	}
}

func makeTestCert(cn string, ous []string) *x509.Certificate {
	raw := []byte(cn)
	for _, ou := range ous {
		raw = append(raw, []byte(":"+ou)...)
	}
	return &x509.Certificate{
		Subject: pkix.Name{
			CommonName:         cn,
			OrganizationalUnit: ous,
		},
		Raw: raw,
	}
}
