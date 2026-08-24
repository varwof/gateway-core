// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testPolicyJSON = `{
  "version": "v1",
  "roles": {
    "admin": {"display_name": "Admin", "profiles": ["admin"], "grants": ["ca:*", "cert:*", "config:write"]},
    "operator": {"display_name": "Operator", "profiles": ["operator"], "grants": ["cert:issue", "cert:renew"]},
    "auditor": {"display_name": "Auditor", "profiles": ["auditor"], "grants": ["audit:read", "report:*"]}
  },
  "ou_mapping": {"gateway:admin": "admin", "gateway:ops": "operator", "gateway:audit": "auditor"}
}`

// newTestCA generates a self-signed CA and an entity certificate issued by it with the given OU.
func newTestCA(t *testing.T, caOU string) (*x509.CertPool, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Issuing CA", OrganizationalUnit: []string{caOU}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return pool, caCert, caKey
}

// newSignedCert issues an entity certificate with the given OU using the CA.
func newSignedCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, ou []string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn, OrganizationalUnit: ou},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, key
}

func TestParseAuthorizationPolicy(t *testing.T) {
	p, err := ParseAuthorizationPolicy([]byte(testPolicyJSON))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !p.HasGrant("admin", "ca:create") {
		t.Error("admin should have ca:create via ca:* wildcard")
	}
	if !p.HasGrant("operator", "cert:renew") {
		t.Error("operator should have cert:renew")
	}
	if p.HasGrant("operator", "config:write") {
		t.Error("operator must NOT have config:write")
	}
	if got := p.RoleByOU("gateway:audit"); got != "auditor" {
		t.Errorf("ou_mapping gateway:audit -> %q, want auditor", got)
	}
	if got := p.IntersectGrants([]string{"operator"}, []string{"cert:issue", "ca:list"}); len(got) != 1 || got[0] != "cert:issue" {
		t.Errorf("intersect = %v, want [cert:issue]", got)
	}
}

func TestParseAuthorizationPolicyErrors(t *testing.T) {
	if _, err := ParseAuthorizationPolicy([]byte(`{"version":"v1"}`)); err == nil {
		t.Error("policy without roles should error")
	}
	if _, err := ParseAuthorizationPolicy([]byte(`{"roles":{}}`)); err == nil {
		t.Error("policy without version should error")
	}
	if _, err := ParseAuthorizationPolicy([]byte(`not-json`)); err == nil {
		t.Error("invalid json should error")
	}
}

func TestSignAndVerifyPolicyRoundTrip(t *testing.T) {
	pool, caCert, caKey := newTestCA(t, "admin")
	adminCert, adminKey := newSignedCert(t, caCert, caKey, "superadmin", []string{RoleAdmin})

	sig, err := SignPolicy([]byte(testPolicyJSON), adminCert, adminKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("empty signature")
	}

	cert, err := VerifySignedPolicy(sig, []byte(testPolicyJSON), pool, true)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if cert.Subject.CommonName != "superadmin" {
		t.Errorf("signer CN = %q, want superadmin", cert.Subject.CommonName)
	}
}

func TestVerifyPolicyRejectsTamperedContent(t *testing.T) {
	pool, caCert, caKey := newTestCA(t, "admin")
	adminCert, adminKey := newSignedCert(t, caCert, caKey, "superadmin", []string{RoleAdmin})

	sig, err := SignPolicy([]byte(testPolicyJSON), adminCert, adminKey)
	if err != nil {
		t.Fatal(err)
	}
	tampered := []byte(`{"version":"v1","roles":{"admin":{"grants":["*"]}}}`)
	if _, err := VerifySignedPolicy(sig, tampered, pool, true); err == nil {
		t.Error("tampered content should fail verification")
	}
}

func TestVerifyPolicyRejectsNonAdminSigner(t *testing.T) {
	pool, caCert, caKey := newTestCA(t, "admin")
	opsCert, opsKey := newSignedCert(t, caCert, caKey, "zhangsan", []string{RoleOps})

	sig, err := SignPolicy([]byte(testPolicyJSON), opsCert, opsKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySignedPolicy(sig, []byte(testPolicyJSON), pool, true); err == nil {
		t.Error("non-admin signer should be rejected when RequireAdminOU=true")
	}
	// When admin OU is not required, it should pass (signature itself is valid).
	if _, err := VerifySignedPolicy(sig, []byte(testPolicyJSON), pool, false); err != nil {
		t.Errorf("signature itself valid, non-admin OU should pass when not required: %v", err)
	}
}

func TestVerifyPolicyRejectsUntrustedChain(t *testing.T) {
	_, caCert, caKey := newTestCA(t, "admin")
	adminCert, adminKey := newSignedCert(t, caCert, caKey, "superadmin", []string{RoleAdmin})
	sig, err := SignPolicy([]byte(testPolicyJSON), adminCert, adminKey)
	if err != nil {
		t.Fatal(err)
	}

	// Verify with a different CA pool; should fail (untrusted chain).
	otherPool, _, _ := newTestCA(t, "admin")
	if _, err := VerifySignedPolicy(sig, []byte(testPolicyJSON), otherPool, true); err == nil {
		t.Error("signer chain from different CA should be rejected")
	}
}

func TestVerifyPolicyRejectsSignatureTamper(t *testing.T) {
	pool, caCert, caKey := newTestCA(t, "admin")
	adminCert, adminKey := newSignedCert(t, caCert, caKey, "superadmin", []string{RoleAdmin})
	sig, err := SignPolicy([]byte(testPolicyJSON), adminCert, adminKey)
	if err != nil {
		t.Fatal(err)
	}
	sig[len(sig)-1] ^= 0xff
	if _, err := VerifySignedPolicy(sig, []byte(testPolicyJSON), pool, true); err == nil {
		t.Error("tampered signature should fail verification")
	}
}

func TestLoadAuthorizationPolicyWithSignature(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "authz.json")
	sigPath := policyPath + ".sig"
	if err := os.WriteFile(policyPath, []byte(testPolicyJSON), 0600); err != nil {
		t.Fatal(err)
	}

	pool, caCert, caKey := newTestCA(t, "admin")
	adminCert, adminKey := newSignedCert(t, caCert, caKey, "superadmin", []string{RoleAdmin})
	sig, err := SignPolicy([]byte(testPolicyJSON), adminCert, adminKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sigPath, sig, 0600); err != nil {
		t.Fatal(err)
	}

	p, err := LoadAuthorizationPolicy(policyPath, ".sig", &PolicyVerifyOptions{Roots: pool, RequireAdminOU: true})
	if err != nil {
		t.Fatalf("load with valid signature: %v", err)
	}
	if p.Version != "v1" {
		t.Errorf("version = %q, want v1", p.Version)
	}
}

func TestLoadAuthorizationPolicyRejectsMissingSig(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "authz.json")
	if err := os.WriteFile(policyPath, []byte(testPolicyJSON), 0600); err != nil {
		t.Fatal(err)
	}
	pool, _, _ := newTestCA(t, "admin")
	if _, err := LoadAuthorizationPolicy(policyPath, ".sig", &PolicyVerifyOptions{Roots: pool}); err == nil {
		t.Error("missing .sig with opts should error (fail-closed)")
	}
}

func TestLoadAuthorizationPolicyWithoutOpts(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "authz.json")
	if err := os.WriteFile(policyPath, []byte(testPolicyJSON), 0600); err != nil {
		t.Fatal(err)
	}
	// When opts=nil, signature is not verified (compatible with unsigned deployments).
	if _, err := LoadAuthorizationPolicy(policyPath, ".sig", nil); err != nil {
		t.Errorf("load without opts should not require signature: %v", err)
	}
}

func TestMatchCapabilityVariants(t *testing.T) {
	cases := []struct {
		id, pat string
		want    bool
	}{
		{"ca:list", "ca:list", true},
		{"ca:list", "ca:*", true},
		{"ca:list", "*", true},
		{"ca:create", "ca:*", true},
		{"varwof/demo-mysql-v1:SELECT:*", "varwof/demo-mysql-v1:SELECT:*", true},
		{"cert:issue", "cert:renew", false},
		{"ca:list", "varwof/demo-mysql-v1:*", false},
	}
	for _, c := range cases {
		if got := MatchCapability(c.id, c.pat); got != c.want {
			t.Errorf("MatchCapability(%q, %q) = %v, want %v", c.id, c.pat, got, c.want)
		}
	}
}

func TestIsAdminOU(t *testing.T) {
	if !IsAdminOU("gateway:admin") {
		t.Error("gateway:admin should be admin OU")
	}
	if !IsAdminOU("admin") {
		t.Error("admin should be admin OU")
	}
	if IsAdminOU("gateway:ops") {
		t.Error("gateway:ops must not be admin OU")
	}
}

func TestSignerHasAdminOU(t *testing.T) {
	_, caCert, caKey := newTestCA(t, "admin")
	adminCert, _ := newSignedCert(t, caCert, caKey, "superadmin", []string{"admin"})
	if !SignerHasAdminOU(adminCert) {
		t.Error("cert with OU=admin should be admin")
	}
	opsCert, _ := newSignedCert(t, caCert, caKey, "zhangsan", []string{RoleOps})
	if SignerHasAdminOU(opsCert) {
		t.Error("cert with OU=gateway:ops must not be admin")
	}
}
