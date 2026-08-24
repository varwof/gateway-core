// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

func testCertWithOfflineRBAC(t *testing.T, ext *OfflineRbacExt) *x509.Certificate {
	t.Helper()
	extDER, err := asn1.Marshal(*ext)
	if err != nil {
		t.Fatal(err)
	}
	return testCertWithExtension(t, OIDOfflineRBAC, extDER)
}

func testCertWithExtension(t *testing.T, oid []int, extValue []byte) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	oidObj := asn1.ObjectIdentifier(oid)
	ext := pkix.Extension{
		Id:    oidObj,
		Value: extValue,
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		ExtraExtensions: []pkix.Extension{ext},
		NotBefore:       time.Now().Add(-1 * time.Hour),
		NotAfter:        time.Now().Add(1 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func makeOfflineRBAC(t *testing.T, mod func(*OfflineRbacExt)) *OfflineRbacExt {
	t.Helper()
	ext := &OfflineRbacExt{
		Version:          1,
		RoleId:           "gateway:ops",
		PermissionBitmap: asn1.BitString{Bytes: []byte{0x0f, 0, 0, 0}, BitLength: 32},
		ResourceScope:    []string{"/api/health", "/api/protected/*"},
		NotBefore:        time.Time{},
		NotAfter:         time.Time{},
		TrustAnchorHash:  make([]byte, 32),
	}
	if mod != nil {
		mod(ext)
	}
	return ext
}

func TestParseOfflineRBAC(t *testing.T) {
	ext := makeOfflineRBAC(t, nil)
	cert := testCertWithOfflineRBAC(t, ext)
	parsed := ParseOfflineRBAC(cert)
	if parsed == nil {
		t.Fatal("expected non-nil")
	}
	if parsed.RoleId != "gateway:ops" {
		t.Fatalf("RoleId: expected gateway:ops, got %s", parsed.RoleId)
	}
}

func TestParseOfflineRBAC_NilCert(t *testing.T) {
	if got := ParseOfflineRBAC(nil); got != nil {
		t.Fatal("expected nil for nil cert")
	}
}

func TestParseOfflineRBAC_NoExt(t *testing.T) {
	cert := testCertWithExtension(t, []int{1, 2, 3}, []byte("dummy"))
	if got := ParseOfflineRBAC(cert); got != nil {
		t.Fatal("expected nil for cert without offline_rbac ext")
	}
}

func TestOfflineRBACCheck_Allow(t *testing.T) {
	ext := makeOfflineRBAC(t, nil)
	dec := OfflineRBACCheck(ext, OfflineRBACCheckOptions{
		TargetResource: "/api/health",
		RequiredPerm:   RBACPermRead,
	})
	if !dec.Allowed {
		t.Fatalf("expected allowed, got: %s", dec.Reason)
	}
}

func TestOfflineRBACCheck_NilExt(t *testing.T) {
	dec := OfflineRBACCheck(nil, OfflineRBACCheckOptions{})
	if dec.Allowed {
		t.Fatal("expected deny for nil ext")
	}
}

func TestOfflineRBACCheck_TrustAnchorMismatch(t *testing.T) {
	ext := makeOfflineRBAC(t, func(e *OfflineRbacExt) {
		e.TrustAnchorHash = []byte("01234567890123456789012345678901")
	})
	// Create a mock issuer with different raw bytes
	issuer := &x509.Certificate{Raw: []byte("different issuer")}
	dec := OfflineRBACCheck(ext, OfflineRBACCheckOptions{
		Issuer: issuer,
	})
	if dec.Allowed {
		t.Fatal("expected deny for trust anchor mismatch")
	}
}

func TestOfflineRBACCheck_TrustAnchorMatch(t *testing.T) {
	issuer := &x509.Certificate{Raw: []byte("test issuer")}
	h := sha256.Sum256(issuer.Raw)
	ext := makeOfflineRBAC(t, func(e *OfflineRbacExt) {
		e.TrustAnchorHash = h[:]
	})
	dec := OfflineRBACCheck(ext, OfflineRBACCheckOptions{
		Issuer: issuer,
	})
	if !dec.Allowed {
		t.Fatalf("expected allowed, got: %s", dec.Reason)
	}
}

func TestOfflineRBACCheck_ResourceScopeDeny(t *testing.T) {
	ext := makeOfflineRBAC(t, nil)
	dec := OfflineRBACCheck(ext, OfflineRBACCheckOptions{
		TargetResource: "/api/admin",
		RequiredPerm:   -1,
	})
	if dec.Allowed {
		t.Fatal("expected deny for resource outside scope")
	}
}

func TestOfflineRBACCheck_ResourceScopeWildcard(t *testing.T) {
	ext := makeOfflineRBAC(t, nil)
	dec := OfflineRBACCheck(ext, OfflineRBACCheckOptions{
		TargetResource: "/api/protected/users",
		RequiredPerm:   -1,
	})
	if !dec.Allowed {
		t.Fatalf("expected allowed via wildcard, got: %s", dec.Reason)
	}
}

func TestOfflineRBACCheck_PermissionDeny(t *testing.T) {
	ext := makeOfflineRBAC(t, func(e *OfflineRbacExt) {
		e.PermissionBitmap = asn1.BitString{Bytes: []byte{0x01, 0, 0, 0}, BitLength: 32}
	})
	dec := OfflineRBACCheck(ext, OfflineRBACCheckOptions{
		RequiredPerm: RBACPermWrite,
	})
	if dec.Allowed {
		t.Fatal("expected deny for write permission not in bitmap")
	}
}

func TestOfflineRBACCheck_ValidityNotYet(t *testing.T) {
	ext := makeOfflineRBAC(t, func(e *OfflineRbacExt) {
		e.NotBefore = time.Now().Add(24 * time.Hour)
		e.NotAfter = time.Now().Add(48 * time.Hour)
	})
	dec := OfflineRBACCheck(ext, OfflineRBACCheckOptions{
		RequiredPerm: -1,
	})
	if dec.Allowed {
		t.Fatal("expected deny for not-yet-valid")
	}
}

func TestOfflineRBACCheck_ValidityExpired(t *testing.T) {
	ext := makeOfflineRBAC(t, func(e *OfflineRbacExt) {
		e.NotBefore = time.Now().Add(-48 * time.Hour)
		e.NotAfter = time.Now().Add(-24 * time.Hour)
	})
	dec := OfflineRBACCheck(ext, OfflineRBACCheckOptions{
		RequiredPerm: -1,
	})
	if dec.Allowed {
		t.Fatal("expected deny for expired")
	}
}

func TestOfflineRBACCheck_ValidityOK(t *testing.T) {
	ext := makeOfflineRBAC(t, func(e *OfflineRbacExt) {
		e.NotBefore = time.Now().Add(-1 * time.Hour)
		e.NotAfter = time.Now().Add(1 * time.Hour)
	})
	dec := OfflineRBACCheck(ext, OfflineRBACCheckOptions{
		RequiredPerm: -1,
	})
	if !dec.Allowed {
		t.Fatalf("expected allowed within validity, got: %s", dec.Reason)
	}
}

func TestOfflineRBACCheck_AllStagesCombined(t *testing.T) {
	// All three stages must pass
	issuer := &x509.Certificate{Raw: []byte("my-ca")}
	h := sha256.Sum256(issuer.Raw)
	ext := makeOfflineRBAC(t, func(e *OfflineRbacExt) {
		e.TrustAnchorHash = h[:]
		e.ResourceScope = []string{"/api/health"}
		e.PermissionBitmap = asn1.BitString{Bytes: []byte{0x08, 0, 0, 0}, BitLength: 32}
		e.NotBefore = time.Time{}
		e.NotAfter = time.Now().Add(1 * time.Hour)
	})
	// All pass
	dec := OfflineRBACCheck(ext, OfflineRBACCheckOptions{
		Issuer:         issuer,
		TargetResource: "/api/health",
		RequiredPerm:   RBACPermExec,
	})
	if !dec.Allowed {
		t.Fatalf("expected all stages pass, got: %s", dec.Reason)
	}
	// Resource fails
	dec2 := OfflineRBACCheck(ext, OfflineRBACCheckOptions{
		Issuer:         issuer,
		TargetResource: "/api/unknown",
		RequiredPerm:   RBACPermExec,
	})
	if dec2.Allowed {
		t.Fatal("expected deny when resource out of scope")
	}
}

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		pattern string
		s       string
		want    bool
	}{
		{"", "", true},
		{"*", "anything", true},
		{"/api/*", "/api/health", true},
		{"/api/*", "/api/v1/users", true},
		{"/api/*", "/other/path", false},
		{"/api/protected/*", "/api/protected/users", true},
		{"/api/health", "/api/health", true},
		{"/api/health", "/api/health/extra", false},
	}
	for _, tt := range tests {
		got := matchGlob(tt.pattern, tt.s)
		if got != tt.want {
			t.Errorf("matchGlob(%q, %q) = %v, want %v", tt.pattern, tt.s, got, tt.want)
		}
	}
}
