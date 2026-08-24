package gw

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeCertPEM(t *testing.T, dir, name string, cert *x509.Certificate, key *rsa.PrivateKey) (string, string) {
	t.Helper()
	certPath := filepath.Join(dir, name+".pem")
	keyPath := filepath.Join(dir, name+".key")

	certDER := cert.Raw
	f, _ := os.Create(certPath)
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	f.Close()

	keyDER := x509.MarshalPKCS1PrivateKey(key)
	f2, _ := os.Create(keyPath)
	pem.Encode(f2, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER})
	f2.Close()

	return certPath, keyPath
}

func TestNewRevoker_Validation(t *testing.T) {
	_, err := NewRevoker(RevokerConfig{CoreURL: ""})
	if err == nil {
		t.Fatal("expected error for empty CoreURL")
	}

	_, err = NewRevoker(RevokerConfig{CoreURL: "http://example.com"})
	if err == nil {
		t.Fatal("expected error for empty cert/key files")
	}

	_, err = NewRevoker(RevokerConfig{
		CoreURL:      "http://example.com",
		MTLSCertFile: "/nonexistent/cert.pem",
		MTLSKeyFile:  "/nonexistent/key.pem",
	})
	if err == nil {
		t.Fatal("expected error for nonexistent cert file")
	}
}

func TestNewRevoker_Success(t *testing.T) {
	dir := t.TempDir()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-gateway"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	certPath, keyPath := writeCertPEM(t, dir, "gateway", cert, key)

	r, err := NewRevoker(RevokerConfig{
		CoreURL:      "http://example.com/api/v1",
		MTLSCertFile: certPath,
		MTLSKeyFile:  keyPath,
	})
	if err != nil {
		t.Fatalf("NewRevoker: %v", err)
	}
	if r == nil {
		t.Fatal("expected non-nil revoker")
	}
	if r.cfg.Timeout != 10*time.Second {
		t.Fatalf("default timeout: expected 10s, got %v", r.cfg.Timeout)
	}
	if r.cfg.RetryCount != 2 {
		t.Fatalf("default retry: expected 2, got %d", r.cfg.RetryCount)
	}
}

func TestNormalizeSerial(t *testing.T) {
	tests := []struct {
		input    *big.Int
		expected string
	}{
		{big.NewInt(1), "0000000000000000000000000000000000000001"},
		{big.NewInt(255), "00000000000000000000000000000000000000FF"},
		{big.NewInt(0), "0000000000000000000000000000000000000000"},
		{big.NewInt(0x1234567890ABCDEF), "0000000000000000000000001234567890ABCDEF"},
	}
	for _, tt := range tests {
		got := NormalizeSerial(tt.input)
		if got != tt.expected {
			t.Fatalf("NormalizeSerial(%x): expected %s, got %s", tt.input, tt.expected, got)
		}
	}
}

func TestRevoker_caNameFor(t *testing.T) {
	r := &Revoker{
		cfg: RevokerConfig{
			CAMap: map[string]string{
				"Varwof Issuing CA": "issuing",
				"Varwof Client CA":  "client",
			},
		},
	}
	if got := r.caNameFor("Varwof Issuing CA"); got != "issuing" {
		t.Fatalf("exact match: expected issuing, got %s", got)
	}
	if got := r.caNameFor("varwof issuing ca"); got != "issuing" {
		t.Fatalf("case-insensitive match: expected issuing, got %s", got)
	}
	if got := r.caNameFor("Unknown CA"); got != "" {
		t.Fatalf("no match: expected empty, got %s", got)
	}

	r2 := &Revoker{cfg: RevokerConfig{CAMap: nil}}
	if got := r2.caNameFor("anything"); got != "" {
		t.Fatalf("nil CAMap: expected empty, got %s", got)
	}
}

func TestRevoker_RevokeClientCert_Nil(t *testing.T) {
	r := &Revoker{}
	r.RevokeClientCert(nil, nil)
}

func TestRevoker_RevokeClientCert_Expired(t *testing.T) {
	cert := &x509.Certificate{
		NotAfter: time.Now().Add(-1 * time.Hour),
	}
	r := &Revoker{}
	r.RevokeClientCert(cert, nil)
}

func TestRevoker_RevokeClientCert_UnknownCA(t *testing.T) {
	now := time.Now()
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "test-client"},
		Issuer:       pkix.Name{CommonName: "Unknown CA"},
		NotAfter:     now.Add(time.Hour),
	}
	audit, _ := NewAuditLogger("", nil, 0, 0)
	r := &Revoker{cfg: RevokerConfig{CAMap: map[string]string{"Known CA": "known"}}}
	r.RevokeClientCert(cert, audit)
}

// TestRevoker_RevokeClientCert_RenewedSkip Verifies P2-A-15: skip revocation when serial is renewed
// (ConnExpiryRegistry renewed flag = true) — no API call issued.
func TestRevoker_RevokeClientCert_RenewedSkip(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	now := time.Now()
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(0x1234),
		Subject:      pkix.Name{CommonName: "agent-1"},
		Issuer:       pkix.Name{CommonName: "Test CA"},
		NotAfter:     now.Add(time.Hour),
	}
	audit, _ := NewAuditLogger("", nil, 0, 0)

	r := &Revoker{cfg: RevokerConfig{
		CoreURL:      server.URL,
		CAMap:        map[string]string{"Test CA": "test-ca"},
		MTLSCertFile: "x.pem",
		MTLSKeyFile:  "x.pem",
	}}
	reg := NewConnExpiryRegistry()
	r.SetConnRegistry(reg)

	// Renewal succeeded → UpdateCert sets the renewed flag.
	reg.Register(NormalizeSerial(cert.SerialNumber), cert)
	if !reg.UpdateCert(NormalizeSerial(cert.SerialNumber), cert) {
		t.Fatal("UpdateCert failed")
	}

	// Close triggers revocation evaluation → should be skipped, zero API calls.
	r.RevokeClientCert(cert, audit)
	if requests != 0 {
		t.Fatalf("expected 0 API calls (renewed skip), got %d", requests)
	}
}

// TestRevoker_RevokeClientCertForced_BypassesRenewedSkip Verifies G2(c):
// forced revocation bypasses the renewed flag; issues revocation even if certificate is marked renewed.
func TestRevoker_RevokeClientCertForced_BypassesRenewedSkip(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	now := time.Now()
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(0x9ABC),
		Subject:      pkix.Name{CommonName: "agent-forced"},
		Issuer:       pkix.Name{CommonName: "Test CA"},
		NotAfter:     now.Add(time.Hour),
	}
	audit, _ := NewAuditLogger("", nil, 0, 0)

	dir := t.TempDir()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "revoker-gateway"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	caCert, _ := x509.ParseCertificate(der)
	certPath, keyPath := writeCertPEM(t, dir, "revoker", caCert, key)

	r, err := NewRevoker(RevokerConfig{
		CoreURL:      server.URL,
		CAMap:        map[string]string{"Test CA": "test-ca"},
		MTLSCertFile: certPath,
		MTLSKeyFile:  keyPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	reg := NewConnExpiryRegistry()
	r.SetConnRegistry(reg)

	// Renewal succeeded → set renewed flag (the path where renewed-skip would take effect).
	reg.Register(NormalizeSerial(cert.SerialNumber), cert)
	if !reg.UpdateCert(NormalizeSerial(cert.SerialNumber), cert) {
		t.Fatal("UpdateCert failed")
	}
	if !r.Registry().ShouldSkipRevoke(NormalizeSerial(cert.SerialNumber)) {
		t.Fatal("ShouldSkipRevoke should be true (renewed)")
	}

	// Forced revocation: issues API call even if renewed flag is set.
	r.RevokeClientCertForced(cert, audit)
	if requests != 1 {
		t.Fatalf("expected 1 API call (forced revoke bypasses renewed skip), got %d", requests)
	}
}

// TestRevoker_RevokeClientCert_NotRenewedRevokes Verifies normal revocation for non-renewed serials.
func TestRevoker_RevokeClientCert_NotRenewedRevokes(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	now := time.Now()
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(0x5678),
		Subject:      pkix.Name{CommonName: "agent-2"},
		Issuer:       pkix.Name{CommonName: "Test CA"},
		NotAfter:     now.Add(time.Hour),
	}
	audit, _ := NewAuditLogger("", nil, 0, 0)

	dir := t.TempDir()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "revoker-gateway"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	caCert, _ := x509.ParseCertificate(der)
	certPath, keyPath := writeCertPEM(t, dir, "revoker", caCert, key)

	r, err := NewRevoker(RevokerConfig{
		CoreURL:      server.URL,
		CAMap:        map[string]string{"Test CA": "test-ca"},
		MTLSCertFile: certPath,
		MTLSKeyFile:  keyPath,
	})
	if err != nil {
		t.Fatalf("NewRevoker: %v", err)
	}
	reg := NewConnExpiryRegistry()
	r.SetConnRegistry(reg)

	// Registered but not renewed → close should revoke normally.
	reg.Register(NormalizeSerial(cert.SerialNumber), cert)
	r.RevokeClientCert(cert, audit)
	if requests != 1 {
		t.Fatalf("expected 1 API call, got %d", requests)
	}
}

func TestRevoker_RevokeClientCert_API(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	now := time.Now()
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(0xABCD),
		Subject:      pkix.Name{CommonName: "test-client"},
		Issuer:       pkix.Name{CommonName: "Test CA"},
		NotAfter:     now.Add(time.Hour),
	}
	audit, _ := NewAuditLogger("", nil, 0, 0)

	dir := t.TempDir()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "revoker-gateway"},
		NotBefore:    now.Add(-1 * time.Hour),
		NotAfter:     now.Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	caCert, _ := x509.ParseCertificate(der)
	certPath, keyPath := writeCertPEM(t, dir, "revoker", caCert, key)

	r, err := NewRevoker(RevokerConfig{
		CoreURL:      server.URL + "/api/v1",
		MTLSCertFile: certPath,
		MTLSKeyFile:  keyPath,
		CAMap:        map[string]string{"Test CA": "issuing"},
	})
	if err != nil {
		t.Fatalf("NewRevoker: %v", err)
	}

	r.RevokeClientCert(cert, audit)
	if requests != 1 {
		t.Fatalf("expected 1 API call, got %d", requests)
	}
}

func TestRevoker_RevokeClientCert_APIRetry(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	now := time.Now()
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(0xDEAD),
		Subject:      pkix.Name{CommonName: "retry-client"},
		Issuer:       pkix.Name{CommonName: "Test CA"},
		NotAfter:     now.Add(time.Hour),
	}

	dir := t.TempDir()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "revoker-gateway"},
		NotBefore:    now.Add(-1 * time.Hour),
		NotAfter:     now.Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	caCert, _ := x509.ParseCertificate(der)
	certPath, keyPath := writeCertPEM(t, dir, "revoker-retry", caCert, key)

	audit, _ := NewAuditLogger("", nil, 0, 0)
	r, err := NewRevoker(RevokerConfig{
		CoreURL:      server.URL + "/api/v1",
		MTLSCertFile: certPath,
		MTLSKeyFile:  keyPath,
		CAMap:        map[string]string{"Test CA": "issuing"},
		RetryCount:   1,
	})
	if err != nil {
		t.Fatalf("NewRevoker: %v", err)
	}

	r.RevokeClientCert(cert, audit)
	if attempts != 2 {
		t.Fatalf("expected 2 attempts (1 initial + 1 retry), got %d", attempts)
	}
}
