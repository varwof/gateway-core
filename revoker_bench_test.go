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

// writeRevokerCertPEM writes cert and key to temp files (no *testing.T helpers in benchmark).
func writeRevokerCertPEM(dir string, cert *x509.Certificate, key *rsa.PrivateKey) (string, string) {
	certPath := filepath.Join(dir, "revoker.pem")
	keyPath := filepath.Join(dir, "revoker.key")

	f, _ := os.Create(certPath)
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	f.Close()

	f2, _ := os.Create(keyPath)
	pem.Encode(f2, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	f2.Close()

	return certPath, keyPath
}

// BenchmarkRevokeEndToEnd measures the end-to-end latency from "task completion event → revoke API response" (E4).
// Scenario: cert not expired → RevokeClientCert determines NeedRevoke=true → calls varwof-core revoke API.
// Uses httptest to mock the varwof-core revoke endpoint (localhost loopback, real HTTP + mTLS auth path).
func BenchmarkRevokeEndToEnd(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	now := time.Now()
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(0xABCDEF),
		Subject:      pkix.Name{CommonName: "task-client"},
		Issuer:       pkix.Name{CommonName: "Test CA"},
		NotAfter:     now.Add(time.Hour),
	}

	dir := b.TempDir()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "revoker-gateway"},
		NotBefore:    now.Add(-1 * time.Hour),
		NotAfter:     now.Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	caCert, _ := x509.ParseCertificate(der)
	certPath, keyPath := writeRevokerCertPEM(dir, caCert, key)

	r, err := NewRevoker(RevokerConfig{
		CoreURL:      server.URL + "/api/v1",
		MTLSCertFile: certPath,
		MTLSKeyFile:  keyPath,
		CAMap:        map[string]string{"Test CA": "issuing"},
	})
	if err != nil {
		b.Fatal(err)
	}

	audit, _ := NewAuditLogger("", nil, 0, 0)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.RevokeClientCert(cert, audit)
	}
}
