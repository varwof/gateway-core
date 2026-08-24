// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type testPKI struct {
	caCert *x509.Certificate
	caKey  *rsa.PrivateKey
	caPool *x509.CertPool
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return &testPKI{caCert: caCert, caKey: key, caPool: pool}
}

func (p *testPKI) issueCert(t *testing.T, cn string, ips ...net.IP) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		DNSNames:     []string{cn},
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return key, cert
}

func writeCertKey(t *testing.T, dir, name string, cert *x509.Certificate, key *rsa.PrivateKey) (certFile, keyFile string) {
	t.Helper()
	certFile = filepath.Join(dir, name+".pem")
	f, _ := os.Create(certFile)
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	f.Close()

	keyFile = filepath.Join(dir, name+".key")
	kf, _ := os.Create(keyFile)
	pem.Encode(kf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	kf.Close()
	return
}

func TestNewIssueClient_Validation(t *testing.T) {
	t.Run("empty url", func(t *testing.T) {
		_, err := NewIssueClient(IssueConfig{})
		if err == nil {
			t.Fatal("expected error for empty CoreURL")
		}
	})

	t.Run("missing cert", func(t *testing.T) {
		_, err := NewIssueClient(IssueConfig{CoreURL: "https://example.com"})
		if err == nil {
			t.Fatal("expected error for missing cert")
		}
	})

	t.Run("missing key", func(t *testing.T) {
		dir := t.TempDir()
		pki := newTestPKI(t)
		clientKey, clientCert := pki.issueCert(t, "test-client")
		certFile, _ := writeCertKey(t, dir, "client", clientCert, clientKey)
		_, err := NewIssueClient(IssueConfig{
			CoreURL:  "https://example.com",
			CertFile: certFile,
		})
		if err == nil {
			t.Fatal("expected error for missing key")
		}
	})
}

func TestNewIssueClient_Success(t *testing.T) {
	dir := t.TempDir()
	pki := newTestPKI(t)
	key, cert := pki.issueCert(t, "test-client")
	certFile, keyFile := writeCertKey(t, dir, "client", cert, key)

	client, err := NewIssueClient(IssueConfig{
		CoreURL:  "https://core.example.com:4433",
		CertFile: certFile,
		KeyFile:  keyFile,
	})
	if err != nil {
		t.Fatalf("NewIssueClient() error = %v", err)
	}
	if client == nil {
		t.Fatal("NewIssueClient() returned nil")
	}
}

func TestIssueClient_Issue_Success(t *testing.T) {
	pki := newTestPKI(t)
	serverKey, serverCert := pki.issueCert(t, "server", net.ParseIP("127.0.0.1"), net.ParseIP("::1"))

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/certs" {
			t.Errorf("expected /api/v1/certs, got %s", r.URL.Path)
		}
		var req IssueRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req.CN != "test-service" {
			t.Errorf("expected CN=test-service, got %s", req.CN)
		}
		if req.Validity != 1 {
			t.Errorf("expected validity=1, got %d", req.Validity)
		}
		resp := IssueResult{
			SerialNumber: "00A1B2C3D4E5F6",
			CommonName:   "test-service",
			CertPEM:      "-----BEGIN CERTIFICATE-----\nMIIBfDCCASOgAwIBAgIUQjKF...\n-----END CERTIFICATE-----",
			KeyPEM:       "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEE...\n-----END EC PRIVATE KEY-----",
			CA:           "issuing",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{serverCert.Raw},
			PrivateKey:  serverKey,
		}},
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  pki.caPool,
	}
	srv.StartTLS()
	defer srv.Close()

	dir := t.TempDir()
	clientKey, clientCert := pki.issueCert(t, "test-client")
	certFile, keyFile := writeCertKey(t, dir, "client", clientCert, clientKey)

	client, err := NewIssueClient(IssueConfig{
		CoreURL:    srv.URL,
		CertFile:   certFile,
		KeyFile:    keyFile,
		CACertFile: "", // uses InsecureSkipVerify equivalent
	})
	if err != nil {
		t.Fatalf("NewIssueClient() error = %v", err)
	}
	// Override TLS config to trust our CA
	client.client.Transport.(*http.Transport).TLSClientConfig.RootCAs = pki.caPool

	result, err := client.Issue(&IssueRequest{
		CA:       "issuing",
		CN:       "test-service",
		Validity: 1,
		Profile:  "tls-server",
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if result.SerialNumber != "00A1B2C3D4E5F6" {
		t.Errorf("serial = %q", result.SerialNumber)
	}
	if result.CommonName != "test-service" {
		t.Errorf("cn = %q", result.CommonName)
	}
	if result.CA != "issuing" {
		t.Errorf("ca = %q", result.CA)
	}
}

func TestIssueClient_Issue_APIError(t *testing.T) {
	pki := newTestPKI(t)
	serverKey, serverCert := pki.issueCert(t, "server", net.ParseIP("127.0.0.1"), net.ParseIP("::1"))

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid CA"}`))
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{serverCert.Raw},
			PrivateKey:  serverKey,
		}},
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  pki.caPool,
	}
	srv.StartTLS()
	defer srv.Close()

	dir := t.TempDir()
	clientKey, clientCert := pki.issueCert(t, "test-client")
	certFile, keyFile := writeCertKey(t, dir, "client", clientCert, clientKey)

	client, err := NewIssueClient(IssueConfig{CoreURL: srv.URL, CertFile: certFile, KeyFile: keyFile})
	if err != nil {
		t.Fatalf("NewIssueClient() error = %v", err)
	}
	client.client.Transport.(*http.Transport).TLSClientConfig.RootCAs = pki.caPool

	_, err = client.Issue(&IssueRequest{CA: "issuing", CN: "fail"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestIssueClient_DefaultCA(t *testing.T) {
	pki := newTestPKI(t)
	serverKey, serverCert := pki.issueCert(t, "server", net.ParseIP("127.0.0.1"), net.ParseIP("::1"))

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req IssueRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.CA != "default-ca" {
			t.Errorf("expected CA=default-ca, got %s", req.CA)
		}
		json.NewEncoder(w).Encode(IssueResult{
			SerialNumber: "01", CommonName: req.CN, CA: req.CA,
		})
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{serverCert.Raw},
			PrivateKey:  serverKey,
		}},
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  pki.caPool,
	}
	srv.StartTLS()
	defer srv.Close()

	dir := t.TempDir()
	clientKey, clientCert := pki.issueCert(t, "test-client")
	certFile, keyFile := writeCertKey(t, dir, "client", clientCert, clientKey)

	client, err := NewIssueClient(IssueConfig{
		CoreURL:   srv.URL,
		CertFile:  certFile,
		KeyFile:   keyFile,
		DefaultCA: "default-ca",
	})
	if err != nil {
		t.Fatalf("NewIssueClient() error = %v", err)
	}
	client.client.Transport.(*http.Transport).TLSClientConfig.RootCAs = pki.caPool

	result, err := client.Issue(&IssueRequest{CN: "test-svc"})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if result.CA != "default-ca" {
		t.Errorf("ca = %q", result.CA)
	}
}

func TestIssueResult_Certificate(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		DNSNames:     []string{"test"},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	r := &IssueResult{CertPEM: certPEM}
	cert, err := r.Certificate()
	if err != nil {
		t.Fatalf("Certificate() error = %v", err)
	}
	if cert.Subject.CommonName != "test" {
		t.Errorf("CN = %q", cert.Subject.CommonName)
	}

	cached, err := r.Certificate()
	if err != nil {
		t.Fatal(err)
	}
	if cached != cert {
		t.Error("Certificate() should return cached result")
	}
}

func TestNeedRenew(t *testing.T) {
	t.Run("nil cert needs renew", func(t *testing.T) {
		if !NeedRenew(nil, 5*time.Minute) {
			t.Error("nil cert should need renew")
		}
	})

	t.Run("expired cert needs renew", func(t *testing.T) {
		cert := &x509.Certificate{
			NotAfter: time.Now().Add(-1 * time.Hour),
		}
		if !NeedRenew(cert, 5*time.Minute) {
			t.Error("expired cert should need renew")
		}
	})

	t.Run("cert expiring within window needs renew", func(t *testing.T) {
		cert := &x509.Certificate{
			NotAfter: time.Now().Add(2 * time.Minute),
		}
		if !NeedRenew(cert, 5*time.Minute) {
			t.Error("cert expiring in 2m with 5m window should need renew")
		}
	})

	t.Run("valid cert outside window does not need renew", func(t *testing.T) {
		cert := &x509.Certificate{
			NotAfter: time.Now().Add(10 * time.Minute),
		}
		if NeedRenew(cert, 5*time.Minute) {
			t.Error("cert valid for 10m with 5m window should not need renew")
		}
	})

	realKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		DNSNames:     []string{"test"},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &realKey.PublicKey, realKey)
	cert, _ := x509.ParseCertificate(der)

	t.Run("real valid cert", func(t *testing.T) {
		if NeedRenew(cert, 5*time.Minute) {
			t.Error("real cert valid for 1h should not need renew")
		}
	})
}

// TestNeedRenewPct verifies the percentage-based renewal threshold (spec P2-A-11, default 10%):
// A cert with 24h total validity and 2h remaining (≈8.3%<10%) should renew; 3h remaining (12.5%>10%) should not;
// Short-validity certs fall back to a fixed 2min window; nil certs should renew.
func TestNeedRenewPct(t *testing.T) {
	t.Run("nil needs renew", func(t *testing.T) {
		if !NeedRenewPct(nil, 0) {
			t.Error("nil cert should need renew")
		}
	})
	t.Run("remaining below 10% needs renew", func(t *testing.T) {
		now := time.Now()
		cert := &x509.Certificate{
			NotBefore: now.Add(-22 * time.Hour),
			NotAfter:  now.Add(2 * time.Hour),
		}
		if !NeedRenewPct(cert, 0) {
			t.Error("2h remaining of 24h (8.3%) should need renew")
		}
	})
	t.Run("remaining above 10% no renew", func(t *testing.T) {
		now := time.Now()
		cert := &x509.Certificate{
			NotBefore: now.Add(-21 * time.Hour),
			NotAfter:  now.Add(3 * time.Hour),
		}
		if NeedRenewPct(cert, 0) {
			t.Error("3h remaining of 24h (12.5%) should not need renew")
		}
	})
	t.Run("custom pct", func(t *testing.T) {
		now := time.Now()
		cert := &x509.Certificate{
			NotBefore: now.Add(-23 * time.Hour),
			NotAfter:  now.Add(1 * time.Hour),
		}
		if !NeedRenewPct(cert, 0.05) {
			t.Error("1h remaining of 24h is 4.2% < 5%, should renew")
		}
	})
	t.Run("no NotBefore falls back to fixed window", func(t *testing.T) {
		cert := &x509.Certificate{NotAfter: time.Now().Add(90 * time.Second)}
		if !NeedRenewPct(cert, 0) {
			t.Error("1.5m remaining should renew via fixed 2m window fallback")
		}
		cert2 := &x509.Certificate{NotAfter: time.Now().Add(3 * time.Minute)}
		if NeedRenewPct(cert2, 0) {
			t.Error("3m remaining with no NotBefore should not renew (outside 2m fallback)")
		}
	})
}

func TestIssueClient_Retry(t *testing.T) {
	var attempts int
	pki := newTestPKI(t)
	serverKey, serverCert := pki.issueCert(t, "server", net.ParseIP("127.0.0.1"), net.ParseIP("::1"))

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(IssueResult{
			SerialNumber: "01", CommonName: "retried",
		})
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{serverCert.Raw},
			PrivateKey:  serverKey,
		}},
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  pki.caPool,
	}
	srv.StartTLS()
	defer srv.Close()

	dir := t.TempDir()
	clientKey, clientCert := pki.issueCert(t, "test-client")
	certFile, keyFile := writeCertKey(t, dir, "client", clientCert, clientKey)

	client, err := NewIssueClient(IssueConfig{
		CoreURL:    srv.URL,
		CertFile:   certFile,
		KeyFile:    keyFile,
		RetryCount: 3,
		DefaultCA:  "test-ca",
	})
	if err != nil {
		t.Fatalf("NewIssueClient() error = %v", err)
	}
	client.client.Transport.(*http.Transport).TLSClientConfig.RootCAs = pki.caPool

	result, err := client.Issue(&IssueRequest{CN: "retried-svc"})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if result.CommonName != "retried" {
		t.Errorf("cn = %q", result.CommonName)
	}
}
