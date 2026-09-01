// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func testCACert(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	return caCert, caKey
}

func TestCRLCache(t *testing.T) {
	caCert, caKey := testCACert(t)
	caDN := caCert.Subject.String()

	revokedSerial := big.NewInt(42)
	activeSerial := big.NewInt(99)

	crlBytes, err := caCert.CreateCRL(rand.Reader, caKey, []pkix.RevokedCertificate{
		{SerialNumber: revokedSerial, RevocationTime: time.Now()},
	}, time.Now(), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("CreateCRL: %v", err)
	}
	crlPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlBytes})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(crlPEM)
	}))
	defer server.Close()

	cache := NewCRLCache(caCert, server.URL, 3600, nil, "en")
	if err := cache.ForceRefresh(); err != nil {
		t.Fatalf("ForceRefresh: %v", err)
	}

	revoked, err := cache.IsRevoked(caDN, revokedSerial)
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if !revoked {
		t.Error("revokedSerial should be revoked")
	}
	revoked, err = cache.IsRevoked(caDN, activeSerial)
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if revoked {
		t.Error("activeSerial should not be revoked")
	}

	n, thisUpdate, nextUpdate := cache.Stats()
	if n != 1 {
		t.Errorf("expected 1 revoked, got %d", n)
	}
	if thisUpdate.IsZero() {
		t.Error("thisUpdate should be set")
	}
	if nextUpdate.IsZero() {
		t.Error("nextUpdate should be set")
	}

	if cache.LastRefresh().IsZero() {
		t.Error("lastRefresh should be set")
	}
}

func TestCRLCacheHTTPError(t *testing.T) {
	caCert, _ := testCACert(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cache := NewCRLCache(caCert, server.URL, 3600, nil, "en")
	err := cache.ForceRefresh()
	if err == nil {
		t.Error("expected error for HTTP 500")
	}
}

func TestCRLCacheConnectionError(t *testing.T) {
	caCert, _ := testCACert(t)

	cache := NewCRLCache(caCert, "http://127.0.0.1:1/crl", 3600, nil, "en")
	err := cache.ForceRefresh()
	if err == nil {
		t.Error("expected error for connection refused")
	}
}

func TestCRLCacheParallel(t *testing.T) {
	caCert, caKey := testCACert(t)
	caDN := caCert.Subject.String()

	var crlBytes []byte
	for range 5 {
		crlBytes, _ = caCert.CreateCRL(rand.Reader, caKey, nil,
			time.Now(), time.Now().Add(24*time.Hour))
	}

	crlPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlBytes})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(crlPEM)
	}))
	defer server.Close()

	cache := NewCRLCache(caCert, server.URL, 3600, nil, "en")
	if err := cache.ForceRefresh(); err != nil {
		t.Fatalf("ForceRefresh: %v", err)
	}

	for range 100 {
		go func() {
			_, _ = cache.IsRevoked(caDN, big.NewInt(1))
			cache.Stats()
			cache.LastRefresh()
		}()
	}
}

// TestCRLCacheIssuerRDNOrder (finding 13): a revoked certificate whose issuer
// RDN ordering differs from the CA subject must still be matched (no silent
// fail-open miss).
func TestCRLCacheIssuerRDNOrder(t *testing.T) {
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	// Subject with two RDNs: O before CN.
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA", Organization: []string{"Varwof"}},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	revokedSerial := big.NewInt(4242)
	crlBytes, _ := caCert.CreateCRL(rand.Reader, caKey, []pkix.RevokedCertificate{
		{SerialNumber: revokedSerial, RevocationTime: time.Now()},
	}, time.Now(), time.Now().Add(24*time.Hour))
	crlPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlBytes})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(crlPEM)
	}))
	defer server.Close()

	cache := NewCRLCache(caCert, server.URL, 3600, nil, "en")
	if err := cache.ForceRefresh(); err != nil {
		t.Fatalf("ForceRefresh: %v", err)
	}

	// Leaf whose Issuer lists the RDNs in a different order (CN before O) but
	// is semantically the same DN. Raw bytes differ, so the structural fallback
	// must still match.
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTmpl := &x509.Certificate{
		SerialNumber: revokedSerial,
		Subject:      pkix.Name{CommonName: "leaf"},
		Issuer:       pkix.Name{CommonName: "Test CA", Organization: []string{"Varwof"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	leaf, _ := x509.ParseCertificate(leafDER)

	// Force a different raw issuer encoding by re-parsing with reordered RDN seq.
	leafTmpl2 := *leafTmpl
	leafTmpl2.RawIssuer = reorderIssuerRDN(t, caCert.RawSubject)
	leafDER2, _ := x509.CreateCertificate(rand.Reader, &leafTmpl2, caCert, &leafKey.PublicKey, caKey)
	leaf2, _ := x509.ParseCertificate(leafDER2)

	revoked, err := cache.IsRevokedCert(leaf)
	if err != nil {
		t.Fatalf("IsRevokedCert: %v", err)
	}
	if !revoked {
		t.Error("revoked cert with same-order issuer must be detected")
	}
	revoked, err = cache.IsRevokedCert(leaf2)
	if err != nil {
		t.Fatalf("IsRevokedCert(reordered): %v", err)
	}
	if !revoked {
		t.Error("revoked cert with reordered issuer RDNs must be detected (finding 13)")
	}
}

// reorderIssuerRDN returns a DER RDN sequence with RDN order reversed, to
// simulate a certificate whose issuer DN is semantically equal but differently
// ordered than the CA subject.
func reorderIssuerRDN(t *testing.T, rawSubject []byte) []byte {
	t.Helper()
	var seq pkix.RDNSequence
	if _, err := asn1.Unmarshal(rawSubject, &seq); err != nil {
		t.Fatalf("unmarshal subject: %v", err)
	}
	reversed := make(pkix.RDNSequence, len(seq))
	for i := range seq {
		reversed[len(seq)-1-i] = seq[i]
	}
	out, err := asn1.Marshal(reversed)
	if err != nil {
		t.Fatalf("marshal reordered: %v", err)
	}
	return out
}
