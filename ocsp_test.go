// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func makeOCSPTestCert(t *testing.T, ocspURL string) *x509.Certificate {
	t.Helper()

	var aiaBytes []byte
	if ocspURL != "" {
		desc := accessDescription{
			Method: OCSPOID,
			Location: asn1.RawValue{
				Class: asn1.ClassContextSpecific,
				Tag:   6,
				Bytes: []byte(ocspURL),
			},
		}
		aiaBytes, _ = asn1.Marshal([]accessDescription{desc})
	}

	return &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-ocsp"},
		Extensions: []pkix.Extension{
			{Id: AIAOID, Value: aiaBytes},
		},
	}
}

func TestExtractOCSPURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"with OCSP URL", "http://ocsp.example.com/"},
		{"empty URL", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := makeOCSPTestCert(t, tt.url)
			got := ExtractOCSPURL(cert)
			if got != tt.url {
				t.Errorf("ExtractOCSPURL = %q, want %q", got, tt.url)
			}
		})
	}
}

func TestOCSPCacheNew(t *testing.T) {
	c := NewOCSPCache(0, "invalid", nil, "en")
	if c.ttl != 5*time.Minute {
		t.Errorf("default ttl = %v, want 5m", c.ttl)
	}
	if c.fallback != OCSPFallbackDeny {
		t.Errorf("default fallback = %q, want %q (changed from allow to deny for security)", c.fallback, OCSPFallbackDeny)
	}
}

func TestOCSPCacheFlush(t *testing.T) {
	c := NewOCSPCache(5*time.Minute, OCSPFallbackAllow, nil, "en")
	c.entries["test"] = &ocspCacheEntry{status: 0}
	if len(c.entries) != 1 {
		t.Fatal("expected 1 entry")
	}
	c.Flush()
	if len(c.entries) != 0 {
		t.Fatal("expected 0 entries after flush")
	}
}

func TestOCSPCacheStats(t *testing.T) {
	c := NewOCSPCache(5*time.Minute, OCSPFallbackAllow, nil, "en")
	c.entries["good"] = &ocspCacheEntry{status: 0}
	c.entries["revoked"] = &ocspCacheEntry{status: 1}
	good, revoked := c.Stats()
	if good != 1 {
		t.Errorf("good = %d, want 1", good)
	}
	if revoked != 1 {
		t.Errorf("revoked = %d, want 1", revoked)
	}
}

func TestOCSPCacheCheckNoURL(t *testing.T) {
	c := NewOCSPCache(5*time.Minute, OCSPFallbackAllow, nil, "en")
	leaf := makeOCSPTestCert(t, "")
	issuer := makeOCSPTestCert(t, "")
	if err := c.Check(leaf, issuer); err != nil {
		t.Errorf("Check with no OCSP URL should return nil, got: %v", err)
	}
}

// B26: a leaf-only chain (no issuer cert) must not panic ocsp.CreateRequest when
// the leaf carries an OCSP AIA URL. Previously issuer=nil reached
// ocsp.CreateRequest → runtime nil pointer panic in the gateway data plane.
func TestOCSPCacheCheckNilIssuer(t *testing.T) {
	c := NewOCSPCache(5*time.Minute, OCSPFallbackAllow, nil, "en")
	leaf := makeOCSPTestCert(t, "http://ocsp.example.com/")
	if err := c.Check(leaf, nil); err != nil {
		t.Errorf("Check with nil issuer (fallback allow) should return nil, got: %v", err)
	}

	deny := NewOCSPCache(5*time.Minute, OCSPFallbackDeny, nil, "en")
	if err := deny.Check(leaf, nil); err == nil {
		t.Error("Check with nil issuer (fallback deny) should return an error")
	}
}

func TestOCSPFallbackStrings(t *testing.T) {
	if OCSPFallbackAllow != "allow" {
		t.Errorf("OCSPFallbackAllow = %q", OCSPFallbackAllow)
	}
	if OCSPFallbackDeny != "deny" {
		t.Errorf("OCSPFallbackDeny = %q", OCSPFallbackDeny)
	}
	if OCSPFallbackCRL != "crl" {
		t.Errorf("OCSPFallbackCRL = %q", OCSPFallbackCRL)
	}
}

// TestOCSPFallbackCRLConsultsCRL (finding 3): fallback=crl must actually consult
// the CRL and fail closed (revoked → error, unconfigured → error, not silently
// allow).
func TestOCSPFallbackCRLConsultsCRL(t *testing.T) {
	leaf := makeOCSPTestCert(t, "")

	t.Run("unconfigured checker fails closed", func(t *testing.T) {
		c := NewOCSPCache(5*time.Minute, OCSPFallbackCRL, nil, "en")
		if err := c.Check(leaf, nil); err == nil {
			t.Fatal("fallback=crl without a CRL checker must fail closed")
		}
	})

	t.Run("revoked cert rejected", func(t *testing.T) {
		c := NewOCSPCache(5*time.Minute, OCSPFallbackCRL, nil, "en")
		c.SetCRLChecker(func(caDN string, serial *big.Int) (bool, error) {
			return true, nil
		})
		if err := c.Check(leaf, nil); err == nil {
			t.Fatal("revoked cert must be rejected by the crl fallback")
		}
	})

	t.Run("crl error fails closed", func(t *testing.T) {
		c := NewOCSPCache(5*time.Minute, OCSPFallbackCRL, nil, "en")
		c.SetCRLChecker(func(caDN string, serial *big.Int) (bool, error) {
			return false, errors.New("CRL unavailable")
		})
		if err := c.Check(leaf, nil); err == nil {
			t.Fatal("CRL check failure must fail closed")
		}
	})

	t.Run("valid cert allowed", func(t *testing.T) {
		c := NewOCSPCache(5*time.Minute, OCSPFallbackCRL, nil, "en")
		c.SetCRLChecker(func(caDN string, serial *big.Int) (bool, error) {
			return false, nil
		})
		if err := c.Check(leaf, nil); err != nil {
			t.Fatalf("valid cert should pass crl fallback, got: %v", err)
		}
	})
}

// H2: concurrent Check calls for the same cert must coalesce into a single
// OCSP fetch (no stampede / double fetch). Before the single-lock fix two
// goroutines could both observe !inFlight and both fetch the same key.
func TestOCSPCoalesceSingleFetch(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "test-leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	var hits int64
	now := time.Now()
	respTmpl := ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: leafCert.SerialNumber,
		ThisUpdate:   now,
		NextUpdate:   now.Add(time.Hour),
		ProducedAt:   now,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		der, err := ocsp.CreateResponse(caCert, caCert, respTmpl, caKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Write(der)
	}))
	defer srv.Close()

	// embed OCSP URL into the leaf
	desc := accessDescription{
		Method: OCSPOID,
		Location: asn1.RawValue{
			Class: asn1.ClassContextSpecific,
			Tag:   6,
			Bytes: []byte(srv.URL),
		},
	}
	aiaBytes, _ := asn1.Marshal([]accessDescription{desc})
	leafCert.Extensions = []pkix.Extension{{Id: AIAOID, Value: aiaBytes}}

	cache := NewOCSPCache(time.Minute, OCSPFallbackDeny, nil, "en")

	const n = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := cache.Check(leafCert, caCert); err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if firstErr != nil {
		t.Fatalf("Check returned error: %v", firstErr)
	}
	got := atomic.LoadInt64(&hits)
	if got != 1 {
		t.Errorf("OCSP responder hit %d times, want exactly 1 (coalesced), %d concurrent callers", got, n)
	}
}

// TestOCSPFreshness (finding 7): a stale OCSP "Good" response (next_update in
// the past) must not be honored as valid.
func TestOCSPFreshness(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "test-leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	leafCert, _ := x509.ParseCertificate(leafDER)

	// Stale response: next_update already in the past.
	now := time.Now()
	respTmpl := ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: leafCert.SerialNumber,
		ThisUpdate:   now.Add(-2 * time.Hour),
		NextUpdate:   now.Add(-time.Hour),
		ProducedAt:   now.Add(-2 * time.Hour),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		der, err := ocsp.CreateResponse(caCert, caCert, respTmpl, caKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Write(der)
	}))
	defer srv.Close()

	desc := accessDescription{
		Method: OCSPOID,
		Location: asn1.RawValue{
			Class: asn1.ClassContextSpecific,
			Tag:   6,
			Bytes: []byte(srv.URL),
		},
	}
	aiaBytes, _ := asn1.Marshal([]accessDescription{desc})
	leafCert.Extensions = []pkix.Extension{{Id: AIAOID, Value: aiaBytes}}

	cache := NewOCSPCache(time.Minute, OCSPFallbackDeny, nil, "en")
	if err := cache.Check(leafCert, caCert); err == nil {
		t.Fatal("stale OCSP response must be rejected, not honored as valid")
	}
}
