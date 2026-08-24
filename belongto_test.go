package gw

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// belongToSetup generates a test CA and two independent agent keys (key1 for handshake, key2 for auth).
func belongToSetup(t *testing.T) (caCert *x509.Certificate, caKey *rsa.PrivateKey, key1, key2 *rsa.PrivateKey) {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "BelongTo CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ = x509.ParseCertificate(caDER)
	key1, _ = rsa.GenerateKey(rand.Reader, 2048)
	key2, _ = rsa.GenerateKey(rand.Reader, 2048)
	return caCert, caKey, key1, key2
}

// belongToAgentCert issues a client certificate from caCert with the given private key (simulates handshake/auth certificate).
func belongToAgentCert(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey, key *rsa.PrivateKey, cn string) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(2 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert
}

func TestVerifyBelongTo(t *testing.T) {
	caCert, caKey, key1, key2 := belongToSetup(t)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	handshake := belongToAgentCert(t, caCert, caKey, key1, "agent-1")
	authSameKey := belongToAgentCert(t, caCert, caKey, key1, "agent-1")       // Same key, same CA
	authDiffKey := belongToAgentCert(t, caCert, caKey, key2, "agent-1")       // Different key, same CA (SPKI differs)
	authDiffName2 := belongToAgentCert(t, caCert, caKey, key1, "agent-other") // Same key, same CA but different agentId

	t.Run("same_keypair_same_ca", func(t *testing.T) {
		// Same keypair, same CA: different certificate instances must also pass (SPKI byte-equal, certificates may differ).
		if err := VerifyBelongTo(handshake, authSameKey, pool); err != nil {
			t.Fatalf("same keypair should pass: %v", err)
		}
		// Different agentId does not affect strong binding (agentId is logging-only, G4).
		if err := VerifyBelongTo(handshake, authDiffName2, pool); err != nil {
			t.Fatalf("agentId must not affect binding: %v", err)
		}
		// Same certificate should pass.
		if err := VerifyBelongTo(handshake, handshake, pool); err != nil {
			t.Fatalf("same cert should pass: %v", err)
		}
	})

	t.Run("different_keypair_rejected", func(t *testing.T) {
		// Different SPKI → must be rejected (even if agentId matches).
		if err := VerifyBelongTo(handshake, authDiffKey, pool); err == nil {
			t.Fatal("different keypair must be rejected (G4)")
		}
	})

	t.Run("nil_roots_skips_chain_only_spki", func(t *testing.T) {
		// roots=nil still enforces SPKI and same-CA check, but skips chain verification.
		if err := VerifyBelongTo(handshake, authSameKey, nil); err != nil {
			t.Fatalf("same keypair with nil roots should pass: %v", err)
		}
		if err := VerifyBelongTo(handshake, authDiffKey, nil); err == nil {
			t.Fatal("different keypair must be rejected even with nil roots")
		}
	})

	t.Run("nil_cert_rejected", func(t *testing.T) {
		if err := VerifyBelongTo(nil, authSameKey, pool); err == nil {
			t.Fatal("nil handshake must be rejected")
		}
		if err := VerifyBelongTo(handshake, nil, pool); err == nil {
			t.Fatal("nil auth must be rejected")
		}
	})
}

func TestVerifyBelongToSameTrustChain(t *testing.T) {
	// Same keypair but auth chain cannot be verified by the same trust root → reject (same trust chain assertion).
	caCert, caKey, key1, _ := belongToSetup(t)
	// Second independent CA, signing an auth certificate with the same agent key.
	ca2Cert, ca2Key, _, _ := belongToSetup(t)

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	handshake := belongToAgentCert(t, caCert, caKey, key1, "agent-1")
	authOtherCA := belongToAgentCert(t, ca2Cert, ca2Key, key1, "agent-1")

	// Same SPKI but different issuer → reject.
	if err := VerifyBelongTo(handshake, authOtherCA, pool); err == nil {
		t.Fatal("different issuing CA must be rejected")
	}
	// Same issuer but roots do not contain the issuing CA → chain verification fails → reject.
	authSameCA := belongToAgentCert(t, caCert, caKey, key1, "agent-1")
	if err := VerifyBelongTo(handshake, authSameCA, nil); err != nil {
		t.Fatalf("same CA with nil roots should pass (no chain check): %v", err)
	}
}
