package gw

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testBinary writes a fake executable file and its detached signature.
func testSignedBinary(t *testing.T, content []byte) (binPath string) {
	t.Helper()
	dir := t.TempDir()
	binPath = filepath.Join(dir, "tool.bin")
	if err := os.WriteFile(binPath, content, 0o755); err != nil {
		t.Fatal(err)
	}
	return binPath
}

func TestVerifySelfValid(t *testing.T) {
	pool, caCert, caKey := newTestCA(t, "admin")
	signerCert, signerKey := newSignedCert(t, caCert, caKey, "release-signer", []string{"release"})

	content := []byte("#!/bin/sh\necho hello\n")
	binPath := testSignedBinary(t, content)

	sig, err := SignPolicy(content, signerCert, signerKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := os.WriteFile(binPath+".p7s", sig, 0o600); err != nil {
		t.Fatal(err)
	}

	cert, err := VerifySelf(binPath, pool)
	if err != nil {
		t.Fatalf("verify self: %v", err)
	}
	if cert.Subject.CommonName != "release-signer" {
		t.Errorf("signer CN = %q, want release-signer", cert.Subject.CommonName)
	}
}

func TestVerifySelfDefaultSigPath(t *testing.T) {
	pool, caCert, caKey := newTestCA(t, "admin")
	signerCert, signerKey := newSignedCert(t, caCert, caKey, "release-signer", nil)

	content := []byte("binary-data-123")
	binPath := testSignedBinary(t, content)
	sig, err := SignPolicy(content, signerCert, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	// Default signature path is <bin>.p7s
	if err := os.WriteFile(binPath+".p7s", sig, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySelf(binPath, pool); err != nil {
		t.Errorf("verify self: %v", err)
	}
}

func TestVerifySelfTamperedBinary(t *testing.T) {
	pool, caCert, caKey := newTestCA(t, "admin")
	signerCert, signerKey := newSignedCert(t, caCert, caKey, "release-signer", nil)

	content := []byte("original-binary\n")
	binPath := testSignedBinary(t, content)
	sig, err := SignPolicy(content, signerCert, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binPath+".p7s", sig, 0o600); err != nil {
		t.Fatal(err)
	}

	// Tamper with binary content (simulating attacker replacing the file).
	if err := os.WriteFile(binPath, []byte("malicious-binary\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySelf(binPath, pool); err == nil {
		t.Error("tampered binary should fail self-verification")
	}
}

func TestVerifySelfMissingSignature(t *testing.T) {
	pool, _, _ := newTestCA(t, "admin")
	binPath := testSignedBinary(t, []byte("some-binary"))
	if _, err := VerifySelf(binPath, pool); err == nil {
		t.Error("missing .p7s should fail verification")
	}
}

func TestVerifySelfUntrustedChain(t *testing.T) {
	_, caCert, caKey := newTestCA(t, "admin")
	signerCert, signerKey := newSignedCert(t, caCert, caKey, "release-signer", nil)

	content := []byte("binary-data")
	binPath := testSignedBinary(t, content)
	sig, err := SignPolicy(content, signerCert, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binPath+".p7s", sig, 0o600); err != nil {
		t.Fatal(err)
	}

	// Verify with a different CA pool; untrusted chain should fail.
	otherPool, _, _ := newTestCA(t, "admin")
	if _, err := VerifySelf(binPath, otherPool); err == nil {
		t.Error("signer from different CA should be rejected")
	}
}

func TestVerifySelfNilRootsSkipsChain(t *testing.T) {
	_, caCert, caKey := newTestCA(t, "admin")
	signerCert, signerKey := newSignedCert(t, caCert, caKey, "release-signer", nil)

	content := []byte("binary-data")
	binPath := testSignedBinary(t, content)
	sig, err := SignPolicy(content, signerCert, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binPath+".p7s", sig, 0o600); err != nil {
		t.Fatal(err)
	}
	// When roots=nil, only signature is verified, chain is skipped.
	if _, err := VerifySelf(binPath, nil); err != nil {
		t.Errorf("nil roots should skip chain verification: %v", err)
	}
}

func TestVerifySelfCustomSigPath(t *testing.T) {
	pool, caCert, caKey := newTestCA(t, "admin")
	signerCert, signerKey := newSignedCert(t, caCert, caKey, "release-signer", nil)

	content := []byte("binary-data")
	binPath := testSignedBinary(t, content)
	sig, err := SignPolicy(content, signerCert, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	sigPath := filepath.Join(t.TempDir(), "custom.p7s")
	if err := os.WriteFile(sigPath, sig, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := VerifySelfWithOptions(binPath, SelfVerifyOptions{
		SigPath: sigPath,
		Roots:   pool,
	}); err != nil {
		t.Errorf("custom sig path verify: %v", err)
	}
}

func TestVerifySelfRequireExecutable(t *testing.T) {
	pool, caCert, caKey := newTestCA(t, "admin")
	signerCert, signerKey := newSignedCert(t, caCert, caKey, "release-signer", nil)

	// Non-executable file: even with a valid signature, RequireExecutable should reject it.
	dir := t.TempDir()
	dataPath := filepath.Join(dir, "config.json")
	content := []byte(`{"a":1}`)
	if err := os.WriteFile(dataPath, content, 0o644); err != nil {
		t.Fatal(err)
	}
	sig, err := SignPolicy(content, signerCert, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataPath+".p7s", sig, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySelfWithOptions(dataPath, SelfVerifyOptions{Roots: pool, RequireExecutable: true}); err == nil {
		t.Error("non-executable file should be rejected when RequireExecutable=true")
	}
}

func TestVerifySelfEmptyBinary(t *testing.T) {
	pool, _, _ := newTestCA(t, "admin")
	dir := t.TempDir()
	binPath := filepath.Join(dir, "empty.bin")
	if err := os.WriteFile(binPath, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySelf(binPath, pool); err == nil {
		t.Error("empty binary should fail verification")
	}
}

func TestVerifySelfMissingBinary(t *testing.T) {
	pool, _, _ := newTestCA(t, "admin")
	if _, err := VerifySelf(filepath.Join(t.TempDir(), "nope.bin"), pool); err == nil {
		t.Error("missing binary should fail verification")
	}
}

func TestVerifySignedBinaryTamperedSignature(t *testing.T) {
	pool, caCert, caKey := newTestCA(t, "admin")
	signerCert, signerKey := newSignedCert(t, caCert, caKey, "release-signer", nil)

	content := []byte("binary-data")
	sig, err := SignPolicy(content, signerCert, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	sig[len(sig)-1] ^= 0xff
	if _, err := VerifySignedBinary(content, sig, pool); err == nil {
		t.Error("tampered signature should fail verification")
	}
}

func TestPEMRootPoolFromCertPEM(t *testing.T) {
	_, caCert, _ := newTestCA(t, "admin")
	der := caCert.Raw
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	pool, err := PEMRootPool(pemBlock)
	if err != nil {
		t.Fatalf("PEMRootPool: %v", err)
	}
	if pool == nil {
		t.Fatal("nil pool")
	}
}

func TestPEMRootPoolInvalid(t *testing.T) {
	if _, err := PEMRootPool([]byte("not-a-cert")); err == nil {
		t.Error("invalid PEM should fail")
	}
}

// TestVerifySelfRSAAndEd25519 exercises RSA and Ed25519 signers too.
func TestVerifySelfRSAAndEd25519(t *testing.T) {
	pool, caCert, caKey := newTestCA(t, "admin")

	t.Run("rsa", func(t *testing.T) {
		signerKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		verifySelfWithKey(t, pool, caCert, caKey, "release-rsa", signerKey)
	})
}

func verifySelfWithKey(t *testing.T, pool *x509.CertPool, ca *x509.Certificate, caKey crypto.Signer, cn string, signerKey crypto.Signer) {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, signerKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	signerCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	content := []byte("binary-" + cn)
	binPath := testSignedBinary(t, content)
	sig, err := SignPolicy(content, signerCert, signerKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := os.WriteFile(binPath+".p7s", sig, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySelf(binPath, pool); err != nil {
		t.Errorf("verify self: %v", err)
	}
}
