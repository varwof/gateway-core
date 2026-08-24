package gw

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// testBundleCA generates a test CA (trust root) + intermediate chain signing.
type testBundlePKI struct {
	root    *x509.Certificate
	rootKey *rsa.PrivateKey
	pool    *x509.CertPool
}

func newTestBundlePKI(t *testing.T) *testBundlePKI {
	t.Helper()
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	root, _ := x509.ParseCertificate(rootDER)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return &testBundlePKI{root: root, rootKey: rootKey, pool: pool}
}

// issueLeaf issues a client certificate from the root CA (with specified extensions).
func (p *testBundlePKI) issueLeaf(t *testing.T, cn string, serial int64, exts []pkix.Extension) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(serial),
		Subject:         pkix.Name{CommonName: cn},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: exts,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.root, &key.PublicKey, p.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert
}

// bundleAIC constructs an AIC (KeyHash points to the principal's public key SPKI).
func bundleAIC(principal *x509.Certificate, agentId string) AIC {
	spki := sha256.Sum256(principal.RawSubjectPublicKeyInfo)
	return AIC{
		Version: 1,
		AgentId: agentId,
		PrincipalUid: PrincipalUid{
			Version:    1,
			Realm:      "varwof",
			Identifier: "user@varwof.com",
			KeyHash:    spki[:],
			HashAlgo:   AlgorithmIdentifier{Algorithm: OIDSHA256},
		},
		DelegationAuthorization: DelegationAuthorization{
			Reason:             Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
}

// paExt constructs a PA extension.
func paExt() pkix.Extension {
	pa := PrincipalAuthorization{Grants: []Capability{{SchemeId: "report", CapabilityId: "list"}}}
	val, _ := asn1.Marshal(pa)
	return pkix.Extension{Id: oidUserPermission, Value: val}
}

func TestVerifyBundle_Valid(t *testing.T) {
	pki := newTestBundlePKI(t)
	// Principal certificate (with PA)
	principal := pki.issueLeaf(t, "principal", 10, []pkix.Extension{paExt()})
	// Agent certificate (with AIC, KeyHash = principal SPKI)
	agent := pki.issueLeaf(t, "agent", 20, []pkix.Extension{func() pkix.Extension {
		aic := bundleAIC(principal, "agent-1")
		val, _ := asn1.Marshal(aic)
		return pkix.Extension{Id: oidAIC, Value: val}
	}()})

	bundle, err := NewCredentialBundle([]*x509.Certificate{agent}, []*x509.Certificate{principal}, []*x509.Certificate{pki.root})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(bundle, pki.pool); err != nil {
		t.Fatalf("valid bundle should verify: %v", err)
	}
}

func TestVerifyBundle_MissingPrincipalChain(t *testing.T) {
	pki := newTestBundlePKI(t)
	principal := pki.issueLeaf(t, "principal", 10, []pkix.Extension{paExt()})
	agent := pki.issueLeaf(t, "agent", 20, []pkix.Extension{func() pkix.Extension {
		aic := bundleAIC(principal, "agent-1")
		val, _ := asn1.Marshal(aic)
		return pkix.Extension{Id: oidAIC, Value: val}
	}()})

	// Principal chain is empty → NewCredentialBundle rejects.
	if _, err := NewCredentialBundle([]*x509.Certificate{agent}, nil, []*x509.Certificate{pki.root}); err == nil {
		t.Fatal("missing principal chain should be rejected at construction")
	}
	// Directly construct empty chain → VerifyBundle rejects (Fail-Close).
	bundle := &CredentialBundle{AgentChain: []*x509.Certificate{agent}}
	if err := VerifyBundle(bundle, pki.pool); err == nil {
		t.Fatal("empty principal chain should fail verification")
	}
}

func TestVerifyBundle_KeyHashMismatch(t *testing.T) {
	pki := newTestBundlePKI(t)
	principal := pki.issueLeaf(t, "principal", 10, []pkix.Extension{paExt()})
	// Another principal (does not match AIC keyHash)
	otherPrincipal := pki.issueLeaf(t, "other", 11, []pkix.Extension{paExt()})
	agent := pki.issueLeaf(t, "agent", 20, []pkix.Extension{func() pkix.Extension {
		aic := bundleAIC(otherPrincipal, "agent-1")
		val, _ := asn1.Marshal(aic)
		return pkix.Extension{Id: oidAIC, Value: val}
	}()})

	bundle := &CredentialBundle{
		AgentChain:     []*x509.Certificate{agent},
		PrincipalChain: []*x509.Certificate{principal},
		CACerts:        []*x509.Certificate{pki.root},
	}
	if err := VerifyBundle(bundle, pki.pool); err == nil {
		t.Fatal("principal SPKI mismatch with AIC keyHash should fail")
	}
}

func TestVerifyBundle_DifferentTrustRoots(t *testing.T) {
	pkiA := newTestBundlePKI(t)
	pkiB := newTestBundlePKI(t)
	// Agent issued by root A, principal issued by root B (different trust roots)
	principal := pkiB.issueLeaf(t, "principal", 10, []pkix.Extension{paExt()})
	agent := pkiA.issueLeaf(t, "agent", 20, []pkix.Extension{func() pkix.Extension {
		aic := bundleAIC(principal, "agent-1")
		val, _ := asn1.Marshal(aic)
		return pkix.Extension{Id: oidAIC, Value: val}
	}()})

	// Both chains should anchor to the same trust root: verifying with pkiA.pool → principal chain fails.
	bundle := &CredentialBundle{
		AgentChain:     []*x509.Certificate{agent},
		PrincipalChain: []*x509.Certificate{principal},
		CACerts:        []*x509.Certificate{pkiA.root},
	}
	if err := VerifyBundle(bundle, pkiA.pool); err == nil {
		t.Fatal("principal chain to different trust root should fail")
	}
}

func TestVerifyPrincipalKeyHash(t *testing.T) {
	pki := newTestBundlePKI(t)
	principal := pki.issueLeaf(t, "principal", 10, []pkix.Extension{paExt()})

	t.Run("match", func(t *testing.T) {
		agent := pki.issueLeaf(t, "agent", 20, []pkix.Extension{func() pkix.Extension {
			aic := bundleAIC(principal, "agent-1")
			val, _ := asn1.Marshal(aic)
			return pkix.Extension{Id: oidAIC, Value: val}
		}()})
		if err := VerifyPrincipalKeyHash(agent, principal); err != nil {
			t.Fatalf("matching keyHash should pass: %v", err)
		}
	})

	t.Run("mismatch", func(t *testing.T) {
		other := pki.issueLeaf(t, "other", 30, nil)
		agent := pki.issueLeaf(t, "agent", 20, []pkix.Extension{func() pkix.Extension {
			aic := bundleAIC(principal, "agent-1")
			val, _ := asn1.Marshal(aic)
			return pkix.Extension{Id: oidAIC, Value: val}
		}()})
		if err := VerifyPrincipalKeyHash(agent, other); err == nil {
			t.Fatal("mismatch should fail")
		}
	})

	t.Run("nil inputs", func(t *testing.T) {
		if err := VerifyPrincipalKeyHash(nil, principal); err == nil {
			t.Fatal("nil agent should fail")
		}
		if err := VerifyPrincipalKeyHash(&x509.Certificate{}, nil); err == nil {
			t.Fatal("nil principal should fail")
		}
	})
}

func TestParseCredentialBundlePEM(t *testing.T) {
	pki := newTestBundlePKI(t)
	principal := pki.issueLeaf(t, "principal", 10, []pkix.Extension{paExt()})
	agent := pki.issueLeaf(t, "agent", 20, []pkix.Extension{func() pkix.Extension {
		aic := bundleAIC(principal, "agent-1")
		val, _ := asn1.Marshal(aic)
		return pkix.Extension{Id: oidAIC, Value: val}
	}()})

	// PEM order: Agent chain first, principal second, CA last.
	pem := certToPEM(agent) + certToPEM(principal) + certToPEM(pki.root)
	bundle, err := ParseCredentialBundlePEM([]byte(pem))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if bundle.Agent() == nil || bundle.Agent().Subject.CommonName != "agent" {
		t.Fatal("agent not identified")
	}
	if bundle.Principal() == nil || bundle.Principal().Subject.CommonName != "principal" {
		t.Fatal("principal not identified")
	}
	if len(bundle.CACerts) != 1 {
		t.Fatalf("CA certs = %d, want 1", len(bundle.CACerts))
	}
	// Parsed bundle can still pass dual-chain verification.
	if err := VerifyBundle(bundle, pki.pool); err != nil {
		t.Fatalf("parsed bundle should verify: %v", err)
	}
}

// certToPEM encodes a certificate to PEM.
func certToPEM(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}
