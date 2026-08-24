package gw

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// makeChainCert generates a self-signed test certificate with the given CN.
func makeChainCert(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() % 1e9),
		Subject:      pkixName(cn),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{cn + ".example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// signDA signs the AIC's DelegationAuthTBS with signerKey, returning the AIC with DA populated.
// puKeyHash is the signer's SPKI hash (used for cross-validation); the SPKI hash of the signer certificate.
func signDA(t *testing.T, aic *AIC, signerKey *ecdsa.PrivateKey, signerCert *x509.Certificate) *AIC {
	t.Helper()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	spki := sha256.Sum256(signerCert.RawSubjectPublicKeyInfo)
	aic.PrincipalUid = PrincipalUid{
		Version:    1,
		Realm:      "test",
		Identifier: signerCert.Subject.CommonName,
		KeyHash:    spki[:],
		HashAlgo:   AlgorithmIdentifier{Algorithm: OIDSHA256},
	}
	tbs := DelegationAuthTBS{
		Version:           aic.Version,
		AgentId:           aic.AgentId,
		PrincipalUid:      aic.PrincipalUid,
		Reason:            Reason{ReasonCode: "DELEG", Description: "multi-level chain test"},
		Capabilities:      aic.Capabilities,
		DelegationMode:    aic.DelegationMode,
		RequestedLifetime: 3600,
		Timestamp:         time.Now(),
		Nonce:             nonce,
	}
	der, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(der)
	sig, err := ecdsa.SignASN1(rand.Reader, signerKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	aic.DelegationAuthorization = DelegationAuthorization{
		Reason:             Reason{ReasonCode: "DELEG", Description: "multi-level chain test"},
		RequestedLifetime:  3600,
		Timestamp:          time.Now(),
		Nonce:              nonce,
		SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		SignatureValue:     sig,
	}
	return aic
}

func TestVerifyDelegationChain_Valid(t *testing.T) {
	principal, principalKey := makeChainCert(t, "zhangsan")
	schedA, schedAKey := makeChainCert(t, "scheduler-a")
	workerB, _ := makeChainCert(t, "worker-b")

	// Worker-B's AIC: DA signed by Scheduler-A
	workerAIC := signDA(t, &AIC{Version: 1, AgentId: "worker-b"}, schedAKey, schedA)
	// Scheduler-A's AIC: DA signed by the top-level Principal
	schedAIC := signDA(t, &AIC{Version: 1, AgentId: "scheduler-a"}, principalKey, principal)

	// Compose certificates with AIC embedded in extensions
	workerCert := embedAIC(t, workerB, workerAIC)
	schedCert := embedAIC(t, schedA, schedAIC)

	chain := []*x509.Certificate{schedCert, workerCert}
	if err := VerifyDelegationChain(chain, principal, 2); err != nil {
		t.Fatalf("valid chain should pass, got: %v", err)
	}
}

func TestVerifyDelegationChain_ExceedsMaxDepth(t *testing.T) {
	principal, principalKey := makeChainCert(t, "zhangsan")
	schedA, schedAKey := makeChainCert(t, "scheduler-a")
	workerB, _ := makeChainCert(t, "worker-b")

	workerAIC := signDA(t, &AIC{Version: 1, AgentId: "worker-b"}, schedAKey, schedA)
	schedAIC := signDA(t, &AIC{Version: 1, AgentId: "scheduler-a"}, principalKey, principal)

	workerCert := embedAIC(t, workerB, workerAIC)
	schedCert := embedAIC(t, schedA, schedAIC)

	chain := []*x509.Certificate{schedCert, workerCert}
	if err := VerifyDelegationChain(chain, principal, 1); err == nil {
		t.Fatal("chain depth 2 with maxDepth 1 should be rejected")
	}
}

func TestVerifyDelegationChain_TamperedMiddle(t *testing.T) {
	principal, principalKey := makeChainCert(t, "zhangsan")
	schedA, _ := makeChainCert(t, "scheduler-a")
	workerB, _ := makeChainCert(t, "worker-b")
	intruder, intruderKey := makeChainCert(t, "intruder")

	// Worker-B's DA should be signed by Scheduler-A, but was forged by intruder
	workerAIC := signDA(t, &AIC{Version: 1, AgentId: "worker-b"}, intruderKey, intruder)
	schedAIC := signDA(t, &AIC{Version: 1, AgentId: "scheduler-a"}, principalKey, principal)

	workerCert := embedAIC(t, workerB, workerAIC)
	schedCert := embedAIC(t, schedA, schedAIC)

	chain := []*x509.Certificate{schedCert, workerCert}
	if err := VerifyDelegationChain(chain, principal, 2); err == nil {
		t.Fatal("tampered middle delegation should be rejected")
	}
}

func TestVerifyDelegationChain_TopMismatch(t *testing.T) {
	principal, _ := makeChainCert(t, "zhangsan")
	otherPrincipal, principalKey := makeChainCert(t, "lisi")
	schedA, schedAKey := makeChainCert(t, "scheduler-a")
	workerB, _ := makeChainCert(t, "worker-b")

	workerAIC := signDA(t, &AIC{Version: 1, AgentId: "worker-b"}, schedAKey, schedA)
	schedAIC := signDA(t, &AIC{Version: 1, AgentId: "scheduler-a"}, principalKey, otherPrincipal)

	workerCert := embedAIC(t, workerB, workerAIC)
	schedCert := embedAIC(t, schedA, schedAIC)

	chain := []*x509.Certificate{schedCert, workerCert}
	// Top-level certificate is zhangsan, but Scheduler-A's DA is signed by lisi → reject
	if err := VerifyDelegationChain(chain, principal, 2); err == nil {
		t.Fatal("top-level principal mismatch should be rejected")
	}
}

func TestVerifyDelegationChain_EmptyAndNil(t *testing.T) {
	principal, _ := makeChainCert(t, "zhangsan")
	if err := VerifyDelegationChain(nil, principal, 2); err == nil {
		t.Fatal("empty chain should fail")
	}
	if err := VerifyDelegationChain([]*x509.Certificate{principal}, nil, 2); err == nil {
		t.Fatal("nil top principal should fail")
	}
}

func TestEffectiveDelegationCapabilities_Example5(t *testing.T) {
	// Example 5 (P2-D-05): Zhangsan{P:database:*, job:*} → Scheduler-A{database:query, job:dispatch}
	// → Worker-B{database:query:SELECT}; C_eff = {database:query:SELECT}.
	principal, principalKey := makeChainCert(t, "zhangsan")
	schedA, schedAKey := makeChainCert(t, "scheduler-a")
	workerB, _ := makeChainCert(t, "worker-b")

	workerAIC := signDA(t, &AIC{
		Version:      1,
		AgentId:      "worker-b",
		Capabilities: []Capability{{SchemeId: "database", CapabilityId: "query:SELECT"}},
	}, schedAKey, schedA)
	schedAIC := signDA(t, &AIC{
		Version:      1,
		AgentId:      "scheduler-a",
		Capabilities: []Capability{{SchemeId: "database", CapabilityId: "query"}, {SchemeId: "job", CapabilityId: "dispatch"}},
	}, principalKey, principal)

	workerCert := embedAIC(t, workerB, workerAIC)
	schedCert := embedAIC(t, schedA, schedAIC)
	chain := []*x509.Certificate{schedCert, workerCert}

	principalCaps := []Capability{
		{SchemeId: "database", CapabilityId: "*"},
		{SchemeId: "job", CapabilityId: "*"},
	}
	eff, err := EffectiveDelegationCapabilities(chain, principalCaps, 0)
	if err != nil {
		t.Fatalf("EffectiveDelegationCapabilities: %v", err)
	}
	if len(eff) != 1 || eff[0].SchemeId != "database" || eff[0].CapabilityId != "query:SELECT" {
		t.Fatalf("C_eff = %+v, want [{database query:SELECT}]", eff)
	}
}

func TestEffectiveDelegationCapabilities_Escalation(t *testing.T) {
	// P1-B-16: subordinate declares capability exceeding superior's effective caps → reject (permissions only shrink).
	principal, principalKey := makeChainCert(t, "zhangsan")
	schedA, schedAKey := makeChainCert(t, "scheduler-a")
	workerB, _ := makeChainCert(t, "worker-b")

	// Scheduler-A only has database:query, but Worker-B demands database:admin → escalation.
	workerAIC := signDA(t, &AIC{
		Version:      1,
		AgentId:      "worker-b",
		Capabilities: []Capability{{SchemeId: "database", CapabilityId: "admin"}},
	}, schedAKey, schedA)
	schedAIC := signDA(t, &AIC{
		Version:      1,
		AgentId:      "scheduler-a",
		Capabilities: []Capability{{SchemeId: "database", CapabilityId: "query"}},
	}, principalKey, principal)

	workerCert := embedAIC(t, workerB, workerAIC)
	schedCert := embedAIC(t, schedA, schedAIC)
	chain := []*x509.Certificate{schedCert, workerCert}

	principalCaps := []Capability{{SchemeId: "database", CapabilityId: "*"}}
	if _, err := EffectiveDelegationCapabilities(chain, principalCaps, 0); err == nil {
		t.Fatal("capability escalation should be rejected")
	}
}

func TestEffectiveDelegationCapabilities_EmptyIntersection(t *testing.T) {
	// P1-B-17: C_eff is empty → reject entire chain.
	principal, principalKey := makeChainCert(t, "zhangsan")
	schedA, _ := makeChainCert(t, "scheduler-a")

	schedAIC := signDA(t, &AIC{
		Version:      1,
		AgentId:      "scheduler-a",
		Capabilities: []Capability{{SchemeId: "database", CapabilityId: "query"}},
	}, principalKey, principal)
	schedCert := embedAIC(t, schedA, schedAIC)
	chain := []*x509.Certificate{schedCert}

	// Principal only authorizes job:*, Scheduler-A only has database:query → intersection is empty.
	principalCaps := []Capability{{SchemeId: "job", CapabilityId: "*"}}
	if _, err := EffectiveDelegationCapabilities(chain, principalCaps, 0); err == nil {
		t.Fatal("empty C_eff should be rejected")
	}
}

func TestVerifyChainStructure_Cycle(t *testing.T) {
	// P1-B-14: duplicate serial number in chain (cycle) → reject.
	c1, _ := makeChainCert(t, "node-1")
	c2, _ := makeChainCert(t, "node-2")

	// Same certificate appears twice → cycle.
	chain := []*x509.Certificate{c1, c2, c1}
	if err := verifyChainStructure(chain, 0); err == nil {
		t.Fatal("duplicate node should be rejected as cycle")
	}

	// Normal chain should pass.
	chain2 := []*x509.Certificate{c1, c2}
	if err := verifyChainStructure(chain2, 0); err != nil {
		t.Fatalf("valid chain structure should pass: %v", err)
	}
}

func TestVerifyChainStructure_CertBomb(t *testing.T) {
	// P1-B-15: chain length exceeds maxChainLen → reject.
	certs := make([]*x509.Certificate, 0, 5)
	for i := 0; i < 5; i++ {
		c, _ := makeChainCert(t, "node")
		certs = append(certs, c)
	}
	if err := verifyChainStructure(certs, 3); err == nil {
		t.Fatal("chain longer than maxChainLen should be rejected")
	}
	if err := verifyChainStructure(certs, 0); err != nil {
		t.Fatalf("no limit should pass: %v", err)
	}
}

func TestVerifyDelegationChainWithCaps_Valid(t *testing.T) {
	principal, principalKey := makeChainCert(t, "zhangsan")
	schedA, schedAKey := makeChainCert(t, "scheduler-a")
	workerB, _ := makeChainCert(t, "worker-b")

	workerAIC := signDA(t, &AIC{
		Version:      1,
		AgentId:      "worker-b",
		Capabilities: []Capability{{SchemeId: "database", CapabilityId: "query:SELECT"}},
	}, schedAKey, schedA)
	schedAIC := signDA(t, &AIC{
		Version:      1,
		AgentId:      "scheduler-a",
		Capabilities: []Capability{{SchemeId: "database", CapabilityId: "query"}},
	}, principalKey, principal)

	workerCert := embedAIC(t, workerB, workerAIC)
	schedCert := embedAIC(t, schedA, schedAIC)
	chain := []*x509.Certificate{schedCert, workerCert}

	principalCaps := []Capability{{SchemeId: "database", CapabilityId: "*"}}
	eff, err := VerifyDelegationChainWithCaps(chain, principal, principalCaps, 2, 0)
	if err != nil {
		t.Fatalf("valid chain with caps should pass: %v", err)
	}
	if len(eff) != 1 || eff[0].CapabilityId != "query:SELECT" {
		t.Fatalf("C_eff = %+v, want [{database query:SELECT}]", eff)
	}
}

func TestVerifyDelegationChainWithCaps_EscalationRejects(t *testing.T) {
	principal, principalKey := makeChainCert(t, "zhangsan")
	schedA, schedAKey := makeChainCert(t, "scheduler-a")
	workerB, _ := makeChainCert(t, "worker-b")

	workerAIC := signDA(t, &AIC{
		Version:      1,
		AgentId:      "worker-b",
		Capabilities: []Capability{{SchemeId: "database", CapabilityId: "admin"}},
	}, schedAKey, schedA)
	schedAIC := signDA(t, &AIC{
		Version:      1,
		AgentId:      "scheduler-a",
		Capabilities: []Capability{{SchemeId: "database", CapabilityId: "query"}},
	}, principalKey, principal)

	workerCert := embedAIC(t, workerB, workerAIC)
	schedCert := embedAIC(t, schedA, schedAIC)
	chain := []*x509.Certificate{schedCert, workerCert}

	principalCaps := []Capability{{SchemeId: "database", CapabilityId: "*"}}
	if _, err := VerifyDelegationChainWithCaps(chain, principal, principalCaps, 2, 0); err == nil {
		t.Fatal("escalation should be rejected by full verification")
	}
}
