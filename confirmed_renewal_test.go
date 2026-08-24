package gw

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

func TestSignRenewalDA_Validation(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	req := &RenewalRequest{AgentId: "agent-1", CN: "svc"}

	t.Run("empty nonce", func(t *testing.T) {
		_, err := SignRenewalDA(req, key, nil, time.Now(), 3600, "RENEW", "renewal")
		if err == nil {
			t.Fatal("expected error for non-32-byte nonce")
		}
	})
	t.Run("zero lifetime", func(t *testing.T) {
		_, err := SignRenewalDA(req, key, make([]byte, 32), time.Now(), 0, "RENEW", "renewal")
		if err == nil {
			t.Fatal("expected error for zero lifetime")
		}
	})
	t.Run("nil request", func(t *testing.T) {
		_, err := SignRenewalDA(nil, key, make([]byte, 32), time.Now(), 3600, "RENEW", "renewal")
		if err == nil {
			t.Fatal("expected error for nil request")
		}
	})
}

func TestSignRenewalDA_RoundTrip(t *testing.T) {
	// Responsibility subject ECDSA P-256: sign → gateway verification passes
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert := makeEntityCert(t, &key.PublicKey)
	req := &RenewalRequest{
		SessionID:    "sess-123",
		AgentId:      "agent-1",
		PrincipalUid: "varwof:user@example.com:" + fp(key),
		CN:           "svc",
		Capabilities: []Capability{{SchemeId: "tcp", CapabilityId: "tunnel:prod"}},
	}
	nonce := make([]byte, 32)
	rand.Read(nonce)
	ts := time.Now().Add(-time.Minute)

	da, err := SignRenewalDA(req, key, nonce, ts, 7200, "RENEW", "agent renewal")
	if err != nil {
		t.Fatalf("SignRenewalDA: %v", err)
	}
	if len(da.SignatureValue) == 0 {
		t.Fatal("expected non-empty signature")
	}
	if len(da.Nonce) != 32 {
		t.Fatalf("nonce length %d", len(da.Nonce))
	}
	if !da.Timestamp.Equal(ts) {
		t.Fatalf("timestamp mismatch: %v != %v", da.Timestamp, ts)
	}

	if err := verifyRenewalDA(req, cert, da); err != nil {
		t.Fatalf("verifyRenewalDA: %v", err)
	}
}

func TestSignRenewalDA_RSA(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert := makeEntityCert(t, &key.PublicKey)
	req := &RenewalRequest{SessionID: "s", AgentId: "a", CN: "svc"}
	nonce := make([]byte, 32)
	rand.Read(nonce)
	da, err := SignRenewalDA(req, key, nonce, time.Now(), 3600, "RENEW", "r")
	if err != nil {
		t.Fatalf("SignRenewalDA(RSA): %v", err)
	}
	if err := verifyRenewalDA(req, cert, da); err != nil {
		t.Fatalf("verifyRenewalDA(RSA): %v", err)
	}
}

func TestConfirmedRenewalManager_HappyPath(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	principalCert := makeEntityCert(t, &key.PublicKey)
	req := &RenewalRequest{
		SessionID:    "sess-1",
		AgentId:      "agent-1",
		PrincipalUid: "varwof:user@example.com:" + fp(key),
		CN:           "svc",
		OldSerial:    "A1",
		Capabilities: []Capability{{SchemeId: "tcp", CapabilityId: "tunnel:prod"}},
	}

	issuedCb := false
	m := NewConfirmedRenewalManager(nil, nil, func(_ *x509.Certificate) { issuedCb = true })
	if err := m.RequestRenewal(req); err != nil {
		t.Fatalf("RequestRenewal: %v", err)
	}
	if m.State() != RenewalAwaitingConfirmation {
		t.Fatalf("state = %s, want awaiting_confirmation", m.State())
	}
	if m.CurrentSessionID() != "sess-1" {
		t.Fatalf("session id = %q", m.CurrentSessionID())
	}

	nonce := make([]byte, 32)
	rand.Read(nonce)
	da, err := SignRenewalDA(req, key, nonce, time.Now(), 3600, "RENEW", "confirm")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Confirm(&RenewalConfirmation{
		SessionID:     "sess-1",
		DA:            da,
		PrincipalCert: principalCert,
	}); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if m.State() != RenewalConfirmed {
		t.Fatalf("state = %s, want confirmed", m.State())
	}
	if issuedCb {
		t.Fatal("onIssued should not fire when issueCfg is nil")
	}
}

func TestConfirmedRenewalManager_SessionIDMismatch(t *testing.T) {
	m := NewConfirmedRenewalManager(nil, nil, nil)
	if err := m.RequestRenewal(&RenewalRequest{SessionID: "sess-1", CN: "svc"}); err != nil {
		t.Fatal(err)
	}
	_, err := m.Confirm(&RenewalConfirmation{SessionID: "sess-2", PrincipalCert: &x509.Certificate{}})
	if err == nil {
		t.Fatal("expected session mismatch error")
	}
	if m.State() != RenewalAwaitingConfirmation {
		t.Fatalf("state should stay awaiting on mismatch, got %s", m.State())
	}
}

func TestConfirmedRenewalManager_Reject(t *testing.T) {
	m := NewConfirmedRenewalManager(nil, nil, nil)
	if err := m.RequestRenewal(&RenewalRequest{SessionID: "s", CN: "svc"}); err != nil {
		t.Fatal(err)
	}
	m.Reject("principal declined")
	if m.State() != RenewalRejected {
		t.Fatalf("state = %s, want rejected", m.State())
	}
	if m.Reason() != "principal declined" {
		t.Fatalf("reason = %q", m.Reason())
	}
}

func TestConfirmedRenewalManager_Timeout(t *testing.T) {
	m := NewConfirmedRenewalManager(nil, nil, nil)
	m.SetTimeout(10 * time.Millisecond)
	if err := m.RequestRenewal(&RenewalRequest{SessionID: "s", CN: "svc"}); err != nil {
		t.Fatal(err)
	}
	m.now = func() time.Time { return time.Now().Add(time.Hour) }
	if m.State() != RenewalRejected {
		t.Fatalf("state = %s, want rejected (timeout)", m.State())
	}
}

func TestConfirmedRenewalManager_DuplicateRequest(t *testing.T) {
	m := NewConfirmedRenewalManager(nil, nil, nil)
	if err := m.RequestRenewal(&RenewalRequest{SessionID: "s", CN: "svc"}); err != nil {
		t.Fatal(err)
	}
	if err := m.RequestRenewal(&RenewalRequest{SessionID: "s2", CN: "svc2"}); err == nil {
		t.Fatal("expected duplicate request error while awaiting")
	}
}

func TestConfirmedRenewalManager_PermissionReduced(t *testing.T) {
	// Responsibility subject PA grants only database:query:SELECT, new declaration contains database:admin → reject
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pa := PrincipalAuthorization{
		Grants: []Capability{{SchemeId: "database", CapabilityId: "query:SELECT"}},
	}
	paVal, _ := asn1.Marshal(pa)
	principalCert := makeEntityCertWithExt(t, &key.PublicKey, oidPrincipalAuthorization, paVal)

	req := &RenewalRequest{
		SessionID:    "sess-perm",
		AgentId:      "agent-1",
		PrincipalUid: "varwof:user@example.com:" + fp(key),
		CN:           "svc",
		OldSerial:    "B2",
		Capabilities: []Capability{
			{SchemeId: "database", CapabilityId: "query:SELECT"},
			{SchemeId: "database", CapabilityId: "admin"}, // out of bounds
		},
	}

	m := NewConfirmedRenewalManager(nil, nil, nil)
	if err := m.RequestRenewal(req); err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 32)
	rand.Read(nonce)
	da, err := SignRenewalDA(req, key, nonce, time.Now(), 3600, "RENEW", "r")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Confirm(&RenewalConfirmation{
		SessionID:     "sess-perm",
		DA:            da,
		PrincipalCert: principalCert,
	}); err == nil {
		t.Fatal("expected permission-reduced rejection")
	}
	if m.State() != RenewalRejected {
		t.Fatalf("state = %s, want rejected", m.State())
	}
	if m.Reason() == "" {
		t.Fatal("expected rejection reason")
	}
}

func TestConfirmedRenewalManager_TransitionMark(t *testing.T) {
	// After successful confirmation, old cert is marked transition in ConnExpiryRegistry (renewed=true → connection close skips revocation)
	reg := NewConnExpiryRegistry()
	oldCert := &x509.Certificate{
		SerialNumber: big.NewInt(1234),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	reg.Register("04D2", oldCert) // 1234 hex = 4D2
	if reg.Renewed("04D2") {
		t.Fatal("should not be renewed initially")
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	principalCert := makeEntityCert(t, &key.PublicKey)
	req := &RenewalRequest{
		SessionID:    "sess-4",
		AgentId:      "agent-1",
		PrincipalUid: "varwof:user@example.com:" + fp(key),
		CN:           "svc",
		OldSerial:    "04D2",
		Capabilities: []Capability{{SchemeId: "tcp", CapabilityId: "tunnel:prod"}},
	}
	m := NewConfirmedRenewalManager(nil, reg, nil)
	if err := m.RequestRenewal(req); err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 32)
	rand.Read(nonce)
	da, _ := SignRenewalDA(req, key, nonce, time.Now(), 3600, "RENEW", "r")
	if _, err := m.Confirm(&RenewalConfirmation{SessionID: "sess-4", DA: da, PrincipalCert: principalCert}); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if !reg.Renewed("04D2") {
		t.Fatal("old cert should be marked transition (renewed=true)")
	}
	if !reg.ShouldSkipRevoke("04D2") {
		t.Fatal("old cert connection close should skip revoke")
	}
}

func TestConfirmedRenewalManager_Reset(t *testing.T) {
	m := NewConfirmedRenewalManager(nil, nil, nil)
	if err := m.RequestRenewal(&RenewalRequest{SessionID: "s", CN: "svc"}); err != nil {
		t.Fatal(err)
	}
	m.Reset()
	if m.State() != RenewalIdle {
		t.Fatalf("state = %s, want idle", m.State())
	}
}

// ---- helpers ----

func fp(key *ecdsa.PrivateKey) string {
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return ""
	}
	return KeyHashHex(&x509.Certificate{RawSubjectPublicKeyInfo: pubDER})
}

func makeEntityCert(t *testing.T, pub any) *x509.Certificate {
	return makeEntityCertWithExt(t, pub, nil, nil)
}

func makeEntityCertWithExt(t *testing.T, pub any, oid asn1.ObjectIdentifier, extVal []byte) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "principal"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{"principal"},
	}
	if oid != nil {
		tmpl.ExtraExtensions = []pkix.Extension{{Id: oid, Value: extVal}}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert
}
