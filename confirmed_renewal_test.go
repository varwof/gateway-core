// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
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

// TestConfirmedRenewalManager_ExpiredPrincipalCert (finding 1): an expired
// responsible-party certificate must never confirm a renewal.
func TestConfirmedRenewalManager_ExpiredPrincipalCert(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	expiredCert := &x509.Certificate{
		SerialNumber:            big.NewInt(7),
		Subject:                 pkix.Name{CommonName: "principal"},
		NotBefore:               time.Now().Add(-48 * time.Hour),
		NotAfter:                time.Now().Add(-24 * time.Hour),
		RawSubjectPublicKeyInfo: pubDER,
	}

	req := &RenewalRequest{SessionID: "sess-x", AgentId: "a", CN: "svc"}
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
	if _, err := m.Confirm(&RenewalConfirmation{SessionID: "sess-x", DA: da, PrincipalCert: expiredCert}); err == nil {
		t.Fatal("expected rejection of expired responsible party certificate")
	}
	if m.State() != RenewalRejected {
		t.Fatalf("state = %s, want rejected", m.State())
	}
}

// TestConfirmedRenewalManager_VerifyPrincipalRejectsSelfSigned (finding 1): with
// a trust-anchor verifier installed, a self-signed attacker cert must be rejected
// even though it signs a valid DA.
func TestConfirmedRenewalManager_VerifyPrincipalRejectsSelfSigned(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	principalCert := makeEntityCert(t, &key.PublicKey)
	req := &RenewalRequest{SessionID: "sess-v", AgentId: "a", CN: "svc"}
	m := NewConfirmedRenewalManager(nil, nil, nil)
	m.SetPrincipalCertVerifier(func(cert *x509.Certificate) error {
		return errors.New("not issued by a trusted identity anchor")
	})
	if err := m.RequestRenewal(req); err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 32)
	rand.Read(nonce)
	da, err := SignRenewalDA(req, key, nonce, time.Now(), 3600, "RENEW", "r")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Confirm(&RenewalConfirmation{SessionID: "sess-v", DA: da, PrincipalCert: principalCert}); err == nil {
		t.Fatal("expected rejection when principal cert verifier rejects the certificate")
	}
}

// TestConfirmedRenewalManager_NoVerifierFailsClosedOnIssue (finding 1): when the
// manager is configured to issue new certificates, a missing responsible-party
// verifier must fail closed instead of issuing on an attacker-supplied cert.
func TestConfirmedRenewalManager_NoVerifierFailsClosedOnIssue(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	principalCert := makeEntityCert(t, &key.PublicKey)
	req := &RenewalRequest{SessionID: "sess-i", AgentId: "a", CN: "svc", Capabilities: []Capability{{SchemeId: "tcp", CapabilityId: "tunnel:prod"}}}
	m := NewConfirmedRenewalManager(&IssueConfig{DefaultCA: "test-ca"}, nil, nil)
	if err := m.RequestRenewal(req); err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 32)
	rand.Read(nonce)
	da, err := SignRenewalDA(req, key, nonce, time.Now(), 3600, "RENEW", "r")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Confirm(&RenewalConfirmation{SessionID: "sess-i", DA: da, PrincipalCert: principalCert}); err == nil {
		t.Fatal("expected fail-closed rejection when issuing without a principal cert verifier")
	}
}

// TestConfirmedRenewalManager_UnboundedCapsFailClosedOnIssue (finding 1): without
// PA grants or an old-certificate bound, issuing a renewal must be refused.
func TestConfirmedRenewalManager_UnboundedCapsFailClosedOnIssue(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	principalCert := makeEntityCert(t, &key.PublicKey)
	req := &RenewalRequest{SessionID: "sess-u", AgentId: "a", CN: "svc", Capabilities: []Capability{{SchemeId: "database", CapabilityId: "admin"}}}
	m := NewConfirmedRenewalManager(&IssueConfig{DefaultCA: "test-ca"}, nil, nil)
	m.SetPrincipalCertVerifier(func(_ *x509.Certificate) error { return nil }) // cert trusted, caps still unbounded
	if err := m.RequestRenewal(req); err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 32)
	rand.Read(nonce)
	da, err := SignRenewalDA(req, key, nonce, time.Now(), 3600, "RENEW", "r")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Confirm(&RenewalConfirmation{SessionID: "sess-u", DA: da, PrincipalCert: principalCert}); err == nil {
		t.Fatal("expected rejection for unbounded renewal capabilities")
	}
	if m.State() != RenewalRejected {
		t.Fatalf("state = %s, want rejected", m.State())
	}
}

// TestConfirmedRenewalManager_TwoPartyControl (finding 2): the entity that
// requested a renewal must not be able to confirm it.
func TestConfirmedRenewalManager_TwoPartyControl(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	principalCert := makeEntityCert(t, &key.PublicKey)
	req := &RenewalRequest{
		SessionID:        "sess-2p",
		AgentId:          "agent-1",
		PrincipalUid:     "varwof:user@example.com:" + fp(key),
		CN:               "svc",
		RequesterKeyHash: KeyHashHex(principalCert), // requester == responsible party
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
	if _, err := m.Confirm(&RenewalConfirmation{SessionID: "sess-2p", DA: da, PrincipalCert: principalCert}); err == nil {
		t.Fatal("expected two-party-control rejection when requester confirms its own renewal")
	}
	if m.State() != RenewalRejected {
		t.Fatalf("state = %s, want rejected", m.State())
	}

	// A different responsible party may confirm.
	key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	principalCert2 := makeEntityCert(t, &key2.PublicKey)
	req2 := &RenewalRequest{
		SessionID:        "sess-2p2",
		AgentId:          "agent-1",
		CN:               "svc",
		RequesterKeyHash: KeyHashHex(principalCert),
	}
	if err := m.RequestRenewal(req2); err != nil {
		t.Fatal(err)
	}
	nonce2 := make([]byte, 32)
	rand.Read(nonce2)
	da2, err := SignRenewalDA(req2, key2, nonce2, time.Now(), 3600, "RENEW", "r")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Confirm(&RenewalConfirmation{SessionID: "sess-2p2", DA: da2, PrincipalCert: principalCert2}); err != nil {
		t.Fatalf("different responsible party should confirm: %v", err)
	}
}

// TestConfirmedRenewalManager_RevokedOldCertFailsClosed (finding 4): a revoked
// old certificate must not be renewable into a fresh valid cert.
func TestConfirmedRenewalManager_RevokedOldCertFailsClosed(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	principalCert := makeEntityCert(t, &key.PublicKey)
	req := &RenewalRequest{
		SessionID:    "sess-rv",
		AgentId:      "agent-1",
		CN:           "svc",
		OldSerial:    "0A",
		Capabilities: []Capability{{SchemeId: "tcp", CapabilityId: "tunnel:prod"}},
	}
	m := NewConfirmedRenewalManager(&IssueConfig{DefaultCA: "test-ca"}, nil, nil)
	m.SetPrincipalCertVerifier(func(_ *x509.Certificate) error { return nil })
	m.SetOldCertVerifier(func(serial string, oldCert *x509.Certificate) error {
		return errors.New("old certificate 0A is revoked")
	})
	if err := m.RequestRenewal(req); err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 32)
	rand.Read(nonce)
	da, err := SignRenewalDA(req, key, nonce, time.Now(), 3600, "RENEW", "r")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Confirm(&RenewalConfirmation{SessionID: "sess-rv", DA: da, PrincipalCert: principalCert}); err == nil {
		t.Fatal("expected rejection when old certificate is revoked")
	}
	if m.State() != RenewalRejected {
		t.Fatalf("state = %s, want rejected", m.State())
	}
}

// TestConfirmedRenewalManager_NoOldCertVerifierFailsClosed (finding 4): issuing
// a renewal without an old-cert revocation verifier must fail closed.
func TestConfirmedRenewalManager_NoOldCertVerifierFailsClosed(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	principalCert := makeEntityCert(t, &key.PublicKey)
	req := &RenewalRequest{
		SessionID:    "sess-nv",
		AgentId:      "agent-1",
		CN:           "svc",
		OldSerial:    "0B",
		Capabilities: []Capability{{SchemeId: "tcp", CapabilityId: "tunnel:prod"}},
	}
	m := NewConfirmedRenewalManager(&IssueConfig{DefaultCA: "test-ca"}, nil, nil)
	m.SetPrincipalCertVerifier(func(_ *x509.Certificate) error { return nil })
	if err := m.RequestRenewal(req); err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 32)
	rand.Read(nonce)
	da, err := SignRenewalDA(req, key, nonce, time.Now(), 3600, "RENEW", "r")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Confirm(&RenewalConfirmation{SessionID: "sess-nv", DA: da, PrincipalCert: principalCert}); err == nil {
		t.Fatal("expected fail-closed rejection when old-cert verifier is unconfigured")
	}
}

// TestConfirmedRenewalManager_StaleDARejected (finding 10): a renewal DA with a
// stale timestamp must be rejected.
func TestConfirmedRenewalManager_StaleDARejected(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	principalCert := makeEntityCert(t, &key.PublicKey)
	req := &RenewalRequest{SessionID: "sess-st", AgentId: "a", CN: "svc"}
	m := NewConfirmedRenewalManager(nil, nil, nil)
	if err := m.RequestRenewal(req); err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 32)
	rand.Read(nonce)
	da, err := SignRenewalDA(req, key, nonce, time.Now().Add(-time.Hour), 3600, "RENEW", "r")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Confirm(&RenewalConfirmation{SessionID: "sess-st", DA: da, PrincipalCert: principalCert}); err == nil {
		t.Fatal("expected rejection of stale renewal DA")
	}
	if m.State() != RenewalRejected {
		t.Fatalf("state = %s, want rejected", m.State())
	}
}

// TestConfirmedRenewalManager_ExcessiveLifetimeRejected (finding 10): a renewal
// DA requesting an unbounded lifetime must be rejected.
func TestConfirmedRenewalManager_ExcessiveLifetimeRejected(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	principalCert := makeEntityCert(t, &key.PublicKey)
	req := &RenewalRequest{SessionID: "sess-lt", AgentId: "a", CN: "svc"}
	m := NewConfirmedRenewalManager(nil, nil, nil)
	if err := m.RequestRenewal(req); err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 32)
	rand.Read(nonce)
	// 30 days — far beyond the 24h default cap.
	da, err := SignRenewalDA(req, key, nonce, time.Now(), 30*24*3600, "RENEW", "r")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Confirm(&RenewalConfirmation{SessionID: "sess-lt", DA: da, PrincipalCert: principalCert}); err == nil {
		t.Fatal("expected rejection of excessive requested lifetime")
	}
	if m.State() != RenewalRejected {
		t.Fatalf("state = %s, want rejected", m.State())
	}
}

// TestConfirmedRenewalManager_DANonceReplay (finding 10): a renewal DA nonce
// must be single-use.
func TestConfirmedRenewalManager_DANonceReplay(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	principalCert := makeEntityCert(t, &key.PublicKey)
	req := &RenewalRequest{SessionID: "sess-rp", AgentId: "a", CN: "svc"}
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
	conf := &RenewalConfirmation{SessionID: "sess-rp", DA: da, PrincipalCert: principalCert}
	if _, err := m.Confirm(conf); err != nil {
		t.Fatalf("first confirm should succeed: %v", err)
	}
	m.Reset()

	// Replay the exact same DA against a fresh request.
	req2 := &RenewalRequest{SessionID: "sess-rp2", AgentId: "a", CN: "svc"}
	if err := m.RequestRenewal(req2); err != nil {
		t.Fatal(err)
	}
	conf2 := &RenewalConfirmation{SessionID: "sess-rp2", DA: da, PrincipalCert: principalCert}
	if _, err := m.Confirm(conf2); err == nil {
		t.Fatal("replayed renewal DA nonce must be rejected")
	}
	if m.State() != RenewalRejected {
		t.Fatalf("state = %s, want rejected", m.State())
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
