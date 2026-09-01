// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAuditLogger(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.log")

	logger, err := NewAuditLogger(auditPath, nil, 10*1024*1024, 3)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}

	entry := AuditEntry{
		Action:  "connected",
		SrcIP:   "10.0.0.1:12345",
		Mapping: "test-mapping",
		Target:  "127.0.0.1:3306",
	}
	logger.Log(entry)
	logger.Close()

	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	var signed SignedAuditEntry
	if err := json.Unmarshal(data, &signed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if signed.Entry.Action != "connected" {
		t.Errorf("action = %q, want %q", signed.Entry.Action, "connected")
	}
	if signed.Entry.SrcIP != "10.0.0.1:12345" {
		t.Errorf("src_ip = %q", signed.Entry.SrcIP)
	}
	if signed.Entry.Time == "" {
		t.Error("time should be set")
	}
}

func TestReadAuditEntries(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.log")

	logger, err := NewAuditLogger(auditPath, nil, 10*1024*1024, 3)
	if err != nil {
		t.Fatal(err)
	}

	logger.Log(AuditEntry{Action: "connected", Mapping: "m1", SrcIP: "10.0.0.1"})
	time.Sleep(10 * time.Millisecond)
	logger.Log(AuditEntry{Action: "disconnected", Mapping: "m1", SrcIP: "10.0.0.1"})
	logger.Close()

	entries, err := ReadAuditEntries(auditPath, AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	entries, err = ReadAuditEntries(auditPath, AuditFilter{Action: "connected"})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Action != "connected" {
		t.Errorf("expected 1 connected, got %d", len(entries))
	}

	entries, err = ReadAuditEntries(auditPath, AuditFilter{Since: time.Now().Add(1 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries with future since, got %d", len(entries))
	}

	_, err = ReadAuditEntries("/nonexistent", AuditFilter{})
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestNewAuditEntryFromConn(t *testing.T) {
	cert := testCertWithOU(t, []string{"gateway:admin"})
	entry := NewAuditEntryFromConn("10.0.0.1:12345", "m1", "127.0.0.1:3306", cert)
	if entry.ClientCN != "test" {
		t.Errorf("ClientCN = %q, want %q", entry.ClientCN, "test")
	}
	if entry.Mapping != "m1" {
		t.Errorf("Mapping = %q", entry.Mapping)
	}
	if entry.Target != "127.0.0.1:3306" {
		t.Errorf("Target = %q", entry.Target)
	}
	if len(entry.Roles) != 1 || entry.Roles[0] != "gateway:admin" {
		t.Errorf("Roles = %v", entry.Roles)
	}
	if entry.SrcIP != "10.0.0.1:12345" {
		t.Errorf("SrcIP = %q", entry.SrcIP)
	}

	entryNoCert := NewAuditEntryFromConn("10.0.0.1", "m1", "127.0.0.1:3306", nil)
	if entryNoCert.ClientCN != "" {
		t.Errorf("expected empty ClientCN for nil cert")
	}
}

func TestNewAuditEntryDenied(t *testing.T) {
	cert := testCertWithOU(t, []string{"gateway:redis"})
	entry := NewAuditEntryDenied("10.0.0.1", "m1", "127.0.0.1:3306", "unauthorized", cert)
	if entry.Action != "denied" {
		t.Errorf("Action = %q, want %q", entry.Action, "denied")
	}
	if entry.DenyReason != "unauthorized" {
		t.Errorf("DenyReason = %q", entry.DenyReason)
	}
	if entry.Roles[0] != "gateway:redis" {
		t.Errorf("Roles = %v", entry.Roles)
	}
}

func TestAuditLogNilLogger(t *testing.T) {
	var logger *AuditLogger
	logger.Log(AuditEntry{}) // should not panic
}

func TestAuditLogConcurrent(t *testing.T) {
	dir := t.TempDir()
	logger, err := NewAuditLogger(filepath.Join(dir, "audit.log"), nil, 10*1024*1024, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.Log(AuditEntry{Action: "connected", SrcIP: "10.0.0.1", Mapping: "m1"})
		}()
	}
	wg.Wait()
}

func TestAuditDuration(t *testing.T) {
	start := time.Now().Add(-5 * time.Second)
	entry := &AuditEntry{}
	AuditDuration(start, entry)
	if entry.Duration == "" {
		t.Error("duration should be set")
	}
}

func TestVerifyAuditEntry(t *testing.T) {
	entry := AuditEntry{
		Time:    time.Now().UTC().Format(time.RFC3339Nano),
		Action:  "connected",
		SrcIP:   "10.0.0.1",
		Mapping: "test",
		Target:  "127.0.0.1:3306",
	}

	signed := SignedAuditEntry{Entry: entry}
	data, _ := json.Marshal(signed)

	err := VerifyAuditEntry(data, nil)
	if err != nil {
		t.Errorf("VerifyAuditEntry with nil client: %v", err)
	}
}

func TestFilterAuditFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "audit.log")
	logger, err := NewAuditLogger(file, nil, 10*1024*1024, 3)
	if err != nil {
		t.Fatal(err)
	}
	logger.Log(AuditEntry{Action: "connected", Mapping: "m1", SrcIP: "1.2.3.4"})
	logger.Close()

	old := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w

	err = FilterAuditFile(file, time.Time{}, "", "", "", "")
	w.Close()
	os.Stdout = old

	if err != nil {
		t.Errorf("FilterAuditFile error: %v", err)
	}
}

func makeAICCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	aic := AIC{
		AgentId:      "agent-42",
		PrincipalUid: PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "admin@varwof.com"},
		Capabilities: []Capability{
			{SchemeId: "http", CapabilityId: "gateway:admin"},
			{SchemeId: "tcp", CapabilityId: "gateway:ops"},
		},
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
	aicVal, err := asn1.Marshal(aic)
	if err != nil {
		t.Fatal(err)
	}
	pa := PrincipalAuthorization{
		DelegationPolicy: DelegationPolicy{AllowedMode: 0},
	}
	paVal, err := asn1.Marshal(pa)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "aic-agent",
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: oidAIC, Value: aicVal},
			{Id: oidUserPermission, Value: paVal},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestNewAuditEntryFromConn_WithAIC(t *testing.T) {
	cert := makeAICCert(t)
	entry := NewAuditEntryFromConn("10.0.0.1:12345", "m1", "127.0.0.1:3306", cert)

	if entry.AgentId != "agent-42" {
		t.Fatalf("AgentId: expected agent-42, got %s", entry.AgentId)
	}
	if entry.PrincipalUid != "varwof:admin@varwof.com:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
		t.Fatalf("PrincipalUid: expected varwof:admin@varwof.com:<keyhash>, got %s", entry.PrincipalUid)
	}
	if entry.DelegationMode != int(DelegationAuthorized) {
		t.Fatalf("DelegationMode: expected %d, got %d", DelegationAuthorized, entry.DelegationMode)
	}
	if len(entry.Capabilities) != 2 {
		t.Fatalf("Capabilities: expected 2, got %d", len(entry.Capabilities))
	}
	if entry.Capabilities[0] != "gateway:admin" || entry.Capabilities[1] != "gateway:ops" {
		t.Fatalf("Capabilities: got %v", entry.Capabilities)
	}
	if entry.ClientCN != "aic-agent" {
		t.Fatalf("ClientCN: expected aic-agent, got %s", entry.ClientCN)
	}
}

func TestNewAuditEntryDenied_WithAIC(t *testing.T) {
	cert := makeAICCert(t)
	entry := NewAuditEntryDenied("10.0.0.2:54321", "m2", "192.168.1.1:443", "rbac:denied", cert)

	if entry.Action != "denied" {
		t.Fatalf("Action: expected denied, got %s", entry.Action)
	}
	if entry.DenyReason != "rbac:denied" {
		t.Fatalf("DenyReason: expected rbac:denied, got %s", entry.DenyReason)
	}
	if entry.AgentId != "agent-42" {
		t.Fatalf("AgentId: expected agent-42, got %s", entry.AgentId)
	}
	if entry.PrincipalUid != "varwof:admin@varwof.com:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
		t.Fatalf("PrincipalUid: expected varwof:admin@varwof.com:<keyhash>, got %s", entry.PrincipalUid)
	}
	if entry.DelegationMode != int(DelegationAuthorized) {
		t.Fatalf("DelegationMode: expected %d, got %d", DelegationAuthorized, entry.DelegationMode)
	}
}

func TestNewAuditEntryFromConn_WithAICImpersonation(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	aic := AIC{
		AgentId:        "agent-imp",
		PrincipalUid:   PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "victim@varwof.com"},
		DelegationMode: DelegationRepresentative,
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
	aicVal, err := asn1.Marshal(aic)
	if err != nil {
		t.Fatal(err)
	}
	pa := PrincipalAuthorization{
		DelegationPolicy: DelegationPolicy{AllowedMode: 1},
	}
	paVal, err := asn1.Marshal(pa)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "imp-agent"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: oidAIC, Value: aicVal},
			{Id: oidUserPermission, Value: paVal},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	entry := NewAuditEntryFromConn("10.0.0.3:9999", "m3", "target:443", cert)
	if entry.AgentId != "agent-imp" {
		t.Fatalf("AgentId: expected agent-imp, got %s", entry.AgentId)
	}
	if entry.PrincipalUid != "varwof:victim@varwof.com:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
		t.Fatalf("PrincipalUid: expected varwof:victim@varwof.com:<keyhash>, got %s", entry.PrincipalUid)
	}
	if entry.DelegationMode != 1 {
		t.Fatalf("DelegationMode: expected 1, got %d", entry.DelegationMode)
	}
}

// TestAuditLoggerNonBlockingOverflow verifies M6: when the buffer is full, Log
// drops entries (and counts them) instead of blocking the caller.
func TestAuditLoggerNonBlockingOverflow(t *testing.T) {
	dir := t.TempDir()
	logger, err := NewAuditLogger(filepath.Join(dir, "audit.log"), nil, 10*1024*1024, 3)
	if err != nil {
		t.Fatal(err)
	}
	// Fill the 8192-deep buffer beyond capacity from a goroutine that never
	// drains (we stop the loop immediately), then ensure Log returns fast.
	done := make(chan struct{})
	go func() {
		for i := 0; i < 50000; i++ {
			logger.Log(AuditEntry{Action: "x", SrcIP: "1.2.3.4"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Log blocked on full buffer (M6 regression)")
	}
	if logger.Dropped() == 0 {
		t.Error("expected some dropped entries under overflow")
	}
	logger.Close()
}

// TestAuditCriticalNotEvictedByFlood (finding 15): a flood of INFO entries must
// not evict a security-critical entry.
func TestAuditCriticalNotEvictedByFlood(t *testing.T) {
	dir := t.TempDir()
	logger, err := NewAuditLogger(filepath.Join(dir, "audit.log"), nil, 10*1024*1024, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()

	// Overwhelm the queue with routine INFO entries (most will be dropped), then
	// log a security-critical entry and verify it reaches the file.
	for i := 0; i < 50000; i++ {
		logger.Log(AuditEntry{Action: string(ActionProxied), SrcIP: "1.2.3.4"})
	}
	logger.Log(AuditEntry{Action: string(ActionRevoked), Level: "WARN", ClientCN: "victim-identity"})

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		data, _ := os.ReadFile(filepath.Join(dir, "audit.log"))
		if strings.Contains(string(data), "victim-identity") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "audit.log"))
	t.Fatalf("critical audit entry was evicted by a flood (log contains %d bytes)", len(data))
}

// TestIsAuditCritical classifies WARN/ERROR and revocation/denial actions as
// critical (finding 15).
func TestIsAuditCritical(t *testing.T) {
	if !isAuditCritical(AuditEntry{Level: "WARN"}) {
		t.Error("WARN must be critical")
	}
	if !isAuditCritical(AuditEntry{Level: "ERROR"}) {
		t.Error("ERROR must be critical")
	}
	if !isAuditCritical(AuditEntry{Action: string(ActionRevoked)}) {
		t.Error("revoked must be critical")
	}
	if !isAuditCritical(AuditEntry{Action: string(ActionDenied)}) {
		t.Error("denied must be critical")
	}
	if isAuditCritical(AuditEntry{Action: string(ActionProxied)}) {
		t.Error("proxied INFO must not be critical")
	}
}

// TestAuditLoggerCloseDrains verifies M6: Close flushes buffered entries rather
// than silently discarding them.
func TestAuditLoggerCloseDrains(t *testing.T) {
	dir := t.TempDir()
	logger, err := NewAuditLogger(filepath.Join(dir, "audit.log"), nil, 10*1024*1024, 3)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		logger.Log(AuditEntry{Action: "drain", SrcIP: "9.9.9.9"})
	}
	logger.Close()
	data, _ := os.ReadFile(filepath.Join(dir, "audit.log"))
	if !strings.Contains(string(data), `"action":"drain"`) {
		t.Error("buffered entries were not flushed on Close")
	}
}

func makeAICCertWithDASig(t *testing.T, sig []byte) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	aic := AIC{
		AgentId:      "agent-evidence",
		PrincipalUid: PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "user@varwof.com"},
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
			SignatureValue:     sig,
		},
	}
	aicVal, err := asn1.Marshal(aic)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "evidence-agent"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: oidAIC, Value: aicVal},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// TestEvidenceFingerprints Task 4: authorization evidence binding to audit entries.
// AIC fingerprint + DA hash populated into audit entry; empty string if no AIC / no DA signature.
func TestEvidenceFingerprints(t *testing.T) {
	sig := []byte("this-is-a-delegation-signature-bytes")
	cert := makeAICCertWithDASig(t, sig)

	// AIC fingerprint must be non-empty (AIC extension present)
	fp := AICFingerprint(cert)
	if len(fp) != 64 {
		t.Fatalf("AICFingerprint length = %d, want 64 hex chars", len(fp))
	}
	// Two calls are consistent (deterministic)
	if fp != AICFingerprint(cert) {
		t.Fatal("AICFingerprint not deterministic")
	}

	// DA hash must be non-empty and equal to SHA-256 of signature value
	dh := DAHash(cert)
	if len(dh) != 64 {
		t.Fatalf("DAHash length = %d, want 64 hex chars", len(dh))
	}
	sum := sha256.Sum256(sig)
	want := hex.EncodeToString(sum[:])
	if dh != want {
		t.Fatalf("DAHash = %s, want %s", dh, want)
	}

	// WithEvidenceFingerprints populates the audit entry
	entry := AuditEntry{}
	entry.WithEvidenceFingerprints(cert)
	if entry.AICFingerprint != fp || entry.DaHash != dh {
		t.Fatalf("entry fingerprints mismatch: %+v", entry)
	}
}

// TestEvidenceFingerprintsEmpty No AIC cert → fingerprint is empty string (omitempty, old entries readable).
func TestEvidenceFingerprintsEmpty(t *testing.T) {
	cert := testCertWithOU(t, []string{"gateway:admin"})
	if fp := AICFingerprint(cert); fp != "" {
		t.Fatalf("expected empty AIC fingerprint for non-AIC cert, got %s", fp)
	}
	if dh := DAHash(cert); dh != "" {
		t.Fatalf("expected empty DAHash for non-AIC cert, got %s", dh)
	}
	if dh := DAHash(nil); dh != "" {
		t.Fatalf("expected empty DAHash for nil cert")
	}
	if fp := AICFingerprint(nil); fp != "" {
		t.Fatalf("expected empty AIC fingerprint for nil cert")
	}
	// No DA signature → empty DAHash
	certNoSig := makeAICCertWithDASig(t, nil)
	if dh := DAHash(certNoSig); dh != "" {
		t.Fatalf("expected empty DAHash without DA signature, got %s", dh)
	}
}

// TestPluginAuditEntryDaHash Plugin decision entry carries DA hash (task 4).
func TestPluginAuditEntryDaHash(t *testing.T) {
	dir := t.TempDir()
	logger, err := NewAuditLogger(filepath.Join(dir, "audit.log"), nil, 10*1024*1024, 3)
	if err != nil {
		t.Fatal(err)
	}
	LogPluginDecision(logger, PluginAuditEntry{
		Scheme: "http", CapabilityID: "gateway:read",
		Decision: "allow", ClientCN: "x", DaHash: "deadbeef",
	})
	logger.Close()
	entries, err := ReadAuditEntries(filepath.Join(dir, "audit.log"), AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].DaHash != "deadbeef" {
		t.Fatalf("DaHash = %q, want deadbeef", entries[0].DaHash)
	}
}
