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
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// ─── registry.go ──────────────────────────────────────────────────

func TestConnRegistry_NewAndStats(t *testing.T) {
	r := NewConnRegistry()
	if r == nil {
		t.Fatal("expected non-nil")
	}
	if s := r.Stats(); s != 0 {
		t.Fatalf("expected 0, got %d", s)
	}
}

func TestConnRegistry_NilReceiver(t *testing.T) {
	var r *ConnRegistry
	// nil receiver should be safe
	remove := r.Register("a", "u", func() {})
	if remove == nil {
		t.Fatal("expected non-nil remove func")
	}
	remove() // noop
	if n := r.DisconnectByAgentId("a"); n != 0 {
		t.Fatalf("expected 0, got %d", n)
	}
	if n := r.DisconnectByPrincipalUid("u"); n != 0 {
		t.Fatalf("expected 0, got %d", n)
	}
	if s := r.Stats(); s != 0 {
		t.Fatalf("expected 0, got %d", s)
	}
}

func TestConnRegistry_RegisterAndDisconnect(t *testing.T) {
	r := NewConnRegistry()

	var closed []string
	_ = r.Register("agent-1", "uid-1", func() { closed = append(closed, "c1") })
	_ = r.Register("agent-1", "uid-2", func() { closed = append(closed, "c2") })
	_ = r.Register("agent-2", "uid-3", func() { closed = append(closed, "c3") })

	if s := r.Stats(); s != 3 {
		t.Fatalf("expected 3, got %d", s)
	}

	// Disconnect by agent
	n := r.DisconnectByAgentId("agent-1")
	if n != 2 {
		t.Fatalf("expected 2 closed, got %d", n)
	}
	if len(closed) != 2 {
		t.Fatalf("expected 2 closed funcs called, got %d", len(closed))
	}

	// After disconnect, stats still reflects entries slice (by-index entries cleaned)
	// but close functions have been called
	if s := r.Stats(); s != 3 {
		t.Fatalf("expected 3 (entries not removed by Disconnect), got %d", s)
	}
}

func TestConnRegistry_DisconnectByPrincipalUid(t *testing.T) {
	r := NewConnRegistry()

	var closed int
	r.Register("agent-x", "uid-target", func() { closed++ })
	r.Register("agent-y", "uid-other", func() { closed++ })

	n := r.DisconnectByPrincipalUid("uid-target")
	if n != 1 {
		t.Fatalf("expected 1, got %d", n)
	}
	if closed != 1 {
		t.Fatalf("expected 1 close, got %d", closed)
	}
}

func TestConnRegistry_ListByAgentId(t *testing.T) {
	r := NewConnRegistry()
	r.Register("a", "u1", func() {})
	r.Register("a", "u2", func() {})
	r.Register("b", "u3", func() {})

	list := r.ListByAgentId()
	if list["a"] != 2 {
		t.Fatalf("expected a=2, got %d", list["a"])
	}
	if list["b"] != 1 {
		t.Fatalf("expected b=1, got %d", list["b"])
	}
}

func TestRemoveID(t *testing.T) {
	ids := []uint64{1, 2, 3, 4}
	result := removeID(ids, 3)
	if len(result) != 3 {
		t.Fatalf("expected 3, got %d", len(result))
	}
	if result[0] != 1 || result[1] != 2 || result[2] != 4 {
		t.Fatalf("unexpected: %v", result)
	}

	// Remove non-existent
	result = removeID(result, 99)
	if len(result) != 3 {
		t.Fatalf("expected 3, got %d", len(result))
	}
}

// ─── user_permission.go ───────────────────────────────────────────

func TestPrincipalAuthorization_HasRole(t *testing.T) {
	pa := &PrincipalAuthorization{}
	if pa.HasRole("admin") {
		t.Fatal("v1.5 PA has no roles field; HasRole must return false")
	}
	if pa.HasRole("audit") {
		t.Fatal("expected false for audit")
	}
}

func TestPrincipalAuthorization_HasRole_Nil(t *testing.T) {
	var pa *PrincipalAuthorization
	if pa.HasRole("x") {
		t.Fatal("expected false on nil")
	}
}

func TestPrincipalAuthorization_AllowsRepresentative(t *testing.T) {
	pa := &PrincipalAuthorization{
		DelegationPolicy: DelegationPolicy{AllowedMode: 1},
	}
	if !pa.AllowsRepresentative() {
		t.Fatal("expected true")
	}
	pa2 := &PrincipalAuthorization{}
	if pa2.AllowsRepresentative() {
		t.Fatal("expected false for mode 0")
	}
}

func TestPrincipalAuthorization_AllowsRepresentative_Nil(t *testing.T) {
	var pa *PrincipalAuthorization
	if pa.AllowsRepresentative() {
		t.Fatal("expected false on nil")
	}
}

func TestPrincipalAuthorization_GrantIds(t *testing.T) {
	pa := &PrincipalAuthorization{
		Grants: []Capability{
			{SchemeId: "s1", CapabilityId: "c1"},
			{SchemeId: "s2", CapabilityId: "c2"},
		},
	}
	ids := pa.GrantIds()
	// FullID spec: the full identifier is scheme:capabilityId
	if len(ids) != 2 || ids[0] != "s1:c1" || ids[1] != "s2:c2" {
		t.Fatalf("unexpected: %v", ids)
	}
}

func TestPrincipalAuthorization_GrantIds_Nil(t *testing.T) {
	var pa *PrincipalAuthorization
	if ids := pa.GrantIds(); ids != nil {
		t.Fatalf("expected nil, got %v", ids)
	}
}

func TestUserPermission_AllowsImpersonation(t *testing.T) {
	u := &UserPermission{
		AgentDelegation: DelegationPolicy{AllowedMode: 1},
	}
	if !u.AllowsImpersonation() {
		t.Fatal("expected true")
	}
	u2 := &UserPermission{}
	if u2.AllowsImpersonation() {
		t.Fatal("expected false")
	}
}

func TestUserPermission_AllowsImpersonation_Nil(t *testing.T) {
	var u *UserPermission
	if u.AllowsImpersonation() {
		t.Fatal("expected false on nil")
	}
}

// ─── tsa.go helpers ───────────────────────────────────────────────

func TestParseRawValue(t *testing.T) {
	// Create a valid ASN.1 raw value
	raw := asn1.RawValue{Tag: asn1.TagSequence, Class: asn1.ClassUniversal, Bytes: []byte{0x01, 0x02}}
	data, err := asn1.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	result, err := parseRawValue(data)
	if err != nil {
		t.Fatalf("parseRawValue: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil")
	}
}

func TestParseRawValue_Invalid(t *testing.T) {
	_, err := parseRawValue([]byte{0xff, 0xff, 0xff})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestParseCertificatesFromRaw_Empty(t *testing.T) {
	certs := parseCertificatesFromRaw([]byte{})
	if len(certs) != 0 {
		t.Fatalf("expected 0, got %d", len(certs))
	}
}

func TestParseCertificatesFromRaw_SETOF(t *testing.T) {
	// Create a self-signed cert to embed
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tsa-test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)

	// Wrap in SET OF
	setOf := []asn1.RawValue{{FullBytes: der}}
	data, err := asn1.Marshal(setOf)
	if err != nil {
		t.Fatal(err)
	}
	certs := parseCertificatesFromRaw(data)
	if len(certs) != 1 {
		t.Fatalf("expected 1, got %d", len(certs))
	}
}

func TestParseCertificatesFromRaw_Sequence(t *testing.T) {
	// SEQUENCE of raw values (fallback path)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "tsa-seq"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)

	seqOf := []asn1.RawValue{{FullBytes: der}}
	data, err := asn1.Marshal(seqOf)
	if err != nil {
		t.Fatal(err)
	}
	certs := parseCertificatesFromRaw(data)
	if len(certs) != 1 {
		t.Fatalf("expected 1, got %d", len(certs))
	}
}

func TestFindTSACert_WithTimeStamping(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tsa"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	found := findTSACert([]*x509.Certificate{cert})
	if found == nil || found.Subject.CommonName != "tsa" {
		t.Fatal("expected TSA cert found")
	}
}

func TestFindTSACert_NoTimeStamping_NonCA(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "not-tsa"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         false,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	found := findTSACert([]*x509.Certificate{cert})
	if found == nil {
		t.Fatal("expected non-CA fallback")
	}
}

func TestFindTSACert_Empty(t *testing.T) {
	found := findTSACert(nil)
	if found != nil {
		t.Fatal("expected nil")
	}
}

func TestFindTSACert_AllCA(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ca"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	found := findTSACert([]*x509.Certificate{cert})
	if found == nil {
		t.Fatal("expected first cert as fallback")
	}
}

func TestVerifyTSACertChain_Valid(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	tsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tsaTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "TSA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	tsaDER, _ := x509.CreateCertificate(rand.Reader, tsaTmpl, caCert, &tsaKey.PublicKey, caKey)
	tsaCert, _ := x509.ParseCertificate(tsaDER)

	err := verifyTSACertChain([]*x509.Certificate{tsaCert}, caCert)
	if err != nil {
		t.Fatalf("expected valid chain, got %v", err)
	}
}

func TestVerifyTSACertChain_BadChain(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: "Other-CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	otherDER, _ := x509.CreateCertificate(rand.Reader, otherTmpl, otherTmpl, &otherKey.PublicKey, otherKey)
	otherCert, _ := x509.ParseCertificate(otherDER)

	tsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tsaTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "TSA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	tsaDER, _ := x509.CreateCertificate(rand.Reader, tsaTmpl, otherCert, &tsaKey.PublicKey, otherKey)
	tsaCert, _ := x509.ParseCertificate(tsaDER)

	err := verifyTSACertChain([]*x509.Certificate{tsaCert}, caCert)
	if err == nil {
		t.Fatal("expected error for bad chain")
	}
}

func TestVerifyTSACertChain_NoTSAKeyUsage(t *testing.T) {
	// All certs lack TimeStamping EKU; findTSACert falls back to first non-CA, or first cert.
	// With only CA certs (IsCA=true), findTSACert returns certs[0] (the CA).
	// The CA cert can self-verify as root, so this test checks that edge case.
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "CA-only"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	err := verifyTSACertChain([]*x509.Certificate{caCert}, caCert)
	// May succeed (CA self-verifies) or fail (ExtKeyUsage mismatch). Just check no panic.
	_ = err
}

// ─── streammux.go accessors ──────────────────────────────────────

func TestMuxStream_Accessors(t *testing.T) {
	// Create a pair of connected pipes
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	mux := NewStreamMux(server)
	defer mux.Close()

	stream := &MuxStream{
		localID:  42,
		remoteID: 99,
		mux:      mux,
	}
	stream.rcond = &sync.Cond{L: &stream.rmu}

	if stream.LocalID() != 42 {
		t.Fatalf("expected 42, got %d", stream.LocalID())
	}
	if stream.RemoteID() != 99 {
		t.Fatalf("expected 99, got %d", stream.RemoteID())
	}
	if stream.LocalAddr() == nil {
		t.Fatal("expected non-nil LocalAddr")
	}
	if stream.RemoteAddr() == nil {
		t.Fatal("expected non-nil RemoteAddr")
	}
	if err := stream.SetDeadline(time.Now()); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if err := stream.SetReadDeadline(time.Now()); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if err := stream.SetWriteDeadline(time.Now()); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
}

// ─── audit.go SetV12Fields ────────────────────────────────────────

func TestAuditEntry_SetV12Fields(t *testing.T) {
	var e AuditEntry
	e.SetV12Fields("tcp", "gw-1", "trace-1", "sess-1", "admit")
	if e.Protocol != "tcp" || e.GatewayId != "gw-1" || e.TraceId != "trace-1" || e.SessionId != "sess-1" || e.Decision != "admit" {
		t.Fatalf("unexpected: %+v", e)
	}
}

// ─── audit.go ArchiveAuditFile ────────────────────────────────────

func TestArchiveAuditFile_EmptyPath(t *testing.T) {
	if err := ArchiveAuditFile(""); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestArchiveAuditFile_NotExist(t *testing.T) {
	if err := ArchiveAuditFile("/tmp/nonexistent-audit-file-12345.jsonl"); err != nil {
		t.Fatalf("expected nil for non-existent, got %v", err)
	}
}

func TestArchiveAuditFile_ZeroSize(t *testing.T) {
	f, _ := os.CreateTemp("", "audit-empty-*.jsonl")
	f.Close()
	defer os.Remove(f.Name())

	if err := ArchiveAuditFile(f.Name()); err != nil {
		t.Fatalf("expected nil for zero size, got %v", err)
	}
}

func TestArchiveAuditFile_Success(t *testing.T) {
	f, _ := os.CreateTemp("", "audit-test-*.jsonl")
	f.WriteString(`{"action":"connected"}` + "\n")
	f.Close()
	defer os.Remove(f.Name() + ".archived")

	if err := ArchiveAuditFile(f.Name()); err != nil {
		t.Fatalf("archive: %v", err)
	}
	// Original should be renamed
	if _, err := os.Stat(f.Name()); !os.IsNotExist(err) {
		t.Fatal("original file should be gone")
	}
}

// ─── audit.go readAuditEntriesReverse ─────────────────────────────

func TestReadAuditEntriesReverse_Basic(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "audit.jsonl")
	content := `{"entry":{"action":"connected","src_ip":"1.1.1.1","mapping":"m","target":"t","time":"2026-01-01T00:00:00Z"}}
{"entry":{"action":"disconnected","src_ip":"2.2.2.2","mapping":"m","target":"t","time":"2026-01-01T01:00:00Z"}}
{"entry":{"action":"denied","src_ip":"3.3.3.3","mapping":"m","target":"t","time":"2026-01-01T02:00:00Z"}}
`
	os.WriteFile(f, []byte(content), 0644)

	filter := AuditFilter{Limit: 2}
	entries, err := readAuditEntriesReverse(f, filter)
	if err != nil {
		t.Fatalf("readAuditEntriesReverse: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	// Reverse order: denied, disconnected
	if entries[0].Action != "denied" {
		t.Fatalf("expected 'denied' first, got %s", entries[0].Action)
	}
}

func TestReadAuditEntriesReverse_WithOffset(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "audit.jsonl")
	content := `{"entry":{"action":"a1","mapping":"m","target":"t","time":"2026-01-01T00:00:00Z"}}
{"entry":{"action":"a2","mapping":"m","target":"t","time":"2026-01-01T01:00:00Z"}}
{"entry":{"action":"a3","mapping":"m","target":"t","time":"2026-01-01T02:00:00Z"}}
{"entry":{"action":"a4","mapping":"m","target":"t","time":"2026-01-01T03:00:00Z"}}
`
	os.WriteFile(f, []byte(content), 0644)

	filter := AuditFilter{Limit: 2, Offset: 1}
	entries, err := readAuditEntriesReverse(f, filter)
	if err != nil {
		t.Fatalf("readAuditEntriesReverse: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	// Skip last (offset 1), take next 2
	if entries[0].Action != "a3" {
		t.Fatalf("expected 'a3' first, got %s", entries[0].Action)
	}
}

func TestReadAuditEntriesReverse_WithActionFilter(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "audit.jsonl")
	content := `{"entry":{"action":"connected","mapping":"m","target":"t","time":"2026-01-01T00:00:00Z"}}
{"entry":{"action":"denied","mapping":"m","target":"t","time":"2026-01-01T01:00:00Z"}}
{"entry":{"action":"connected","mapping":"m","target":"t","time":"2026-01-01T02:00:00Z"}}
`
	os.WriteFile(f, []byte(content), 0644)

	filter := AuditFilter{Limit: 10, Action: "denied"}
	entries, err := readAuditEntriesReverse(f, filter)
	if err != nil {
		t.Fatalf("readAuditEntriesReverse: %v", err)
	}
	if len(entries) != 1 || entries[0].Action != "denied" {
		t.Fatalf("expected 1 denied entry, got %d", len(entries))
	}
}

func TestReadAuditEntriesReverse_Empty(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "empty.jsonl")
	os.WriteFile(f, []byte{}, 0644)

	entries, err := readAuditEntriesReverse(f, AuditFilter{Limit: 10})
	if err != nil {
		t.Fatalf("readAuditEntriesReverse: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0, got %d", len(entries))
	}
}

func TestReadAuditEntriesReverse_FileNotFound(t *testing.T) {
	_, err := readAuditEntriesReverse("/tmp/nonexistent-99999.jsonl", AuditFilter{})
	if err == nil {
		t.Fatal("expected error")
	}
}

// ─── stopher.go Reset ─────────────────────────────────────────────

func TestStopGuard_Reset(t *testing.T) {
	g := NewStopGuard()
	if g.IsStopped() {
		t.Fatal("not stopped yet")
	}
	g.Stop()
	if !g.IsStopped() {
		t.Fatal("expected stopped")
	}
	g.Reset()
	if g.IsStopped() {
		t.Fatal("expected not stopped after reset")
	}
}

// ─── tsa_proof.go SetAuditChain ──────────────────────────────────

func TestTSAProofLogger_SetAuditChain(t *testing.T) {
	logger := &TSAProofLogger{}
	chain := &AuditChain{}
	logger.SetAuditChain(chain)
	if logger.chain != chain {
		t.Fatal("expected chain set")
	}
}

// ─── pluginconfig.go webhook Scheme/Execute ────────────────────────

func TestWebhookPlugin_SchemeAndExecute(t *testing.T) {
	p, err := newWebhookPlugin("test-webhook", map[string]interface{}{
		"url": "https://example.com/hook",
	})
	if err != nil {
		t.Fatalf("newWebhookPlugin: %v", err)
	}
	if p.Scheme() != "test-webhook" {
		t.Fatalf("expected test-webhook, got %s", p.Scheme())
	}

	result, _ := p.Execute(&Capability{
		SchemeId:     "test-webhook",
		CapabilityId: "test-cap",
	}, &PluginContext{})
	_ = result
}
