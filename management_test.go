// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type testTranslator struct {
	overrides map[string]string
}

func (tt *testTranslator) T(lang, key string, args ...any) string {
	if v, ok := tt.overrides[key]; ok {
		return v
	}
	return key
}

func TestNewManagementServer(t *testing.T) {
	ms := NewManagementServer(ManagementServerConfig{})
	if ms == nil {
		t.Fatal("NewManagementServer() returned nil")
	}
	if ms.mux == nil {
		t.Error("mux not initialized")
	}
}

// TestManagementStartRequiresMTLS (finding 12): Start must refuse to run when
// the TLS config does not require and verify client certificates.
func TestManagementStartRequiresMTLS(t *testing.T) {
	dir := t.TempDir()
	cfg := testTLSConfig(t, dir)
	cfg.ClientAuth = tls.NoClientCert
	ms := NewManagementServer(ManagementServerConfig{
		Listen:    "127.0.0.1:0",
		TLSConfig: cfg,
	})
	if err := ms.Start(); err == nil {
		t.Fatal("Start must refuse a TLS config without RequireAndVerifyClientCert")
	}
	if ms.server != nil {
		t.Fatal("server must not be bound when refusing to start")
	}
}

func TestManagementStartStop(t *testing.T) {
	dir := t.TempDir()
	cfg := testTLSConfig(t, dir)
	ms := NewManagementServer(ManagementServerConfig{
		Listen:    "127.0.0.1:0",
		TLSConfig: cfg,
	})
	errCh := make(chan error, 1)
	go func() {
		errCh <- ms.Start()
	}()
	time.Sleep(50 * time.Millisecond)
	ms.Stop()
	select {
	case err := <-errCh:
		if err != nil && err.Error() != "http: Server closed" {
			t.Fatalf("Start() returned unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start() did not return after Stop()")
	}
}

func TestManagementStopIdempotent(t *testing.T) {
	dir := t.TempDir()
	cfg := testTLSConfig(t, dir)
	ms := NewManagementServer(ManagementServerConfig{
		Listen:    "127.0.0.1:0",
		TLSConfig: cfg,
	})
	go ms.Start()
	time.Sleep(50 * time.Millisecond)
	ms.Stop()
	ms.Stop()
}

func freePort(t testing.TB) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

func TestManagementServeAndHealth(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := testCA(t, dir)
	srvCert := testCert(t, dir, "server", caCert, caKey, nil)
	clientCert := testCert(t, dir, "client", caCert, caKey, []string{"gateway:admin"})

	srvTLS := &tls.Config{
		Certificates: []tls.Certificate{srvCert.TLSCertificate()},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool(t, dir),
	}

	addr := freePort(t)
	ms := NewManagementServer(ManagementServerConfig{
		Listen:    addr,
		TLSConfig: srvTLS,
	})
	go ms.Start()
	time.Sleep(100 * time.Millisecond)
	defer ms.Stop()

	cliTLS := &tls.Config{
		Certificates:       []tls.Certificate{clientCert.TLSCertificate()},
		RootCAs:            clientCAPool(t, dir),
		InsecureSkipVerify: true,
	}
	conn, err := tls.Dial("tcp", addr, cliTLS)
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer conn.Close()

	req := "GET /api/v1/gateway/health HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"
	fmt.Fprint(conn, req)
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := conn.Read(buf)
	body := string(buf[:n])
	if !strings.Contains(body, "200 OK") {
		t.Fatalf("expected 200, got: %s", body)
	}
	if !strings.Contains(body, `"status":"ok"`) {
		t.Fatalf("expected status ok, got: %s", body)
	}
}

func TestManagementMetricsAdminRole(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := testCA(t, dir)
	srvCert := testCert(t, dir, "server", caCert, caKey, nil)
	adminCert := testCert(t, dir, "admin", caCert, caKey, []string{"gateway:admin"})

	srvTLS := &tls.Config{
		Certificates: []tls.Certificate{srvCert.TLSCertificate()},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool(t, dir),
	}

	addr := freePort(t)
	ms := NewManagementServer(ManagementServerConfig{
		Listen:    addr,
		TLSConfig: srvTLS,
		BuildInfo: "test-build 1.0",
	})
	go ms.Start()
	time.Sleep(100 * time.Millisecond)
	defer ms.Stop()

	resp := mgmtRequest(t, addr, adminCert, clientCAPool(t, dir), "/api/v1/gateway/metrics")
	if !strings.Contains(resp, "200 OK") {
		t.Fatalf("expected 200, got: %s", resp)
	}
	if !strings.Contains(resp, "test-build") {
		t.Fatalf("expected build info in metrics, got: %s", resp)
	}
}

func TestManagementMetricsOpsRole(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := testCA(t, dir)
	srvCert := testCert(t, dir, "server", caCert, caKey, nil)
	opsCert := testCert(t, dir, "ops", caCert, caKey, []string{"gateway:ops"})

	srvTLS := &tls.Config{
		Certificates: []tls.Certificate{srvCert.TLSCertificate()},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool(t, dir),
	}

	addr := freePort(t)
	ms := NewManagementServer(ManagementServerConfig{
		Listen:    addr,
		TLSConfig: srvTLS,
	})
	go ms.Start()
	time.Sleep(100 * time.Millisecond)
	defer ms.Stop()

	resp := mgmtRequest(t, addr, opsCert, clientCAPool(t, dir), "/api/v1/gateway/metrics")
	if !strings.Contains(resp, "200 OK") {
		t.Fatalf("expected ops to access metrics, got: %s", resp)
	}
}

func TestManagementMetricsForbidden(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := testCA(t, dir)
	srvCert := testCert(t, dir, "server", caCert, caKey, nil)
	auditCert := testCert(t, dir, "auditor", caCert, caKey, []string{"gateway:audit"})

	srvTLS := &tls.Config{
		Certificates: []tls.Certificate{srvCert.TLSCertificate()},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool(t, dir),
	}

	addr := freePort(t)
	ms := NewManagementServer(ManagementServerConfig{
		Listen:    addr,
		TLSConfig: srvTLS,
	})
	go ms.Start()
	time.Sleep(100 * time.Millisecond)
	defer ms.Stop()

	resp := mgmtRequest(t, addr, auditCert, clientCAPool(t, dir), "/api/v1/gateway/metrics")
	if !strings.Contains(resp, "403 Forbidden") {
		t.Fatalf("expected 403 for audit role, got: %s", resp)
	}
}

func TestManagementAuditEndpoint(t *testing.T) {
	dir := t.TempDir()
	auditFile := filepath.Join(dir, "audit.log")
	al, err := NewAuditLogger(auditFile, nil, 1024*1024, 3)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer al.Close()

	al.Log(AuditEntry{Action: "connected", SrcIP: "1.2.3.4", Mapping: "test"})
	al.Log(AuditEntry{Action: "denied", SrcIP: "5.6.7.8", Mapping: "test", DenyReason: "bad cert"})
	time.Sleep(100 * time.Millisecond)

	caCert, caKey := testCA(t, dir)
	srvCert := testCert(t, dir, "server", caCert, caKey, nil)
	adminCert := testCert(t, dir, "admin", caCert, caKey, []string{"gateway:admin"})

	srvTLS := &tls.Config{
		Certificates: []tls.Certificate{srvCert.TLSCertificate()},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool(t, dir),
	}

	addr := freePort(t)
	ms := NewManagementServer(ManagementServerConfig{
		Listen:      addr,
		TLSConfig:   srvTLS,
		AuditLogger: al,
	})
	go ms.Start()
	time.Sleep(100 * time.Millisecond)
	defer ms.Stop()

	resp := mgmtRequest(t, addr, adminCert, clientCAPool(t, dir), "/api/v1/gateway/audit")
	if !strings.Contains(resp, "200 OK") {
		t.Fatalf("expected 200, got: %s", resp)
	}
	if !strings.Contains(resp, "connected") {
		t.Fatalf("expected audit entries, got: %s", resp)
	}
}

func TestManagementAuditNoLogger(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := testCA(t, dir)
	srvCert := testCert(t, dir, "server", caCert, caKey, nil)
	adminCert := testCert(t, dir, "admin", caCert, caKey, []string{"gateway:admin"})

	srvTLS := &tls.Config{
		Certificates: []tls.Certificate{srvCert.TLSCertificate()},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool(t, dir),
	}

	addr := freePort(t)
	ms := NewManagementServer(ManagementServerConfig{
		Listen:    addr,
		TLSConfig: srvTLS,
	})
	go ms.Start()
	time.Sleep(100 * time.Millisecond)
	defer ms.Stop()

	resp := mgmtRequest(t, addr, adminCert, clientCAPool(t, dir), "/api/v1/gateway/audit")
	if !strings.Contains(resp, "404 Not Found") {
		t.Fatalf("expected 404 without audit logger, got: %s", resp)
	}
}

func TestManagementAuditWithFilters(t *testing.T) {
	dir := t.TempDir()
	auditFile := filepath.Join(dir, "audit.log")
	al, err := NewAuditLogger(auditFile, nil, 1024*1024, 3)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer al.Close()

	al.Log(AuditEntry{Action: "connected", SrcIP: "1.2.3.4", Mapping: "alpha"})
	al.Log(AuditEntry{Action: "denied", SrcIP: "5.6.7.8", Mapping: "beta", DenyReason: "bad"})
	time.Sleep(100 * time.Millisecond)

	caCert, caKey := testCA(t, dir)
	srvCert := testCert(t, dir, "server", caCert, caKey, nil)
	adminCert := testCert(t, dir, "admin", caCert, caKey, []string{"gateway:admin"})

	srvTLS := &tls.Config{
		Certificates: []tls.Certificate{srvCert.TLSCertificate()},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool(t, dir),
	}

	addr := freePort(t)
	ms := NewManagementServer(ManagementServerConfig{
		Listen:      addr,
		TLSConfig:   srvTLS,
		AuditLogger: al,
	})
	go ms.Start()
	time.Sleep(100 * time.Millisecond)
	defer ms.Stop()

	resp := mgmtRequest(t, addr, adminCert, clientCAPool(t, dir), "/api/v1/gateway/audit?action=denied")
	if !strings.Contains(resp, "200 OK") {
		t.Fatalf("expected 200, got: %s", resp)
	}
	if strings.Contains(resp, "connected") {
		t.Fatalf("filtered by action=denied but got connected entry: %s", resp)
	}
}

func TestManagementAuditVerify(t *testing.T) {
	dir := t.TempDir()
	chain := NewAuditChain(100, nil)
	chain.Seal([][]byte{[]byte("entry1"), []byte("entry2")}, "")

	caCert, caKey := testCA(t, dir)
	srvCert := testCert(t, dir, "server", caCert, caKey, nil)
	adminCert := testCert(t, dir, "admin", caCert, caKey, []string{"gateway:admin"})

	srvTLS := &tls.Config{
		Certificates: []tls.Certificate{srvCert.TLSCertificate()},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool(t, dir),
	}

	addr := freePort(t)
	ms := NewManagementServer(ManagementServerConfig{
		Listen:     addr,
		TLSConfig:  srvTLS,
		AuditChain: chain,
	})
	go ms.Start()
	time.Sleep(100 * time.Millisecond)
	defer ms.Stop()

	verifyReq := VerifyRequest{
		Batch: 0,
		Leaf:  fmt.Sprintf("%x", HashLeaf([]byte("entry1"))),
		Proof: []ProofStepJSON{
			{Sibling: fmt.Sprintf("%x", HashLeaf([]byte("entry2"))), Left: false},
		},
	}
	body, _ := json.Marshal(verifyReq)

	conn := mgmtDial(t, addr, adminCert, clientCAPool(t, dir))
	defer conn.Close()

	req := fmt.Sprintf("POST /api/v1/gateway/audit/verify HTTP/1.1\r\nHost: test\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
	fmt.Fprint(conn, req)
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := conn.Read(buf)
	resp := string(buf[:n])
	if !strings.Contains(resp, "200 OK") {
		t.Fatalf("expected 200, got: %s", resp)
	}
}

func TestManagementAuditVerifyWrongMethod(t *testing.T) {
	dir := t.TempDir()
	chain := NewAuditChain(100, nil)

	caCert, caKey := testCA(t, dir)
	srvCert := testCert(t, dir, "server", caCert, caKey, nil)
	adminCert := testCert(t, dir, "admin", caCert, caKey, []string{"gateway:admin"})

	srvTLS := &tls.Config{
		Certificates: []tls.Certificate{srvCert.TLSCertificate()},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool(t, dir),
	}

	addr := freePort(t)
	ms := NewManagementServer(ManagementServerConfig{
		Listen:     addr,
		TLSConfig:  srvTLS,
		AuditChain: chain,
	})
	go ms.Start()
	time.Sleep(100 * time.Millisecond)
	defer ms.Stop()

	conn := mgmtDial(t, addr, adminCert, clientCAPool(t, dir))
	defer conn.Close()

	req := "GET /api/v1/gateway/audit/verify HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"
	fmt.Fprint(conn, req)
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := conn.Read(buf)
	resp := string(buf[:n])
	if !strings.Contains(resp, "405 Method Not Allowed") {
		t.Fatalf("expected 405, got: %s", resp)
	}
}

func TestManagementRegisterHandler(t *testing.T) {
	ms := NewManagementServer(ManagementServerConfig{})
	called := false
	ms.RegisterHandler("/api/v1/gateway/custom", func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
	}, RoleAdmin)
	if ms.mux == nil {
		t.Fatal("mux nil after RegisterHandler")
	}
	_ = called
}

func TestManagementRegisterRawHandler(t *testing.T) {
	ms := NewManagementServer(ManagementServerConfig{})
	called := false
	ms.RegisterRawHandler("/api/v1/gateway/raw", func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	})
	if ms.mux == nil {
		t.Fatal("mux nil after RegisterRawHandler")
	}
	_ = called
}

func TestWriteMgmtJSON(t *testing.T) {
	w := httptest.NewRecorder()
	WriteMgmtJSON(w, http.StatusCreated, map[string]string{"id": "abc"})
	resp := w.Result()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	var body map[string]string
	json.NewDecoder(resp.Body).Decode(&body)
	if body["id"] != "abc" {
		t.Fatalf("body id = %q, want abc", body["id"])
	}
}

func TestWriteMgmtError(t *testing.T) {
	w := httptest.NewRecorder()
	WriteMgmtError(w, http.StatusBadRequest, "invalid input")
	resp := w.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	var body map[string]string
	json.NewDecoder(resp.Body).Decode(&body)
	if body["error"] != "invalid input" {
		t.Fatalf("error = %q, want 'invalid input'", body["error"])
	}
}

func TestTOrDefault(t *testing.T) {
	tr := &testTranslator{overrides: map[string]string{"custom.key": "translated"}}

	tests := []struct {
		name     string
		tr       Translator
		lang     string
		key      string
		fallback string
		want     string
	}{
		{"translator returns value", tr, "en", "custom.key", "fallback", "translated"},
		{"translator returns key as-is", tr, "en", "missing.key", "fallback", "fallback"},
		{"nil translator", nil, "en", "custom.key", "fallback", "fallback"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tOrDefault(tt.tr, tt.lang, tt.key, tt.fallback)
			if got != tt.want {
				t.Errorf("tOrDefault = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHandleHealth(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/gateway/health", nil)
	handleHealth(w, r)
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var body map[string]string
	json.NewDecoder(resp.Body).Decode(&body)
	if body["status"] != "ok" {
		t.Fatalf("status = %q, want ok", body["status"])
	}
}

func TestMakeMetricsHandler(t *testing.T) {
	RegisterCounter(NewMetricCounter("test_requests", "Test requests", "method"))
	ms := NewManagementServer(ManagementServerConfig{
		BuildInfo: "test-build v1",
	})
	handler := ms.makeMetricsHandler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/gateway/metrics", nil)
	handler(w, r)
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body := w.Body.String()
	if !strings.Contains(body, "test-build") {
		t.Fatalf("expected build info in body, got: %s", body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Fatalf("Content-Type = %q", ct)
	}
}

func TestMakeAuditHandlerInvalidSince(t *testing.T) {
	dir := t.TempDir()
	auditFile := filepath.Join(dir, "audit.log")
	al, err := NewAuditLogger(auditFile, nil, 1024*1024, 3)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer al.Close()

	ms := NewManagementServer(ManagementServerConfig{
		AuditLogger: al,
	})
	handler := ms.makeAuditHandler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/gateway/audit?since=bad-date", nil)
	handler(w, r)
	resp := w.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid since, got %d", resp.StatusCode)
	}
}

func TestMakeAuditHandlerInvalidUntil(t *testing.T) {
	dir := t.TempDir()
	auditFile := filepath.Join(dir, "audit.log")
	al, err := NewAuditLogger(auditFile, nil, 1024*1024, 3)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer al.Close()

	ms := NewManagementServer(ManagementServerConfig{
		AuditLogger: al,
	})
	handler := ms.makeAuditHandler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/gateway/audit?until=bad-date", nil)
	handler(w, r)
	resp := w.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid until, got %d", resp.StatusCode)
	}
}

func TestWithRolesAuthenticated(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := testCA(t, dir)
	adminCert := testCert(t, dir, "admin", caCert, caKey, []string{"gateway:admin"})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{adminCert.cert},
	}

	handler := withRoles([]string{RoleAdmin}, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}, nil, "en")
	handler(w, r)
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Result().StatusCode)
	}
}

func TestWithRolesUnauthenticated(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)

	handler := withRoles([]string{RoleAdmin}, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}, nil, "en")
	handler(w, r)
	if w.Result().StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Result().StatusCode)
	}
}

func TestWithRolesForbidden(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := testCA(t, dir)
	auditCert := testCert(t, dir, "auditor", caCert, caKey, []string{"gateway:audit"})

	r := httptest.NewRequest("GET", "/test", nil)
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{auditCert.cert},
	}

	w := httptest.NewRecorder()
	handler := withRoles([]string{RoleAdmin}, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}, nil, "en")
	handler(w, r)
	if w.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Result().StatusCode)
	}
}

func TestWithRolesTranslation(t *testing.T) {
	tr := &testTranslator{overrides: map[string]string{"auth.mtls_required": "MTLS_REQUIRED"}}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	handler := withRoles([]string{RoleAdmin}, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}, tr, "en")
	handler(w, r)
	resp := w.Result()
	var body map[string]string
	json.NewDecoder(resp.Body).Decode(&body)
	if body["error"] != "MTLS_REQUIRED" {
		t.Fatalf("expected translated error, got: %q", body["error"])
	}
	_ = resp
}

// --- test helpers ---

type testCertPair struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

func testCA(t *testing.T, dir string) (*testCertPair, *testCertPair) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(2 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	writePEMFile(t, dir, "ca.pem", "CERTIFICATE", der)
	return &testCertPair{cert: cert, key: key}, &testCertPair{cert: cert, key: key}
}

func testCert(t *testing.T, dir, cn string, ca, caKey *testCertPair, ous []string) *testCertPair {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn, OrganizationalUnit: ous},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(2 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, caKey.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	writePEMFile(t, dir, cn+".pem", "CERTIFICATE", der)
	writePEMFile(t, dir, cn+".key", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key))
	return &testCertPair{cert: cert, key: key}
}

func writePEMFile(t *testing.T, dir, name, blockType string, der []byte) {
	t.Helper()
	f, err := os.Create(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	pem.Encode(f, &pem.Block{Type: blockType, Bytes: der})
}

func clientCAPool(t *testing.T, dir string) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	data, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pool.AppendCertsFromPEM(data)
	return pool
}

func testTLSConfig(t *testing.T, dir string) *tls.Config {
	t.Helper()
	ca, caKey := testCA(t, dir)
	srv := testCert(t, dir, "server", ca, caKey, nil)
	return &tls.Config{
		Certificates: []tls.Certificate{srv.TLSCertificate()},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool(t, dir),
	}
}

func mgmtRequest(t *testing.T, addr string, clientCert *testCertPair, pool *x509.CertPool, path string) string {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		Certificates:       []tls.Certificate{clientCert.TLSCertificate()},
		RootCAs:            pool,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer conn.Close()

	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n", path)
	fmt.Fprint(conn, req)
	buf := make([]byte, 8192)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil && err.Error() != "EOF" {
		t.Fatalf("read: %v", err)
	}
	return string(buf[:n])
}

func mgmtRequestWithMethod(t *testing.T, addr string, clientCert *testCertPair, pool *x509.CertPool, method, path, body string) string {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		Certificates:       []tls.Certificate{clientCert.TLSCertificate()},
		RootCAs:            pool,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer conn.Close()

	req := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: test\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		method, path, len(body), body)
	fmt.Fprint(conn, req)
	buf := make([]byte, 8192)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil && err.Error() != "EOF" {
		t.Fatalf("read: %v", err)
	}
	return string(buf[:n])
}

func mgmtDial(t *testing.T, addr string, clientCert *testCertPair, pool *x509.CertPool) *tls.Conn {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		Certificates:       []tls.Certificate{clientCert.TLSCertificate()},
		RootCAs:            pool,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	return conn
}

func TestManagementPluginsListEmpty(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := testCA(t, dir)
	srvCert := testCert(t, dir, "server", caCert, caKey, nil)
	clientCert := testCert(t, dir, "client", caCert, caKey, []string{"gateway:admin"})

	srvTLS := &tls.Config{
		Certificates: []tls.Certificate{srvCert.TLSCertificate()},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool(t, dir),
	}

	reg := NewPluginRegistry()
	addr := freePort(t)
	ms := NewManagementServer(ManagementServerConfig{
		Listen:         addr,
		TLSConfig:      srvTLS,
		PluginRegistry: reg,
	})
	go ms.Start()
	time.Sleep(100 * time.Millisecond)
	defer ms.Stop()

	pool := clientCAPool(t, dir)
	body := mgmtRequest(t, addr, clientCert, pool, "/api/v1/gateway/plugins")
	if !strings.Contains(body, "200 OK") {
		t.Fatalf("expected 200, got: %s", firstLine(body))
	}
	var summaries []PluginSummary
	extractJSONBody(t, body, &summaries)
	if len(summaries) != 0 {
		t.Fatalf("expected empty list, got %d", len(summaries))
	}
}

func TestManagementPluginsListWithPlugins(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := testCA(t, dir)
	srvCert := testCert(t, dir, "server", caCert, caKey, nil)
	clientCert := testCert(t, dir, "client", caCert, caKey, []string{"gateway:admin"})

	srvTLS := &tls.Config{
		Certificates: []tls.Certificate{srvCert.TLSCertificate()},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool(t, dir),
	}

	reg := NewPluginRegistry()
	cfgs := PluginConfigs{
		"tcp":  {Type: "allowlist", Config: map[string]interface{}{"allow": []string{"x"}}},
		"http": {Type: "denylist", Config: map[string]interface{}{"deny": []string{"y"}}},
	}
	if err := BuildPluginsFromConfig(reg, cfgs); err != nil {
		t.Fatal(err)
	}
	addr := freePort(t)
	ms := NewManagementServer(ManagementServerConfig{
		Listen:         addr,
		TLSConfig:      srvTLS,
		PluginRegistry: reg,
	})
	go ms.Start()
	time.Sleep(100 * time.Millisecond)
	defer ms.Stop()

	pool := clientCAPool(t, dir)
	body := mgmtRequest(t, addr, clientCert, pool, "/api/v1/gateway/plugins")
	if !strings.Contains(body, "200 OK") {
		t.Fatalf("expected 200, got: %s", firstLine(body))
	}
	var summaries []PluginSummary
	extractJSONBody(t, body, &summaries)
	if len(summaries) != 2 {
		t.Fatalf("expected 2 plugins, got %d", len(summaries))
	}
}

func TestManagementPluginsGetByScheme(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := testCA(t, dir)
	srvCert := testCert(t, dir, "server", caCert, caKey, nil)
	clientCert := testCert(t, dir, "client", caCert, caKey, []string{"gateway:admin"})

	srvTLS := &tls.Config{
		Certificates: []tls.Certificate{srvCert.TLSCertificate()},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool(t, dir),
	}

	reg := NewPluginRegistry()
	cfgs := PluginConfigs{
		"tcp": {Type: "allowlist", Config: map[string]interface{}{"allow": []string{"x"}}},
	}
	if err := BuildPluginsFromConfig(reg, cfgs); err != nil {
		t.Fatal(err)
	}
	addr := freePort(t)
	ms := NewManagementServer(ManagementServerConfig{
		Listen:         addr,
		TLSConfig:      srvTLS,
		PluginRegistry: reg,
	})
	go ms.Start()
	time.Sleep(100 * time.Millisecond)
	defer ms.Stop()

	pool := clientCAPool(t, dir)
	body := mgmtRequest(t, addr, clientCert, pool, "/api/v1/gateway/plugins/tcp")
	if !strings.Contains(body, "200 OK") {
		t.Fatalf("expected 200, got: %s", firstLine(body))
	}
	var summary PluginSummary
	extractJSONBody(t, body, &summary)
	if summary.Scheme != "tcp" {
		t.Fatalf("expected scheme tcp, got %s", summary.Scheme)
	}
	if summary.Type != "allowlist" {
		t.Fatalf("expected type allowlist, got %s", summary.Type)
	}
}

func TestManagementPluginsGetBySchemeNotFound(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := testCA(t, dir)
	srvCert := testCert(t, dir, "server", caCert, caKey, nil)
	clientCert := testCert(t, dir, "client", caCert, caKey, []string{"gateway:admin"})

	srvTLS := &tls.Config{
		Certificates: []tls.Certificate{srvCert.TLSCertificate()},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool(t, dir),
	}

	reg := NewPluginRegistry()
	addr := freePort(t)
	ms := NewManagementServer(ManagementServerConfig{
		Listen:         addr,
		TLSConfig:      srvTLS,
		PluginRegistry: reg,
	})
	go ms.Start()
	time.Sleep(100 * time.Millisecond)
	defer ms.Stop()

	pool := clientCAPool(t, dir)
	body := mgmtRequest(t, addr, clientCert, pool, "/api/v1/gateway/plugins/unknown")
	if !strings.Contains(body, "404") {
		t.Fatalf("expected 404, got: %s", firstLine(body))
	}
}

func firstLine(s string) string {
	v := strings.SplitN(s, "\n", 2)
	if len(v) > 0 {
		return strings.TrimSpace(v[0])
	}
	return s
}

func extractJSONBody(t *testing.T, resp string, v interface{}) {
	t.Helper()
	parts := strings.SplitN(resp, "\r\n\r\n", 2)
	if len(parts) < 2 {
		t.Fatalf("no body found in response: %s", firstLine(resp))
	}
	if err := json.Unmarshal([]byte(parts[1]), v); err != nil {
		t.Fatalf("json decode: %v, body: %s", err, parts[1])
	}
}

func (p *testCertPair) TLSCertificate() tls.Certificate {
	return tls.Certificate{
		Certificate: [][]byte{p.cert.Raw},
		PrivateKey:  p.key,
	}
}

// ---- Confirmed renewal management endpoints (P0-2, P2-A-12/17) ----

func TestManagementConfirmedRenewalEndpoints(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := testCA(t, dir)
	srvCert := testCert(t, dir, "server", caCert, caKey, nil)
	adminCert := testCert(t, dir, "admin", caCert, caKey, []string{"gateway:admin"})

	m := NewConfirmedRenewalManager(nil, nil, nil)
	srvTLS := &tls.Config{
		Certificates: []tls.Certificate{srvCert.TLSCertificate()},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool(t, dir),
	}
	addr := freePort(t)
	ms := NewManagementServer(ManagementServerConfig{
		Listen:                  addr,
		TLSConfig:               srvTLS,
		ConfirmedRenewalManager: m,
	})
	go ms.Start()
	time.Sleep(100 * time.Millisecond)
	defer ms.Stop()
	pool := clientCAPool(t, dir)

	// status before request → idle
	resp := mgmtRequest(t, addr, adminCert, pool, "/api/v1/gateway/renewal/status")
	if !strings.Contains(resp, "200 OK") {
		t.Fatalf("status expected 200, got: %s", firstLine(resp))
	}
	var st map[string]interface{}
	extractJSONBody(t, resp, &st)
	if st["status"] != "idle" {
		t.Fatalf("status = %v, want idle", st["status"])
	}

	// request
	conn := mgmtDial(t, addr, adminCert, pool)
	reqBody := `{"session_id":"sess-1","cn":"svc","agent_id":"agent-1","capabilities":[{"scheme_id":"tcp","capability_id":"tunnel:prod"}]}`
	req := fmt.Sprintf("POST /api/v1/gateway/renewal/request HTTP/1.1\r\nHost: test\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(reqBody), reqBody)
	fmt.Fprint(conn, req)
	buf := make([]byte, 8192)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := conn.Read(buf)
	resp = string(buf[:n])
	extractJSONBody(t, resp, &st)
	if st["status"] != "awaiting_confirmation" {
		t.Fatalf("status = %v, want awaiting_confirmation (body: %s)", st["status"], resp)
	}
	conn.Close()

	// reject
	conn = mgmtDial(t, addr, adminCert, pool)
	rejBody := `{"reason":"no"}`
	req = fmt.Sprintf("POST /api/v1/gateway/renewal/reject HTTP/1.1\r\nHost: test\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(rejBody), rejBody)
	fmt.Fprint(conn, req)
	buf = make([]byte, 8192)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ = conn.Read(buf)
	resp = string(buf[:n])
	extractJSONBody(t, resp, &st)
	if st["status"] != "rejected" {
		t.Fatalf("status = %v, want rejected (body: %s)", st["status"], resp)
	}
	conn.Close()
}

func TestManagementConfirmedRenewalConfirm(t *testing.T) {
	// Responsibility principal re-signs DA -> management API confirm -> status confirmed
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	principalCert := makeEntityCert(t, &key.PublicKey)
	principalPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: principalCert.Raw}))

	req := &RenewalRequest{
		SessionID:    "sess-c",
		AgentId:      "agent-1",
		PrincipalUid: "varwof:user@example.com:" + fp(key),
		CN:           "svc",
		OldSerial:    "A1",
		Capabilities: []Capability{{SchemeId: "tcp", CapabilityId: "tunnel:prod"}},
	}
	nonce := make([]byte, 32)
	rand.Read(nonce)
	da, err := SignRenewalDA(req, key, nonce, time.Now(), 3600, "RENEW", "confirm")
	if err != nil {
		t.Fatal(err)
	}
	payload := DAToPayload(da)
	payloadJSON, _ := json.Marshal(payload)

	m := NewConfirmedRenewalManager(nil, nil, nil)
	if err := m.RequestRenewal(req); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	caCert, caKey := testCA(t, dir)
	srvCert := testCert(t, dir, "server", caCert, caKey, nil)
	adminCert := testCert(t, dir, "admin", caCert, caKey, []string{"gateway:admin"})
	srvTLS := &tls.Config{
		Certificates: []tls.Certificate{srvCert.TLSCertificate()},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool(t, dir),
	}
	addr := freePort(t)
	ms := NewManagementServer(ManagementServerConfig{
		Listen:                  addr,
		TLSConfig:               srvTLS,
		ConfirmedRenewalManager: m,
	})
	go ms.Start()
	time.Sleep(100 * time.Millisecond)
	defer ms.Stop()
	pool := clientCAPool(t, dir)

	body := fmt.Sprintf(`{"session_id":"sess-c","principal_cert_pem":%q,"da":%s}`, principalPEM, string(payloadJSON))
	conn := mgmtDial(t, addr, adminCert, pool)
	reqLine := fmt.Sprintf("POST /api/v1/gateway/renewal/confirm HTTP/1.1\r\nHost: test\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
	fmt.Fprint(conn, reqLine)
	buf := make([]byte, 16384)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := conn.Read(buf)
	respBody := string(buf[:n])
	conn.Close()

	var st map[string]interface{}
	extractJSONBody(t, respBody, &st)
	if st["status"] != "confirmed" {
		t.Fatalf("status = %v, want confirmed (body: %s)", st["status"], respBody)
	}
	if m.State() != RenewalConfirmed {
		t.Fatalf("manager state = %s, want confirmed", m.State())
	}
}

func TestRenewalDAPayloadRoundTrip(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	req := &RenewalRequest{AgentId: "a", CN: "svc"}
	nonce := make([]byte, 32)
	rand.Read(nonce)
	ts := time.Now().Add(-time.Minute)
	da, err := SignRenewalDA(req, key, nonce, ts, 3600, "RENEW", "roundtrip")
	if err != nil {
		t.Fatal(err)
	}
	payload := DAToPayload(da)
	back, err := payload.toDelegationAuthorization()
	if err != nil {
		t.Fatal(err)
	}
	if back.Reason.ReasonCode != "RENEW" {
		t.Errorf("reason code = %q", back.Reason.ReasonCode)
	}
	if back.RequestedLifetime != 3600 {
		t.Errorf("lifetime = %d", back.RequestedLifetime)
	}
	if len(back.Nonce) != 32 {
		t.Errorf("nonce len = %d", len(back.Nonce))
	}
	if !back.Timestamp.Equal(ts) {
		t.Errorf("timestamp mismatch")
	}
	if !back.SignatureAlgorithm.Algorithm.Equal(da.SignatureAlgorithm.Algorithm) {
		t.Errorf("algo mismatch")
	}
	// Round-tripped DA can still be verified via responsibility principal cert (TBS recomputed consistently)
	cert := makeEntityCert(t, &key.PublicKey)
	if err := verifyRenewalDA(&RenewalRequest{AgentId: "a", CN: "svc"}, cert, back); err != nil {
		t.Errorf("verify round-tripped DA: %v", err)
	}
}

func readAllBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// ---- Task 5a: Policy versioning / rollback management API ----

func startPolicyMgmtServer(t *testing.T) (addr string, ms *ManagementServer, adminCert *testCertPair, pool *x509.CertPool) {
	t.Helper()
	dir := t.TempDir()
	caCert, caKey := testCA(t, dir)
	srvCert := testCert(t, dir, "server", caCert, caKey, nil)
	adminCert = testCert(t, dir, "admin", caCert, caKey, []string{"gateway:admin"})
	opsCert := testCert(t, dir, "ops", caCert, caKey, []string{"gateway:ops"})

	srvTLS := &tls.Config{
		Certificates: []tls.Certificate{srvCert.TLSCertificate()},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool(t, dir),
	}

	reg := NewPluginRegistry()
	pm := NewPolicyManager(reg)
	addr = freePort(t)
	ms = NewManagementServer(ManagementServerConfig{
		Listen:         addr,
		TLSConfig:      srvTLS,
		PluginRegistry: reg,
		PolicyManager:  pm,
	})
	go ms.Start()
	time.Sleep(100 * time.Millisecond)
	t.Cleanup(ms.Stop)
	_ = opsCert
	return addr, ms, adminCert, clientCAPool(t, dir)
}

func TestManagementPolicyVersionsLifecycle(t *testing.T) {
	addr, _, adminCert, pool := startPolicyMgmtServer(t)

	// PUT plugins -> publish v1
	body := mgmtRequestWithMethod(t, addr, adminCert, pool, "PUT", "/api/v1/gateway/plugins",
		`{"tcp":{"type":"allowlist","config":{"allow":["tunnel:prod"],"default_action":"deny"}}}`)
	if !strings.Contains(body, "200 OK") || !strings.Contains(body, `"policy_version":1`) {
		t.Fatalf("expected publish v1, got: %s", firstLine(body))
	}

	// Second PUT -> v2
	body = mgmtRequestWithMethod(t, addr, adminCert, pool, "PUT", "/api/v1/gateway/plugins",
		`{"tcp":{"type":"allowlist","config":{"allow":["tunnel:staging"],"default_action":"deny"}}}`)
	if !strings.Contains(body, `"policy_version":2`) {
		t.Fatalf("expected publish v2, got: %s", firstLine(body))
	}

	// GET versions -> 2 history entries
	body = mgmtRequest(t, addr, adminCert, pool, "/api/v1/gateway/policies/versions")
	var versionsResp struct {
		CurrentVersion uint64 `json:"current_version"`
		Count          int    `json:"count"`
		Versions       []struct {
			Version  uint64 `json:"version"`
			Source   string `json:"source"`
			Operator string `json:"operator"`
		} `json:"versions"`
	}
	extractJSONBody(t, body, &versionsResp)
	if versionsResp.CurrentVersion != 2 || versionsResp.Count != 2 {
		t.Fatalf("current=%d count=%d, want 2/2", versionsResp.CurrentVersion, versionsResp.Count)
	}
	if versionsResp.Versions[0].Operator != "admin" {
		t.Fatalf("operator = %q, want admin", versionsResp.Versions[0].Operator)
	}
	if versionsResp.Versions[0].Source != "api" {
		t.Fatalf("source = %q, want api", versionsResp.Versions[0].Source)
	}
}

func TestManagementPolicyRollbackAPI(t *testing.T) {
	addr, ms, adminCert, pool := startPolicyMgmtServer(t)

	// v1
	body := mgmtRequestWithMethod(t, addr, adminCert, pool, "PUT", "/api/v1/gateway/plugins",
		`{"tcp":{"type":"allowlist","config":{"allow":["tunnel:prod"],"default_action":"deny"}}}`)
	if !strings.Contains(body, `"policy_version":1`) {
		t.Fatalf("publish v1 failed: %s", firstLine(body))
	}
	// v2
	body = mgmtRequestWithMethod(t, addr, adminCert, pool, "PUT", "/api/v1/gateway/plugins",
		`{"tcp":{"type":"allowlist","config":{"allow":["tunnel:staging"],"default_action":"deny"}}}`)

	// Rollback to v1 -> new version v3
	body = mgmtRequestWithMethod(t, addr, adminCert, pool, "POST", "/api/v1/gateway/policies/rollback",
		`{"version":1}`)
	if !strings.Contains(body, "200 OK") || !strings.Contains(body, `"new_version":3`) {
		t.Fatalf("rollback failed: %s", firstLine(body))
	}

	// Active policy reverts to allowlist[tunnel:prod]
	ctx := &PluginContext{Context: context.Background()}
	res, err := ms.cfg.PolicyManager.Registry().Execute("tcp", &Capability{CapabilityId: "tunnel:prod"}, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != PluginAllow {
		t.Fatalf("after rollback expected allow, got %v", res.Decision)
	}

	// Unknown version rollback -> 400
	body = mgmtRequestWithMethod(t, addr, adminCert, pool, "POST", "/api/v1/gateway/policies/rollback",
		`{"version":99}`)
	if !strings.Contains(body, "400") {
		t.Fatalf("expected 400 for unknown version, got: %s", firstLine(body))
	}
}

func TestManagementPolicyVersionsNotConfigured(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := testCA(t, dir)
	srvCert := testCert(t, dir, "server", caCert, caKey, nil)
	adminCert := testCert(t, dir, "admin", caCert, caKey, []string{"gateway:admin"})

	srvTLS := &tls.Config{
		Certificates: []tls.Certificate{srvCert.TLSCertificate()},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool(t, dir),
	}

	reg := NewPluginRegistry()
	addr := freePort(t)
	ms := NewManagementServer(ManagementServerConfig{
		Listen:         addr,
		TLSConfig:      srvTLS,
		PluginRegistry: reg,
	})
	go ms.Start()
	time.Sleep(100 * time.Millisecond)
	defer ms.Stop()

	pool := clientCAPool(t, dir)
	body := mgmtRequest(t, addr, adminCert, pool, "/api/v1/gateway/policies/versions")
	if !strings.Contains(body, "404") {
		t.Fatalf("expected 404 when policy manager not configured, got: %s", firstLine(body))
	}
	body = mgmtRequestWithMethod(t, addr, adminCert, pool, "POST", "/api/v1/gateway/policies/rollback", `{"version":1}`)
	if !strings.Contains(body, "404") {
		t.Fatalf("expected 404 for rollback, got: %s", firstLine(body))
	}
}

func TestManagementPolicyRollbackForbiddenRole(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := testCA(t, dir)
	srvCert := testCert(t, dir, "server", caCert, caKey, nil)
	opsCert := testCert(t, dir, "ops", caCert, caKey, []string{"gateway:ops"})

	srvTLS := &tls.Config{
		Certificates: []tls.Certificate{srvCert.TLSCertificate()},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool(t, dir),
	}

	reg := NewPluginRegistry()
	pm := NewPolicyManager(reg)
	addr := freePort(t)
	ms := NewManagementServer(ManagementServerConfig{
		Listen:         addr,
		TLSConfig:      srvTLS,
		PluginRegistry: reg,
		PolicyManager:  pm,
	})
	go ms.Start()
	time.Sleep(100 * time.Millisecond)
	defer ms.Stop()

	pool := clientCAPool(t, dir)
	body := mgmtRequestWithMethod(t, addr, opsCert, pool, "POST", "/api/v1/gateway/policies/rollback", `{"version":1}`)
	if !strings.Contains(body, "403") {
		t.Fatalf("expected 403 for ops role, got: %s", firstLine(body))
	}
	// ops can read version list
	body = mgmtRequest(t, addr, opsCert, pool, "/api/v1/gateway/policies/versions")
	if !strings.Contains(body, "200 OK") {
		t.Fatalf("expected 200 for ops read, got: %s", firstLine(body))
	}
}

func TestManagementPolicyBranchesLifecycle(t *testing.T) {
	addr, ms, adminCert, pool := startPolicyMgmtServer(t)

	// publish v1 / v2
	body := mgmtRequestWithMethod(t, addr, adminCert, pool, "PUT", "/api/v1/gateway/plugins",
		`{"tcp":{"type":"allowlist","config":{"allow":["tunnel:prod"],"default_action":"deny"}}}`)
	if !strings.Contains(body, `"policy_version":1`) {
		t.Fatalf("publish v1 failed: %s", firstLine(body))
	}
	body = mgmtRequestWithMethod(t, addr, adminCert, pool, "PUT", "/api/v1/gateway/plugins",
		`{"tcp":{"type":"allowlist","config":{"allow":["tunnel:prod","tunnel:staging"],"default_action":"deny"}}}`)
	if !strings.Contains(body, `"policy_version":2`) {
		t.Fatalf("publish v2 failed: %s", firstLine(body))
	}

	// PUT branches -> canary uses v1
	body = mgmtRequestWithMethod(t, addr, adminCert, pool, "PUT", "/api/v1/gateway/policies/branches",
		`{"branches":[{"id":"canary","agent_id":"agent-canary-*","version":1,"priority":10,"comment":"canary rollout"}]}`)
	if !strings.Contains(body, "200 OK") || !strings.Contains(body, `"count":1`) {
		t.Fatalf("set branches failed: %s", firstLine(body))
	}

	// GET branches -> matched branches
	body = mgmtRequest(t, addr, adminCert, pool, "/api/v1/gateway/policies/branches")
	var brResp struct {
		Count    int            `json:"count"`
		Branches []PolicyBranch `json:"branches"`
	}
	extractJSONBody(t, body, &brResp)
	if brResp.Count != 1 || len(brResp.Branches) != 1 {
		t.Fatalf("branches count = %d/%d, want 1/1", brResp.Count, len(brResp.Branches))
	}
	if brResp.Branches[0].AgentID != "agent-canary-*" || brResp.Branches[0].Version != 1 {
		t.Fatalf("branch = %+v", brResp.Branches[0])
	}

	// Decision pipeline: canary Agent hits v1 (deny staging)
	version, _ := ms.cfg.PolicyManager.SelectRegistry("agent-canary-001")
	if version != 1 {
		t.Fatalf("canary version = %d, want 1", version)
	}

	// DELETE branches -> clear all
	body = mgmtRequestWithMethod(t, addr, adminCert, pool, "DELETE", "/api/v1/gateway/policies/branches", "")
	if !strings.Contains(body, "200 OK") || !strings.Contains(body, "policy_branches_cleared") {
		t.Fatalf("clear branches failed: %s", firstLine(body))
	}
	version, _ = ms.cfg.PolicyManager.SelectRegistry("agent-canary-001")
	if version != 2 {
		t.Fatalf("after clear version = %d, want 2", version)
	}
}

func TestManagementPolicyBranchesValidationAndRBAC(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := testCA(t, dir)
	srvCert := testCert(t, dir, "server", caCert, caKey, nil)
	adminCert := testCert(t, dir, "admin", caCert, caKey, []string{"gateway:admin"})
	opsCert := testCert(t, dir, "ops", caCert, caKey, []string{"gateway:ops"})
	srvTLS := &tls.Config{
		Certificates: []tls.Certificate{srvCert.TLSCertificate()},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool(t, dir),
	}
	reg := NewPluginRegistry()
	pm := NewPolicyManager(reg)
	addr := freePort(t)
	ms := NewManagementServer(ManagementServerConfig{
		Listen:         addr,
		TLSConfig:      srvTLS,
		PluginRegistry: reg,
		PolicyManager:  pm,
	})
	go ms.Start()
	time.Sleep(100 * time.Millisecond)
	t.Cleanup(ms.Stop)
	pool := clientCAPool(t, dir)

	// Reference unpublished version -> 400
	body := mgmtRequestWithMethod(t, addr, adminCert, pool, "PUT", "/api/v1/gateway/policies/branches",
		`{"branches":[{"id":"b","agent_id":"a-*","version":99}]}`)
	if !strings.Contains(body, "400") {
		t.Fatalf("expected 400 for unpublished version, got: %s", firstLine(body))
	}
	// Missing agent_id -> 400
	body = mgmtRequestWithMethod(t, addr, adminCert, pool, "PUT", "/api/v1/gateway/policies/branches",
		`{"branches":[{"id":"b","version":1}]}`)
	if !strings.Contains(body, "400") {
		t.Fatalf("expected 400 for missing agent_id, got: %s", firstLine(body))
	}
	// ops cannot write branches
	body = mgmtRequestWithMethod(t, addr, opsCert, pool, "PUT", "/api/v1/gateway/policies/branches",
		`{"branches":[{"id":"b","agent_id":"a-*","version":1}]}`)
	if !strings.Contains(body, "403") {
		t.Fatalf("expected 403 for ops write, got: %s", firstLine(body))
	}
	// ops can read branches
	body = mgmtRequest(t, addr, opsCert, pool, "/api/v1/gateway/policies/branches")
	if !strings.Contains(body, "200 OK") {
		t.Fatalf("expected 200 for ops read, got: %s", firstLine(body))
	}
}
