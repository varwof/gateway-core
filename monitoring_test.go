// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// makeMonitoringServer builds a management server with ConnRegistry/AuditIndex
// and returns its *ManagementServer (tests use ms.mux.ServeHTTP directly to test routes).
// Also generates a gateway:admin client cert for injecting r.TLS to pass RBAC.
func makeMonitoringServer(t *testing.T, auditIndex *AuditIndex) *ManagementServer {
	t.Helper()
	return NewManagementServer(ManagementServerConfig{
		Listen:       "127.0.0.1:0",
		BuildInfo:    "test",
		AuditIndex:   auditIndex,
		ConnRegistry: NewConnRegistry(),
		Translator:   &testTranslator{},
		Lang:         "en",
	})
}

// mgmtTLSRequest constructs a request with an mTLS peer certificate.
func mgmtTLSRequest(t *testing.T, cert *x509.Certificate, method, target string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	return req
}

func TestMonitoringConnectionsEndpoint(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := testCA(t, dir)
	adminCert := testCert(t, dir, "admin", caCert, caKey, []string{"gateway:admin"})

	ms := makeMonitoringServer(t, nil)
	unreg := ms.cfg.ConnRegistry.RegisterConn("agent-1", "user@varwof.com", "10.0.0.5", "tcp", "1A2B", func() {})
	defer unreg()

	rec := httptest.NewRecorder()
	ms.mux.ServeHTTP(rec, mgmtTLSRequest(t, adminCert.cert, http.MethodGet, "/api/v1/gateway/connections"))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "agent-1") || !strings.Contains(body, "10.0.0.5") || !strings.Contains(body, "tcp") {
		t.Fatalf("connections body missing fields: %s", body)
	}
}

func TestMonitoringAccessPointsEndpoint(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := testCA(t, dir)
	adminCert := testCert(t, dir, "admin", caCert, caKey, []string{"gateway:admin"})

	ms := makeMonitoringServer(t, nil)
	a1 := ms.cfg.ConnRegistry.RegisterConn("agent-1", "u1", "10.0.0.5", "tcp", "1A", func() {})
	a2 := ms.cfg.ConnRegistry.RegisterConn("agent-2", "u2", "10.0.0.5", "http", "2B", func() {})
	defer a1()
	defer a2()

	rec := httptest.NewRecorder()
	ms.mux.ServeHTTP(rec, mgmtTLSRequest(t, adminCert.cert, http.MethodGet, "/api/v1/gateway/access-points"))
	body := rec.Body.String()
	if !strings.Contains(body, "10.0.0.5") || !strings.Contains(body, "agent-1") || !strings.Contains(body, "agent-2") {
		t.Fatalf("access-points body unexpected: %s", body)
	}
}

func TestMonitoringAgentsEndpoint(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := testCA(t, dir)
	adminCert := testCert(t, dir, "admin", caCert, caKey, []string{"gateway:admin"})

	ms := makeMonitoringServer(t, nil)
	unreg := ms.cfg.ConnRegistry.RegisterConn("agent-9", "user@varwof.com", "10.0.0.9", "dtls", "9F", func() {})
	defer unreg()

	rec := httptest.NewRecorder()
	ms.mux.ServeHTTP(rec, mgmtTLSRequest(t, adminCert.cert, http.MethodGet, "/api/v1/gateway/agents"))
	body := rec.Body.String()
	if !strings.Contains(body, "agent-9") || !strings.Contains(body, "user@varwof.com") ||
		!strings.Contains(body, "10.0.0.9") || !strings.Contains(body, "dtls") {
		t.Fatalf("agents body unexpected: %s", body)
	}
}

func TestMonitoringAuditSearchNoIndex(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := testCA(t, dir)
	adminCert := testCert(t, dir, "admin", caCert, caKey, []string{"gateway:admin"})

	ms := makeMonitoringServer(t, nil)
	rec := httptest.NewRecorder()
	ms.mux.ServeHTTP(rec, mgmtTLSRequest(t, adminCert.cert, http.MethodGet, "/api/v1/gateway/audit/search?q=deny"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 without audit index, got %d", rec.Code)
	}
}

func TestMonitoringAuditSearchIndexed(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := testCA(t, dir)
	adminCert := testCert(t, dir, "admin", caCert, caKey, []string{"gateway:admin"})

	idxPath := filepath.Join(t.TempDir(), "audit-index.db")
	idx, err := NewAuditIndex(idxPath)
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()

	entry := AuditEntry{
		Time:         time.Now().Format(time.RFC3339),
		Action:       "denied",
		SrcIP:        "10.0.0.5",
		ClientCN:     "agent-1",
		ClientSerial: "1A2B",
		Mapping:      "web-proxy",
		Target:       "secret",
		DenyReason:   "plugin deny",
		AgentId:      "agent-1",
		Protocol:     "http",
	}
	if err := idx.Index(&entry); err != nil {
		t.Fatal(err)
	}

	ms := makeMonitoringServer(t, idx)
	rec := httptest.NewRecorder()
	ms.mux.ServeHTTP(rec, mgmtTLSRequest(t, adminCert.cert, http.MethodGet, "/api/v1/gateway/audit/search?q=secret"))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"action":"denied"`) || !strings.Contains(body, `"agent_id":"agent-1"`) {
		t.Fatalf("search body unexpected: %s", body)
	}
}

func TestMonitoringAuditSearchFilters(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := testCA(t, dir)
	adminCert := testCert(t, dir, "admin", caCert, caKey, []string{"gateway:admin"})

	idxPath := filepath.Join(t.TempDir(), "audit-index.db")
	idx, err := NewAuditIndex(idxPath)
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()

	base := AuditEntry{
		Time:     time.Now().Format(time.RFC3339),
		Action:   "denied",
		SrcIP:    "10.0.0.5",
		ClientCN: "agent-1",
		Mapping:  "web-proxy",
		Target:   "secret",
		AgentId:  "agent-1",
		Protocol: "http",
	}
	if err := idx.Index(&base); err != nil {
		t.Fatal(err)
	}
	other := base
	other.ClientCN = "agent-2"
	other.AgentId = "agent-2"
	other.Mapping = "db-proxy"
	if err := idx.Index(&other); err != nil {
		t.Fatal(err)
	}

	ms := makeMonitoringServer(t, idx)

	rec := httptest.NewRecorder()
	ms.mux.ServeHTTP(rec, mgmtTLSRequest(t, adminCert.cert, http.MethodGet, "/api/v1/gateway/audit/search?agent_id=agent-1&limit=10"))
	body := rec.Body.String()
	if strings.Contains(body, "agent-2") {
		t.Fatalf("agent_id filter leaked agent-2: %s", body)
	}
	if !strings.Contains(body, `"count":1`) {
		t.Fatalf("expected count=1, got: %s", body)
	}

	rec2 := httptest.NewRecorder()
	ms.mux.ServeHTTP(rec2, mgmtTLSRequest(t, adminCert.cert, http.MethodGet, "/api/v1/gateway/audit/search?mapping=db-proxy&limit=10"))
	if !strings.Contains(rec2.Body.String(), "db-proxy") {
		t.Fatalf("mapping filter unexpected: %s", rec2.Body.String())
	}
}

func TestRegisterConnMetadata(t *testing.T) {
	r := NewConnRegistry()
	unreg := r.RegisterConn("agent-1", "user", "10.1.1.1", "udp", "CAFE", func() {})
	defer unreg()

	conns := r.ListConnections()
	if len(conns) != 1 {
		t.Fatalf("expected 1 connection, got %d", len(conns))
	}
	c := conns[0]
	if c.AgentId != "agent-1" || c.SrcIP != "10.1.1.1" || c.Protocol != "udp" || c.Serial != "CAFE" {
		t.Fatalf("unexpected connection info: %+v", c)
	}
	if c.Established == 0 {
		t.Fatal("established timestamp missing")
	}
	if got := r.ListByIP()["10.1.1.1"]; got != 1 {
		t.Fatalf("expected 1 conn for IP, got %d", got)
	}
	unreg()
	if got := r.Stats(); got != 0 {
		t.Fatalf("expected 0 after unregister, got %d", got)
	}
}

func TestMonitoringChainRefsEndpoint(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := testCA(t, dir)
	adminCert := testCert(t, dir, "admin", caCert, caKey, []string{"gateway:admin"})

	chain := NewAuditChain(1000, nil)
	chain.Seal([][]byte{[]byte("e1"), []byte("e2")}, "")

	store := NewChainRefStore()
	store.Record(ChainRef{Peer: "gw2", BatchNumber: 3, Root: "peer-root-3", Previous: "prev", Size: 42})

	ms := NewManagementServer(ManagementServerConfig{
		Listen:     "127.0.0.1:0",
		AuditChain: chain,
		ChainRefs:  store,
		Translator: &testTranslator{},
		Lang:       "en",
	})

	rec := httptest.NewRecorder()
	ms.mux.ServeHTTP(rec, mgmtTLSRequest(t, adminCert.cert, http.MethodGet, "/api/v1/gateway/audit/chain"))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"batch":0`) || !strings.Contains(body, "peer-root-3") || !strings.Contains(body, "gw2") {
		t.Fatalf("chain refs body unexpected: %s", body)
	}
}

func TestMonitoringChainRefsEndpointNoChain(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := testCA(t, dir)
	adminCert := testCert(t, dir, "admin", caCert, caKey, []string{"gateway:admin"})

	ms := NewManagementServer(ManagementServerConfig{
		Listen:     "127.0.0.1:0",
		Translator: &testTranslator{},
		Lang:       "en",
	})
	rec := httptest.NewRecorder()
	ms.mux.ServeHTTP(rec, mgmtTLSRequest(t, adminCert.cert, http.MethodGet, "/api/v1/gateway/audit/chain"))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"local":null`) || !strings.Contains(body, `"peers":null`) {
		t.Fatalf("expected null local/peers, got: %s", body)
	}
}
