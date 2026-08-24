// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ── constraints.go: RegisterGeoResolver early-return branches ──

func TestRegisterGeoResolverInvalid(t *testing.T) {
	// Empty name / nil fn must not register.
	RegisterGeoResolver("", nil)
	RegisterGeoResolver("", func(ip string) (string, error) { return "", nil })
	RegisterGeoResolver("still-not-registered", nil)
	if _, ok := geoResolvers["still-not-registered"]; ok {
		t.Fatal("nil fn should not register")
	}
	name := "reg-ok-" + time.Now().Format("150405.000000000")
	RegisterGeoResolver(name, func(ip string) (string, error) { return "CN", nil })
	defer delete(geoResolvers, name)
	if _, ok := geoResolvers[name]; !ok {
		t.Fatal("valid resolver should register")
	}
}

// ── management.go: RegisterHandler no-roles branch ──

func TestManagementRegisterHandlerNoRoles(t *testing.T) {
	ms := NewManagementServer(ManagementServerConfig{})
	called := false
	ms.RegisterHandler("/api/v1/gateway/no-roles", func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
	})
	rr := httptest.NewRecorder()
	ms.mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/gateway/no-roles", nil))
	if !called || rr.Code != http.StatusTeapot {
		t.Fatalf("called=%v code=%d", called, rr.Code)
	}
}

// ── mesh.go: checkPeers all branches ──

func TestMeshCheckPeersReconnect(t *testing.T) {
	m := NewMeshManager(MeshConfig{
		LocalName:   "t",
		Peers:       []MeshPeer{{Name: "x", Address: "127.0.0.1:1"}},
		DialTimeout: 200 * time.Millisecond,
	})

	// Unhealthy peer → redial fails (connection refused).
	m.mu.Lock()
	m.peers = append(m.peers, &peerConn{peer: MeshPeer{Name: "bad", Address: "127.0.0.1:1"}, logger: m.logger})
	m.mu.Unlock()
	m.checkPeers()

	// Healthy peer but dead connection → Read error → marked unhealthy, triggers redial goroutine.
	c1, c2 := net.Pipe()
	c1.Close()
	pc := &peerConn{
		peer:    MeshPeer{Name: "dead", Address: "127.0.0.1:1"},
		conn:    c2,
		tlsConn: tls.Client(c2, &tls.Config{InsecureSkipVerify: true}),
		logger:  m.logger,
	}
	pc.healthy.Store(true)
	m.mu.Lock()
	m.peers = append(m.peers, pc)
	m.mu.Unlock()
	m.checkPeers()
	if pc.healthy.Load() {
		t.Error("peer with dead conn should be marked unhealthy")
	}
	// Idempotent: checkPeers again must not panic.
	m.checkPeers()
	m.Stop()
}

// ── selfverify.go: VerifyCurrentExecutable error path ──

func TestVerifyCurrentExecutableErrorPath(t *testing.T) {
	// Test binary has no <path>.p7s, must fail.
	if err := VerifyCurrentExecutable(nil); err == nil {
		t.Fatal("expected error for unsigned test binary")
	}
}

// ── tsa_proof.go: Stop ──

func TestTSAProofLoggerStop(t *testing.T) {
	l := NewTSAProofLogger("", nil, nil, 3600)
	l.Stop()
}

// ── ocsp.go: fallbackErr three branches ──

func TestOCSPFallbackErrBranches(t *testing.T) {
	tr := &testTranslator{overrides: map[string]string{
		"ocsp.fallback_allow": "allow %s",
		"ocsp.fallback_crl":   "crl %s",
		"ocsp.fallback_deny":  "deny %s",
	}}
	c := NewOCSPCache(time.Minute, OCSPFallbackAllow, tr, "en")
	if err := c.fallbackErr("boom %d", 1); err != nil {
		t.Errorf("allow fallback should return nil, got %v", err)
	}
	c.fallback = OCSPFallbackCRL
	if err := c.fallbackErr("boom %d", 2); err != nil {
		t.Errorf("crl fallback should return nil, got %v", err)
	}
	c.fallback = OCSPFallbackDeny
	if err := c.fallbackErr("boom %d", 3); err == nil {
		t.Error("deny fallback should return error")
	}
}
