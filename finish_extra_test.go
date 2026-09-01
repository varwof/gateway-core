// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"crypto/sha256"
)

// ── aic.go ──

func TestSigAlgoToOID(t *testing.T) {
	cases := []struct {
		algo x509.SignatureAlgorithm
		want AlgorithmIdentifier
	}{
		{x509.ECDSAWithSHA256, AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256}},
		{x509.ECDSAWithSHA384, AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA384}},
		{x509.ECDSAWithSHA512, AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA512}},
		{x509.SHA256WithRSA, AlgorithmIdentifier{Algorithm: OIDSigRSAWithSHA256}},
		{x509.SHA384WithRSA, AlgorithmIdentifier{Algorithm: OIDSigRSAWithSHA384}},
		{x509.SHA512WithRSA, AlgorithmIdentifier{Algorithm: OIDSigRSAWithSHA512}},
		{x509.PureEd25519, AlgorithmIdentifier{Algorithm: OIDSigEd25519}},
		{x509.SHA256WithRSAPSS, AlgorithmIdentifier{}},
	}
	for _, tc := range cases {
		got := sigAlgoToOID(tc.algo)
		if !got.Algorithm.Equal(tc.want.Algorithm) {
			t.Errorf("sigAlgoToOID(%v) = %v, want %v", tc.algo, got, tc.want)
		}
	}
}

func TestParsePrincipalUidLib(t *testing.T) {
	fp := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	pu, err := ParsePrincipalUid("varwof:alice:" + fp)
	if err != nil {
		t.Fatalf("parse valid: %v", err)
	}
	if pu.Realm != "varwof" || pu.Identifier != "alice" || len(pu.KeyHash) != 32 {
		t.Errorf("bad parse result: %+v", pu)
	}
	for _, bad := range []string{"no-colons", "a:b:!!!", "", ":" + strings.Repeat("x", 200) + ":abc"} {
		if _, err := ParsePrincipalUid(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestMakePrincipalUidFromCertLib(t *testing.T) {
	pool, caCert, caKey := newTestCA(t, "admin")
	cert, _ := newSignedCert(t, caCert, caKey, "u1", nil)
	der := cert.Raw

	pu := MakePrincipalUidFromCert("varwof", "u1", der)
	if len(pu.KeyHash) != sha256.Size {
		t.Fatalf("KeyHash length = %d, want %d", len(pu.KeyHash), sha256.Size)
	}
	// SPKI hash must match pki-types MakePrincipalUidFromCert.
	pubBytes, _ := x509.MarshalPKIXPublicKey(cert.PublicKey)
	want := sha256.Sum256(pubBytes)
	if !bytes.Equal(pu.KeyHash, want[:]) {
		t.Error("KeyHash does not match SPKI SHA-256")
	}
	_ = pool

	// Invalid DER → no KeyHash.
	bad := MakePrincipalUidFromCert("r", "i", []byte("garbage"))
	if len(bad.KeyHash) != 0 {
		t.Error("invalid DER should yield empty KeyHash")
	}
}

// ── policy.go ──

func TestBuildPolicyVerifyOptions(t *testing.T) {
	var nilPS *PolicySigningConfig
	if got, err := nilPS.BuildPolicyVerifyOptions(""); err != nil || got != nil {
		t.Fatalf("nil receiver = %v, %v; want nil, nil", got, err)
	}
	if got, err := (&PolicySigningConfig{Enabled: false}).BuildPolicyVerifyOptions(""); err != nil || got != nil {
		t.Fatalf("disabled = %v, %v; want nil, nil", got, err)
	}
	// Default: do not load CA, RequireAdminOU=true, suffix .sig.
	opts, err := (&PolicySigningConfig{Enabled: true}).BuildPolicyVerifyOptions("")
	if err != nil {
		t.Fatalf("enabled default: %v", err)
	}
	if opts == nil {
		t.Fatal("expected non-nil opts")
	}
	if !opts.RequireAdminOU || opts.Roots != nil {
		t.Errorf("default opts = %+v", opts)
	}

	requireFalse := false
	opts, err = (&PolicySigningConfig{Enabled: true, RequireAdminOU: &requireFalse}).BuildPolicyVerifyOptions("")
	if err != nil {
		t.Fatalf("requireAdminOU=false: %v", err)
	}
	if opts.RequireAdminOU {
		t.Error("RequireAdminOU should be false")
	}

	dir := t.TempDir()
	pool, caCert, caKey := newTestCA(t, "admin")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	opts, err = (&PolicySigningConfig{Enabled: true, CAFile: caPath}).BuildPolicyVerifyOptions("")
	if err != nil {
		t.Fatalf("with CA file: %v", err)
	}
	if opts.Roots == nil {
		t.Error("Roots should be loaded")
	}
	if _, err := (&PolicySigningConfig{Enabled: true, CAFile: filepath.Join(dir, "missing.pem")}).BuildPolicyVerifyOptions(""); err == nil {
		t.Error("missing CA file should error")
	}
	// Empty CAFile falls back to tlsClientCA.
	opts, err = (&PolicySigningConfig{Enabled: true}).BuildPolicyVerifyOptions(caPath)
	if err != nil {
		t.Fatalf("fallback CA: %v", err)
	}
	if opts.Roots == nil {
		t.Error("tlsClientCA fallback should load roots")
	}
	_ = pool
	_ = caKey
}

func TestLoadCAFromFile(t *testing.T) {
	dir := t.TempDir()
	pool, caCert, caKey := newTestCA(t, "admin")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	pool2, err := LoadCAFromFile(caPath)
	if err != nil {
		t.Fatalf("LoadCAFromFile: %v", err)
	}
	if pool2 == nil {
		t.Fatal("nil pool")
	}
	if _, err := LoadCAFromFile(filepath.Join(dir, "nope.pem")); err == nil {
		t.Error("missing file should error")
	}
	badPath := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(badPath, []byte("not a pem"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCAFromFile(badPath); err == nil {
		t.Error("non-PEM file should error")
	}
	_ = pool
	_ = caKey
}

func TestParseCertPEMVariants(t *testing.T) {
	dir := t.TempDir()
	pool, caCert, caKey := newTestCA(t, "admin")
	leaf, _ := newSignedCert(t, caCert, caKey, "leaf", nil)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	certPath := filepath.Join(dir, "leaf.pem")
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatal(err)
	}

	c, err := ParseCertPEM(certPEM)
	if err != nil || c.Subject.CommonName != "leaf" {
		t.Fatalf("ParseCertPEM = %v, %v", c, err)
	}
	c, err = ParseCertPEMFile(certPath)
	if err != nil || c.Subject.CommonName != "leaf" {
		t.Fatalf("ParseCertPEMFile = %v, %v", c, err)
	}
	if _, err := ParseCertPEM([]byte("garbage")); err == nil {
		t.Error("garbage cert PEM should error")
	}
	if _, err := ParseCertPEMFile(filepath.Join(dir, "missing.pem")); err == nil {
		t.Error("missing cert file should error")
	}
	_ = pool
}

func TestParsePrivateKeyPEMVariants(t *testing.T) {
	dir := t.TempDir()

	// PKCS#1 RSA
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)})
	k, err := ParsePrivateKeyPEM(rsaPEM)
	if err != nil {
		t.Fatalf("PKCS1: %v", err)
	}
	if _, ok := k.(*rsa.PrivateKey); !ok {
		t.Error("expected RSA key")
	}

	// EC
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecDER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	ecPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER})
	k, err = ParsePrivateKeyPEM(ecPEM)
	if err != nil {
		t.Fatalf("EC: %v", err)
	}
	if _, ok := k.(*ecdsa.PrivateKey); !ok {
		t.Error("expected EC key")
	}

	// PKCS#8
	p8DER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	p8PEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p8DER})
	k, err = ParsePrivateKeyPEM(p8PEM)
	if err != nil {
		t.Fatalf("PKCS8: %v", err)
	}
	if _, ok := k.(*rsa.PrivateKey); !ok {
		t.Error("expected RSA from PKCS8")
	}

	// Encrypted private key -> error
	encPEM := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("x")})
	if _, err := ParsePrivateKeyPEM(encPEM); err == nil {
		t.Error("encrypted key should error")
	}
	// Unknown type
	unkPEM := pem.EncodeToMemory(&pem.Block{Type: "FOO PRIVATE KEY", Bytes: []byte("x")})
	if _, err := ParsePrivateKeyPEM(unkPEM); err == nil {
		t.Error("unknown key type should error")
	}
	// Not PEM
	if _, err := ParsePrivateKeyPEM([]byte("garbage")); err == nil {
		t.Error("garbage should error")
	}

	// File version
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(keyPath, rsaPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePrivateKeyPEMFile(keyPath); err != nil {
		t.Fatalf("ParsePrivateKeyPEMFile: %v", err)
	}
	if _, err := ParsePrivateKeyPEMFile(filepath.Join(dir, "nope.pem")); err == nil {
		t.Error("missing key file should error")
	}
}

func TestLoadPolicySigningIdentity(t *testing.T) {
	dir := t.TempDir()
	_, caCert, caKey := newTestCA(t, "admin")
	leaf, leafKey := newSignedCert(t, caCert, caKey, "signer", []string{RoleAdmin})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPath := filepath.Join(dir, "s.pem")
	keyPath := filepath.Join(dir, "s.key")
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	id, err := LoadPolicySigningIdentity(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadPolicySigningIdentity: %v", err)
	}
	if id.Cert.Subject.CommonName != "signer" || id.Key == nil {
		t.Errorf("bad identity: %+v", id)
	}
	if _, err := LoadPolicySigningIdentity(filepath.Join(dir, "nope.pem"), keyPath); err == nil {
		t.Error("missing cert should error")
	}
	if _, err := LoadPolicySigningIdentity(certPath, filepath.Join(dir, "nope.pem")); err == nil {
		t.Error("missing key should error")
	}
}

func TestRoleGrants(t *testing.T) {
	p, err := ParseAuthorizationPolicy([]byte(testPolicyJSON))
	if err != nil {
		t.Fatal(err)
	}
	if got := p.RoleGrants("operator"); len(got) != 2 {
		t.Errorf("operator grants = %v", got)
	}
	if got := p.RoleGrants("nonexistent"); got != nil {
		t.Errorf("nonexistent role grants = %v, want nil", got)
	}
}

func TestGlobalPolicySetGetExtract(t *testing.T) {
	prev := GetAuthorizationPolicy()
	defer SetAuthorizationPolicy(prev)

	p, err := ParseAuthorizationPolicy([]byte(testPolicyJSON))
	if err != nil {
		t.Fatal(err)
	}
	SetAuthorizationPolicy(p)
	if GetAuthorizationPolicy() != p {
		t.Fatal("GetAuthorizationPolicy should return set policy")
	}

	pool, caCert, caKey := newTestCA(t, "admin")
	opsCert, _ := newSignedCert(t, caCert, caKey, "ops", []string{"gateway:ops"})
	roles := ExtractPolicyRoles(opsCert)
	found := map[string]bool{}
	for _, r := range roles {
		found[r] = true
	}
	if !found["operator"] {
		t.Errorf("expected policy-mapped role operator, got %v", roles)
	}
	if !found["gateway:ops"] {
		t.Errorf("expected hardcoded gateway:ops retained, got %v", roles)
	}

	// When policy is not set, falls back to hardcoded values.
	SetAuthorizationPolicy(nil)
	roles = ExtractPolicyRoles(opsCert)
	if len(roles) != 1 || roles[0] != "gateway:ops" {
		t.Errorf("nil policy fallback = %v, want [gateway:ops]", roles)
	}
	_ = pool
}

func TestLoadGatewayPolicy(t *testing.T) {
	prev := GetAuthorizationPolicy()
	defer SetAuthorizationPolicy(prev)

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "authz.json")
	if err := os.WriteFile(policyPath, []byte(testPolicyJSON), 0600); err != nil {
		t.Fatal(err)
	}

	// Empty path -> return immediately.
	if err := LoadGatewayPolicy("", "", nil, true); err != nil {
		t.Fatalf("empty path: %v", err)
	}
	// Success -> set global policy.
	if err := LoadGatewayPolicy(policyPath, ".sig", nil, true); err != nil {
		t.Fatalf("load valid: %v", err)
	}
	if GetAuthorizationPolicy() == nil {
		t.Fatal("policy should be set after LoadGatewayPolicy")
	}
	// require=true + bad file -> error.
	if err := LoadGatewayPolicy(filepath.Join(dir, "missing.json"), ".sig", nil, true); err == nil {
		t.Error("require=true with missing file should error")
	}
	// require=false + bad file -> degrade, return nil.
	if err := LoadGatewayPolicy(filepath.Join(dir, "missing.json"), ".sig", nil, false); err != nil {
		t.Errorf("require=false should degrade, got %v", err)
	}
}

// ── constraints.go ──

type emptyIDEvaluator struct{}

func (emptyIDEvaluator) CapabilityId() string { return "" }
func (emptyIDEvaluator) Evaluate(_ *Capability, _ *ConstraintContext) error {
	return nil
}

func TestReplaceConstraintGlobal(t *testing.T) {
	ResetConstraints()
	defer ResetConstraints()

	ev := &countingEvaluator{capabilityId: "custom-rc"}
	if err := ReplaceConstraint(ev); err != nil {
		t.Fatalf("ReplaceConstraint: %v", err)
	}
	got, err := globalConstraintRegistry.Find(ev.CapabilityId())
	if err != nil || got != ev {
		t.Fatalf("Find = %v, %v", got, err)
	}
	if err := ReplaceConstraint(nil); err == nil {
		t.Error("nil evaluator should error")
	}
	if err := ReplaceConstraint(emptyIDEvaluator{}); err == nil {
		t.Error("empty capabilityId should error")
	}
}

func TestSkipEvaluatorMaxConcurrent(t *testing.T) {
	ResetConstraints()
	defer ResetConstraints()
	cap := Capability{
		SchemeId:     "constraint",
		CapabilityId: ConstraintConcurrentKey,
		Parameters:   []byte(`{"max": 10}`),
	}
	if err := CheckAuthorizationConstraints([]Capability{cap}, "10.1.2.3"); err != nil {
		t.Fatalf("max-concurrent should pass through, got %v", err)
	}
}

// ── decision.go ──

func TestHasDelegatedAgentOUExported(t *testing.T) {
	if HasDelegatedAgentOU(nil) {
		t.Error("nil cert should not be delegated agent")
	}
	pool, caCert, caKey := newTestCA(t, "admin")
	daCert, _ := newSignedCert(t, caCert, caKey, "da", []string{"Delegated-Agent"})
	if !HasDelegatedAgentOU(daCert) {
		t.Error("Delegated-Agent OU should be detected")
	}
	normal, _ := newSignedCert(t, caCert, caKey, "u", []string{RoleOps})
	if HasDelegatedAgentOU(normal) {
		t.Error("normal cert should not be delegated agent")
	}
	_ = pool
}

func TestLogAdmission(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	LogAdmission(AdmissionResult{Decision: DecisionAllow, PrincipalUid: "p", Reason: ""}, "1.2.3.4", logger)
	LogAdmission(AdmissionResult{Decision: DecisionDeny, PrincipalUid: "p", Reason: "no"}, "1.2.3.4", logger)
	if !strings.Contains(buf.String(), "admission: allow") || !strings.Contains(buf.String(), "admission: deny") {
		t.Errorf("log output missing decisions: %s", buf.String())
	}
	// nil logger falls back to default, should not panic.
	LogAdmission(AdmissionResult{Decision: DecisionDeny, PrincipalUid: "p", Reason: "x"}, "1.2.3.4", nil)
}

func TestDelegatedAgentServerIdentityExtra(t *testing.T) {
	pool, caCert, caKey := newTestCA(t, "admin")
	daCert, _ := newSignedCert(t, caCert, caKey, "da", []string{"Delegated-Agent"})

	// Non-delegated cert -> all zeros.
	normal, _ := newSignedCert(t, caCert, caKey, "u", nil)
	if u, _, r := DelegatedAgentServerIdentity(normal, "p"); u != "" || r != "" {
		t.Errorf("non-delegated = %q, %q", u, r)
	}
	// DA cert -> has user, expiry bounded by cert NotAfter (finding 17).
	u, exp, r := DelegatedAgentServerIdentity(daCert, "")
	if u == "" || r != "" {
		t.Errorf("da cert = %q, %q", u, r)
	}
	if exp.IsZero() {
		t.Error("expiry must be bound to the certificate NotAfter (finding 17)")
	}
	// DA cert with explicit principal.
	u, _, r = DelegatedAgentServerIdentity(daCert, "user-x")
	if u != "user-x" || r != "" {
		t.Errorf("da with principal = %q, %q", u, r)
	}
	_ = pool
}

// ── alarm.go ──

func TestAlarmStartStop(t *testing.T) {
	cfg := &AlarmConfig{
		Rules: []AlarmRule{
			{Name: "r1", Metric: "m1", Operator: "gt", Threshold: 10, Cooldown: 0, Receiver: "rcv"},
		},
		Receivers: []AlarmReceiver{
			{Name: "rcv", Type: "webhook-unknown", Webhook: "http://127.0.0.1:1/hook"},
		},
	}
	a := NewAlarmClient(cfg)
	a.tick = 20 * time.Millisecond
	src := NewMetricSource("m1", 100)
	a.AddSource(src)

	stop := make(chan struct{})
	a.Start(stop)
	time.Sleep(80 * time.Millisecond)
	a.Stop()
	// External stopCh close path.
	b := NewAlarmClient(cfg)
	b.tick = 20 * time.Millisecond
	b.AddSource(src)
	extStop := make(chan struct{})
	b.Start(extStop)
	close(extStop)
	time.Sleep(50 * time.Millisecond)
}

func TestSnapshotSource(t *testing.T) {
	s := NewSnapshotSource(func() map[string]float64 {
		return map[string]float64{"connections_tcp": 7}
	})
	if s.Name() != "snapshot" {
		t.Errorf("Name = %q", s.Name())
	}
	if v, ok := s.Value(); !ok || v != 7 {
		t.Errorf("Value = %v, %v; want 7, true", v, ok)
	}
	other := NewSnapshotSource(func() map[string]float64 { return map[string]float64{"cpu": 1} })
	if _, ok := other.Value(); ok {
		t.Error("non-connections key should yield (0,false)")
	}
	nilFn := NewSnapshotSource(nil)
	if _, ok := nilFn.Value(); ok {
		t.Error("nil snapshot fn should yield (0,false)")
	}
}

func TestAggregateSourceSetUpdate(t *testing.T) {
	agg := NewAggregateSource()
	agg.Set("cpu", 10)
	agg.Set("cpu", 99) // update existing
	agg.Set("mem", 50) // new entry
	if len(agg.children) != 2 {
		t.Fatalf("children = %d, want 2", len(agg.children))
	}
	if agg.children[0].value != 99 {
		t.Errorf("cpu updated = %v, want 99", agg.children[0].value)
	}
}

// ── management.go ──

func TestManagementUpdatePluginRegistry(t *testing.T) {
	ms := NewManagementServer(ManagementServerConfig{})
	reg := NewPluginRegistry()
	ms.UpdatePluginRegistry(reg)
	ms.mu.Lock()
	got := ms.cfg.PluginRegistry
	ms.mu.Unlock()
	if got != reg {
		t.Error("UpdatePluginRegistry did not take effect")
	}
}

func TestManagementPutPluginsHandler(t *testing.T) {
	t.Run("no registry", func(t *testing.T) {
		ms := NewManagementServer(ManagementServerConfig{})
		h := ms.makePutPluginsHandler()
		rr := httptest.NewRecorder()
		h(rr, httptest.NewRequest(http.MethodPut, "/api/v1/gateway/plugins", strings.NewReader(`{}`)))
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("code = %d, want 503", rr.Code)
		}
	})
	t.Run("bad json", func(t *testing.T) {
		ms := NewManagementServer(ManagementServerConfig{PluginRegistry: NewPluginRegistry()})
		rr := httptest.NewRecorder()
		ms.makePutPluginsHandler()(rr, httptest.NewRequest(http.MethodPut, "/x", strings.NewReader(`{`)))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("code = %d, want 400", rr.Code)
		}
	})
	t.Run("success", func(t *testing.T) {
		ms := NewManagementServer(ManagementServerConfig{PluginRegistry: NewPluginRegistry()})
		body := `{"tcp":{"type":"allowlist","config":{"allow":["tunnel:prod"],"default_action":"deny"}}}`
		rr := httptest.NewRecorder()
		ms.makePutPluginsHandler()(rr, httptest.NewRequest(http.MethodPut, "/x", strings.NewReader(body)))
		if rr.Code != http.StatusOK {
			t.Fatalf("code = %d, body = %s", rr.Code, rr.Body.String())
		}
		if ms.cfg.PluginRegistry.Len() != 1 {
			t.Errorf("registry Len = %d, want 1", ms.cfg.PluginRegistry.Len())
		}
	})
	t.Run("invalid plugin config", func(t *testing.T) {
		ms := NewManagementServer(ManagementServerConfig{PluginRegistry: NewPluginRegistry()})
		body := `{"tcp":{"type":"no-such-type","config":{}}}`
		rr := httptest.NewRecorder()
		ms.makePutPluginsHandler()(rr, httptest.NewRequest(http.MethodPut, "/x", strings.NewReader(body)))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("code = %d, want 400", rr.Code)
		}
	})
}

func TestManagementDeletePluginsHandler(t *testing.T) {
	t.Run("no registry", func(t *testing.T) {
		ms := NewManagementServer(ManagementServerConfig{})
		rr := httptest.NewRecorder()
		ms.makeDeletePluginsHandler()(rr, httptest.NewRequest(http.MethodDelete, "/x", nil))
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("code = %d, want 503", rr.Code)
		}
	})
	t.Run("clears", func(t *testing.T) {
		reg := NewPluginRegistry()
		if err := BuildPluginsFromConfig(reg, PluginConfigs{
			"tcp": {Type: "allowlist", Config: map[string]interface{}{"allow": []string{"*"}}},
		}); err != nil {
			t.Fatal(err)
		}
		ms := NewManagementServer(ManagementServerConfig{PluginRegistry: reg})
		rr := httptest.NewRecorder()
		ms.makeDeletePluginsHandler()(rr, httptest.NewRequest(http.MethodDelete, "/x", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("code = %d", rr.Code)
		}
		if reg.Len() != 0 {
			t.Errorf("registry Len = %d, want 0", reg.Len())
		}
	})
}

func TestDisconnectByAgentHandler(t *testing.T) {
	reg := NewConnRegistry()
	closed := false
	reg.Register("agent-1", "user-1", func() { closed = true })
	h := MakeDisconnectByAgentHandler(reg, nil, "en")

	t.Run("wrong method", func(t *testing.T) {
		rr := httptest.NewRecorder()
		h(rr, httptest.NewRequest(http.MethodGet, "/disconnect", nil))
		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("code = %d, want 405", rr.Code)
		}
	})
	t.Run("bad body", func(t *testing.T) {
		rr := httptest.NewRecorder()
		h(rr, httptest.NewRequest(http.MethodPost, "/disconnect", strings.NewReader(`{`)))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("code = %d, want 400", rr.Code)
		}
	})
	t.Run("missing agent", func(t *testing.T) {
		rr := httptest.NewRecorder()
		h(rr, httptest.NewRequest(http.MethodPost, "/disconnect", strings.NewReader(`{"agent_id":""}`)))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("code = %d, want 400", rr.Code)
		}
	})
	t.Run("disconnect", func(t *testing.T) {
		rr := httptest.NewRecorder()
		h(rr, httptest.NewRequest(http.MethodPost, "/disconnect", strings.NewReader(`{"agent_id":"agent-1"}`)))
		if rr.Code != http.StatusOK {
			t.Fatalf("code = %d, body = %s", rr.Code, rr.Body.String())
		}
		if !closed {
			t.Error("close func was not invoked")
		}
		if !strings.Contains(rr.Body.String(), `"disconnected":1`) {
			t.Errorf("body = %s", rr.Body.String())
		}
	})
}

func TestDisconnectByUserHandler(t *testing.T) {
	reg := NewConnRegistry()
	closed := false
	reg.Register("agent-1", "user-1", func() { closed = true })
	h := MakeDisconnectByUserHandler(reg, nil, "en")

	rr := httptest.NewRecorder()
	h(rr, httptest.NewRequest(http.MethodGet, "/disconnect", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("method: code = %d, want 405", rr.Code)
	}
	rr = httptest.NewRecorder()
	h(rr, httptest.NewRequest(http.MethodPost, "/disconnect", strings.NewReader(`{`)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad body: code = %d, want 400", rr.Code)
	}
	rr = httptest.NewRecorder()
	h(rr, httptest.NewRequest(http.MethodPost, "/disconnect", strings.NewReader(`{"principal_uid":""}`)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("missing uid: code = %d, want 400", rr.Code)
	}
	rr = httptest.NewRecorder()
	h(rr, httptest.NewRequest(http.MethodPost, "/disconnect", strings.NewReader(`{"principal_uid":"user-1"}`)))
	if rr.Code != http.StatusOK || !closed {
		t.Fatalf("disconnect: code = %d closed=%v", rr.Code, closed)
	}
}

func TestConnRegistryFull(t *testing.T) {
	var nilReg *ConnRegistry
	if nilReg.Register("a", "b", func() {}) == nil {
		t.Error("nil receiver Register should return a func")
	}
	if nilReg.DisconnectByAgentId("a") != 0 || nilReg.DisconnectByPrincipalUid("b") != 0 || nilReg.Stats() != 0 {
		t.Error("nil receiver should be noop")
	}
	reg := NewConnRegistry()
	rm1 := reg.Register("agent-1", "uid-1", func() {})
	rm2 := reg.Register("agent-1", "uid-2", func() {})
	rm3 := reg.Register("agent-2", "uid-2", func() {})
	if reg.Stats() != 3 {
		t.Errorf("Stats = %d, want 3", reg.Stats())
	}
	// RemoveFunc is idempotent: calling twice only removes one entry.
	rm1()
	rm1()
	if reg.Stats() != 2 {
		t.Errorf("after rm1 Stats = %d, want 2", reg.Stats())
	}
	// Disconnect returns count of closed connections, and removes from byID/byUID index.
	if got := reg.DisconnectByAgentId("agent-1"); got != 1 {
		t.Errorf("DisconnectByAgentId = %d, want 1", got)
	}
	ids := reg.ListByAgentId()
	if len(ids) != 1 || ids["agent-2"] != 1 {
		t.Errorf("ListByAgentId = %v, want {agent-2:1}", ids)
	}
	// entries are cleaned up by each connection's RemoveFunc.
	rm2()
	rm3()
	if reg.Stats() != 0 {
		t.Errorf("Stats = %d, want 0", reg.Stats())
	}
}

// ── streammux.go ──

func TestStreamMuxRemoveLocal(t *testing.T) {
	ca, cb := net.Pipe()
	muxA := NewStreamMux(ca)
	muxB := NewStreamMux(cb)
	defer muxA.Close()
	defer muxB.Close()

	s, err := muxA.Open()
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := muxB.Accept()
	if err != nil {
		t.Fatal(err)
	}
	// Protocol has no accept-ack: opener's remoteID stays 0, only the acceptor gets a remoteID.
	if s.remoteID != 0 {
		t.Fatal("opener stream should have no remoteID")
	}
	if accepted.remoteID == 0 {
		t.Fatal("accepted stream should have remoteID")
	}
	// Stream with remoteID: both byLocalID and byRemID are cleaned.
	muxB.removeLocal(accepted.localID)
	muxB.mu.Lock()
	_, lok := muxB.byLocalID[accepted.localID]
	_, rok := muxB.byRemID[accepted.remoteID]
	muxB.mu.Unlock()
	if lok || rok {
		t.Error("accepted stream should be removed from both maps")
	}
	// Stream without remoteID: only clean byLocalID.
	muxA.removeLocal(s.localID)
	muxA.mu.Lock()
	_, ok := muxA.byLocalID[s.localID]
	muxA.mu.Unlock()
	if ok {
		t.Error("local stream should be removed from byLocalID")
	}
	// Unknown ID has no side effects.
	muxA.removeLocal(99999)
}

// ── ratelimit.go ──

func TestTokenBucketWaitNBlocking(t *testing.T) {
	tb := NewTokenBucket(100, 100)
	start := time.Now()
	tb.WaitN(100)
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Errorf("first WaitN(100) should be instant, took %v", elapsed)
	}
	start = time.Now()
	tb.WaitN(100) // needs refill ~1s
	if elapsed := time.Since(start); elapsed < 500*time.Millisecond {
		t.Errorf("second WaitN(100) should block until refill, took %v", elapsed)
	}
}

// ── configwatch.go ──

func TestConfigWatcherStartLoop(t *testing.T) {
	json := []byte(`{"version":"v1"}`)
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Write(json)
	}))
	defer server.Close()

	w := NewConfigWatcher(server.URL, nil, 20*time.Millisecond, func(data []byte) error {
		atomic.AddInt32(&calls, 1)
		if !strings.Contains(string(data), "version") {
			return fmt.Errorf("bad data: %s", data)
		}
		return nil
	})
	w.Start()
	time.Sleep(80 * time.Millisecond)
	w.Stop()
	if atomic.LoadInt32(&calls) == 0 {
		t.Error("onChange should have been called")
	}
	// After stop, Start should return immediately.
	w.Start()
}

// ── crl.go ──

func TestCRLCacheStart(t *testing.T) {
	caCert, caKey := testCACert(t)
	crlBytes, err := caCert.CreateCRL(rand.Reader, caKey, []pkix.RevokedCertificate{
		{SerialNumber: big.NewInt(7), RevocationTime: time.Now()},
	}, time.Now(), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	crlPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlBytes})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(crlPEM)
	}))
	defer server.Close()

	cache := NewCRLCache(caCert, server.URL, 3600, nil, "en")
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		cache.Start(stop)
		close(done)
	}()
	deadline := time.Now().Add(3 * time.Second)
	for cache.LastRefresh().IsZero() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if cache.LastRefresh().IsZero() {
		t.Fatal("CRL cache did not refresh")
	}
	close(stop)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after stop")
	}
}

// ── mesh.go integration: dialPeer / healthLoop / checkPeers / Forward / findPeerConn ──

func TestMeshDialHealthForwardIntegration(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := testCA(t, dir)
	srvCert := testCert(t, dir, "mesh-srv", caCert, caKey, nil)
	cliCert := testCert(t, dir, "mesh-cli", caCert, caKey, nil)
	pool := clientCAPool(t, dir)

	srvTLS := &tls.Config{
		Certificates: []tls.Certificate{srvCert.TLSCertificate()},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}
	cliTLS := &tls.Config{
		Certificates:       []tls.Certificate{cliCert.TLSCertificate()},
		RootCAs:            pool,
		InsecureSkipVerify: true,
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", srvTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(cc net.Conn) {
				io.Copy(cc, cc)
				cc.Close()
			}(c)
		}
	}()

	m := NewMeshManager(MeshConfig{
		LocalName:    "local",
		TLSConfig:    cliTLS,
		Peers:        []MeshPeer{{Name: "p1", Address: ln.Addr().String()}},
		DialTimeout:  2 * time.Second,
		PingInterval: 400 * time.Millisecond,
	})
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer m.Stop()

	deadline := time.Now().Add(3 * time.Second)
	for len(m.HealthyPeers()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(m.HealthyPeers()) != 1 {
		t.Fatal("peer did not become healthy")
	}

	// Forward: target unknown -> error.
	if err := m.Forward("nope", nil); err == nil {
		t.Error("Forward to unknown peer should error")
	}

	// Forward normal echo loop.
	p1, p2 := net.Pipe()
	fwdDone := make(chan error, 1)
	go func() { fwdDone <- m.Forward("p1", p1) }()
	p2.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := p2.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(p2, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "ping" {
		t.Errorf("echo = %q, want ping", buf)
	}
	p2.Close()
	select {
	case err := <-fwdDone:
		if err != nil {
			t.Fatalf("Forward: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Forward did not return")
	}

	// Wait for healthLoop/checkPeers to run a few rounds (including read timeout -> disconnect/reconnect path),
	// should eventually reconnect.
	deadline = time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if len(m.HealthyPeers()) >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
}
