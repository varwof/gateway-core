// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/varwof/gateway-core/acps"
)

const aacTestAIC = "1.2.156.3088.1.2.34C2.478BDF.3GF546.0JU4" // partner AIC (peer)

func aacTestCert(t *testing.T, cn string, sanAIC string) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(9000000),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}
	if sanAIC != "" {
		u, err := url.Parse("acps://" + sanAIC)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.URIs = []*url.URL{u}
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

func aacTestBearer(t *testing.T, jti string) *acps.DelegationRecord {
	t.Helper()
	now := time.Now().Unix()
	claims := map[string]any{
		"iss":                       "https://sts.example.com",
		"sub":                       "https://idp.example.com/realm#user-123",
		"aud":                       "acps:agent:" + aacTestAIC,
		"exp":                       now + 3600,
		"iat":                       now - 60,
		"jti":                       jti,
		"scope":                     "acps.skill.invoke:data.export",
		"act":                       "agent:" + aacTestAIC,
		"acps_subject_type":         "human",
		"acps_delegation_id":        "dlg-9001",
		"acps_delegation_mode":      acps.DelegationModeDynamic,
		"acps_target_aic":           aacTestAIC,
		"acps_chain_depth":          1,
		"acps_max_chain_depth":      5,
		"acps_allowed_partner_aics": []string{aacTestAIC},
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, sig, err := acps.SignRecord(payload, priv)
	if err != nil {
		t.Fatal(err)
	}
	return acps.NewSignedDelegation(acps.FromTokenClaims(claims), payload, sig, pub)
}

func aacAllowAll(dec *acps.AuthorizationDecision) acps.PolicyFunc {
	return func(*acps.AuthorizationRequest) (*acps.AuthorizationDecision, error) { return dec, nil }
}

func aacReq(action string, bearer *acps.DelegationRecord, sender string) *AACRequest {
	return &AACRequest{
		Action:   action,
		Resource: acps.AuthorizationResource{ResourceType: "skill", ResourceID: "data.export", SkillId: "data.export"},
		Bearer:   bearer,
		SenderID: sender,
	}
}

func aacConfig() *AACProfileConfig {
	return &AACProfileConfig{Enabled: true, Policy: aacAllowAll(acps.Allow())}
}

func TestRunAccessPipelineAAC_DisabledPassthrough(t *testing.T) {
	cert := aacTestCert(t, aacTestAIC, aacTestAIC)
	base := RunAccessPipeline([]*x509.Certificate{cert}, &PipelineConfig{})
	if !base.Granted {
		t.Fatalf("baseline pipeline denied: %s", base.DenyReason)
	}
	if got := RunAccessPipelineAAC([]*x509.Certificate{cert}, &PipelineConfig{}, nil, nil); !sameResult(got, base) {
		t.Fatalf("nil AAC profile must degenerate to pipeline: %+v vs %+v", got, base)
	}
	if got := RunAccessPipelineAAC([]*x509.Certificate{cert}, &PipelineConfig{}, &AACProfileConfig{Enabled: false}, nil); !sameResult(got, base) {
		t.Fatalf("disabled AAC profile must degenerate to pipeline: %+v vs %+v", got, base)
	}
}

func sameResult(a, b *PipelineResult) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Granted == b.Granted && a.DenyReason == b.DenyReason &&
		a.AgentId == b.AgentId && a.Principal == b.Principal
}

func TestRunAccessPipelineAAC_MissingIdentity(t *testing.T) {
	cert := aacTestCert(t, "not-an-aic/0", "")
	res := RunAccessPipelineAAC([]*x509.Certificate{cert}, &PipelineConfig{}, aacConfig(), aacReq("task.start", nil, ""))
	if res.Granted {
		t.Fatal("certificate without a peer AIC must be denied")
	}
	if res.DenyReason != "Authentication required" {
		t.Fatalf("DenyReason = %q, want public message", res.DenyReason)
	}
}

func TestRunAccessPipelineAAC_SenderIDMismatch(t *testing.T) {
	cert := aacTestCert(t, aacTestAIC, aacTestAIC)
	res := RunAccessPipelineAAC([]*x509.Certificate{cert}, &PipelineConfig{}, aacConfig(),
		aacReq("task.start", nil, "1.2.156.3088.1.1.34C2.478BDF.3GF546.0JU4"))
	if res.Granted {
		t.Fatal("senderId != peer AIC must be denied")
	}
	if res.DenyReason != "Authorization failed" {
		t.Fatalf("DenyReason = %q, want Authorization failed", res.DenyReason)
	}
}

func TestRunAccessPipelineAAC_NilPolicyFailsClosed(t *testing.T) {
	cert := aacTestCert(t, aacTestAIC, aacTestAIC)
	cfg := &AACProfileConfig{Enabled: true}
	res := RunAccessPipelineAAC([]*x509.Certificate{cert}, &PipelineConfig{}, cfg, aacReq("task.start", nil, ""))
	if res.Granted || res.DenyReason != "Authorization failed" {
		t.Fatalf("nil policy must fail closed: %+v", res)
	}
}

func TestRunAccessPipelineAAC_Allow(t *testing.T) {
	cert := aacTestCert(t, aacTestAIC, aacTestAIC)
	cfg := &AACProfileConfig{Enabled: true, Policy: aacAllowAll(acps.Allow())}
	pc := &PipelineConfig{}
	res := RunAccessPipelineAAC([]*x509.Certificate{cert}, pc, cfg, aacReq("task.start", nil, ""))
	if !res.Granted {
		t.Fatalf("allow decision denied: %+v", res)
	}
}

func TestRunAccessPipelineAAC_BearerAndReplay(t *testing.T) {
	cert := aacTestCert(t, aacTestAIC, aacTestAIC)
	guard := NewReplayGuard()
	nc := NewNonceCache()
	defer nc.Stop()
	cfg := &AACProfileConfig{Enabled: true, Policy: aacAllowAll(acps.Allow()), ReplayGuard: guard, NonceCache: nc}
	pc := &PipelineConfig{}
	bearer := aacTestBearer(t, "jti-9001")
	first := RunAccessPipelineAAC([]*x509.Certificate{cert}, pc, cfg, aacReq("task.start", bearer, ""))
	if !first.Granted {
		t.Fatalf("first call with bearer denied: %+v", first)
	}
	// Same peer re-presenting the same one-time-use jti is a replay
	// (AAC §14.3(2)), refused with the public message only.
	second := RunAccessPipelineAAC([]*x509.Certificate{cert}, pc, cfg, aacReq("task.start", bearer, ""))
	if second.Granted || second.DenyReason != "Invalid access token" {
		t.Fatalf("replayed jti must be denied with public message: %+v", second)
	}
	// A freshly issued jti is accepted again.
	fresh := aacTestBearer(t, "jti-9002")
	third := RunAccessPipelineAAC([]*x509.Certificate{cert}, pc, cfg, aacReq("task.start", fresh, ""))
	if !third.Granted {
		t.Fatalf("fresh jti denied: %+v", third)
	}
}

func TestRunAccessPipelineAAC_AuditSink(t *testing.T) {
	cert := aacTestCert(t, "not-an-aic/0", "")
	var got acps.AuditRecord
	cfg := &AACProfileConfig{
		Enabled:   true,
		Policy:    aacAllowAll(acps.Allow()),
		AuditSink: func(r acps.AuditRecord) { got = r },
	}
	res := RunAccessPipelineAAC([]*x509.Certificate{cert}, &PipelineConfig{}, cfg, aacReq("task.start", nil, ""))
	if res.Granted || res.DenyReason != "Authentication required" {
		t.Fatalf("decision = %+v", res)
	}
	if got.Event != "authorization_decision" || got.Decision != "deny" {
		t.Fatalf("audit record = %+v", got)
	}
	if got.ReasonCode != acps.ReasonInvalidPeerIdentity || got.Action != "task.start" {
		t.Fatalf("audit reason/action = %+v", got)
	}
}

func TestRunAccessPipelineAAC_AuditLoggerDrain(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "audit.log")
	logger, err := NewAuditLogger(logFile, nil, 1<<20, 2)
	if err != nil || logger == nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	cert := aacTestCert(t, aacTestAIC, aacTestAIC)
	pc := &PipelineConfig{AuditLogger: logger}
	res := RunAccessPipelineAAC([]*x509.Certificate{cert}, pc, aacConfig(), aacReq("task.start", nil, ""))
	if !res.Granted {
		t.Fatalf("allow decision denied: %+v", res)
	}
	if err := logger.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	text := string(data)
	if !strings.Contains(text, `"action":"authorization_decision"`) {
		t.Fatalf("audit log missing authorization_decision entry:\n%s", text)
	}
	if !strings.Contains(text, `"decision":"allow"`) || !strings.Contains(text, "\"level\":\"INFO\"") {
		t.Fatalf("audit log missing allow/INFO entry:\n%s", text)
	}
}
