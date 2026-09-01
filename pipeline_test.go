// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPipelineDenyOnEmptyChain(t *testing.T) {
	r := RunAccessPipeline(nil, &PipelineConfig{})
	if r.Granted {
		t.Error("expected nil chain to be denied")
	}
	if r.DenyReason != "no client certificate presented" {
		t.Errorf("unexpected deny reason: %s", r.DenyReason)
	}
}

func TestPipelineDenyOnNoRoles(t *testing.T) {
	cert := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(1 * time.Hour),
	}
	chain := []*x509.Certificate{cert}
	r := RunAccessPipeline(chain, &PipelineConfig{
		AllowRoles: []string{RoleAdmin},
	})
	if r.Granted {
		t.Error("expected cert without admin role to be denied")
	}
}

func TestPipelineAllowNoRolesConfigured(t *testing.T) {
	cert := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(1 * time.Hour),
	}
	chain := []*x509.Certificate{cert}
	r := RunAccessPipeline(chain, &PipelineConfig{})
	if !r.Granted {
		t.Errorf("expected cert to be allowed when no roles configured, got: %s", r.DenyReason)
	}
}

func TestPipelineExtractsRoles(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:         "admin",
			OrganizationalUnit: []string{"gateway:admin"},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(1 * time.Hour),
	}
	chain := []*x509.Certificate{cert}
	r := RunAccessPipeline(chain, &PipelineConfig{
		AllowRoles: []string{RoleAdmin},
	})
	if !r.Granted {
		t.Errorf("expected admin cert to be allowed: %s", r.DenyReason)
	}
	if len(r.Roles) != 1 || r.Roles[0] != RoleAdmin {
		t.Errorf("expected roles [gateway:admin], got %v", r.Roles)
	}
	if r.Serial == "" {
		t.Error("expected serial to be set")
	}
}

func TestPipelineCheckLeafOnly(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:         "leaf",
			OrganizationalUnit: []string{"gateway:ops"},
		},
		SerialNumber: big.NewInt(42),
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
	}
	chain := []*x509.Certificate{cert}
	r := RunAccessPipeline(chain, &PipelineConfig{
		AllowRoles: []string{RoleOps},
		CheckScope: CheckLeafOnly,
	})
	if !r.Granted {
		t.Errorf("expected leaf ops cert to be allowed: %s", r.DenyReason)
	}
	if r.Serial != "2a" {
		t.Errorf("expected serial 2a, got %s", r.Serial)
	}
}

func TestPipelineWithoutGS(t *testing.T) {
	cert := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "no-gs"},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(1 * time.Hour),
	}
	chain := []*x509.Certificate{cert}
	r := RunAccessPipeline(chain, &PipelineConfig{})
	if !r.Granted {
		t.Fatalf("expected allow: %s", r.DenyReason)
	}
}

func TestPipelineRequireAIC(t *testing.T) {
	cert := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "no-aic"},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(1 * time.Hour),
	}
	chain := []*x509.Certificate{cert}
	r := RunAccessPipeline(chain, &PipelineConfig{RequireAIC: true})
	if r.Granted {
		t.Fatal("expected denial when RequireAIC is true but no AIC extension")
	}
}

func TestPipelineRequireAICWithAICPresent(t *testing.T) {
	aic := AIC{
		AgentId:      "agent-1",
		PrincipalUid: PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "user@varwof.com"},
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
	aicVal, _ := asn1.Marshal(aic)
	cert := makeCertWithExt(t, oidAIC, aicVal)
	chain := []*x509.Certificate{cert}
	r := RunAccessPipeline(chain, &PipelineConfig{RequireAIC: true})
	if !r.Granted {
		t.Fatalf("expected allow when AIC is present: %s", r.DenyReason)
	}
	if r.AgentId != "agent-1" {
		t.Errorf("AgentId: expected agent-1, got %s", r.AgentId)
	}
	if r.Principal != "varwof:user@varwof.com:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
		t.Errorf("Principal: expected varwof:user@varwof.com:<keyhash>, got %s", r.Principal)
	}
}

func TestPipelinePluginsAllow(t *testing.T) {
	reg := NewPluginRegistry()
	cfgs := PluginConfigs{
		"tcp": {
			Type:   "allowlist",
			Config: map[string]interface{}{"allow": []string{"tunnel:prod"}, "default_action": "deny"},
		},
	}
	if err := BuildPluginsFromConfig(reg, cfgs); err != nil {
		t.Fatal(err)
	}

	aic := AIC{
		AgentId:      "agent-1",
		PrincipalUid: PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "user@varwof.com"},
		Capabilities: []Capability{{SchemeId: "tcp", CapabilityId: "tunnel:prod"}},
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
	aicVal, _ := asn1.Marshal(aic)
	cert := makeCertWithExt(t, oidAIC, aicVal)
	chain := []*x509.Certificate{cert}
	r := RunAccessPipeline(chain, &PipelineConfig{
		RequireAIC:               true,
		CapabilityPluginRegistry: reg,
	})
	if !r.Granted {
		t.Fatalf("expected allow: %s", r.DenyReason)
	}
}

func TestPipelinePluginsDeny(t *testing.T) {
	reg := NewPluginRegistry()
	cfgs := PluginConfigs{
		"tcp": {
			Type:   "allowlist",
			Config: map[string]interface{}{"allow": []string{"tunnel:prod"}, "default_action": "deny"},
		},
	}
	if err := BuildPluginsFromConfig(reg, cfgs); err != nil {
		t.Fatal(err)
	}

	aic := AIC{
		AgentId:      "agent-1",
		PrincipalUid: PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "user@varwof.com"},
		Capabilities: []Capability{{SchemeId: "tcp", CapabilityId: "tunnel:staging"}},
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
	aicVal, _ := asn1.Marshal(aic)
	cert := makeCertWithExt(t, oidAIC, aicVal)
	chain := []*x509.Certificate{cert}
	r := RunAccessPipeline(chain, &PipelineConfig{
		RequireAIC:               true,
		CapabilityPluginRegistry: reg,
	})
	if r.Granted {
		t.Fatal("expected denial for capability not in allowlist")
	}
}

func TestPipelinePluginsPAOnlyNoAIC(t *testing.T) {
	// User cert without AIC carries PA grants: plugin evaluation must take effect (EffectiveCaps = PA grants).
	reg := NewPluginRegistry()
	cfgs := PluginConfigs{
		"varwof/demo-mysql-v1": {
			Type: "rbac",
			Config: map[string]interface{}{
				"default_action": "deny",
				"role_map": map[string]interface{}{
					"gateway:admin":      []string{"*"},
					"gateway:mysql-read": []string{"varwof/demo-mysql-v1:SELECT:*"},
				},
			},
		},
	}
	if err := BuildPluginsFromConfig(reg, cfgs); err != nil {
		t.Fatal(err)
	}

	pa := PrincipalAuthorization{
		Grants: []Capability{
			{SchemeId: "varwof/demo-mysql-v1", CapabilityId: "SELECT:*"},
			{SchemeId: "varwof/demo-mysql-v1", CapabilityId: "INSERT:*"},
		},
	}
	paVal, err := asn1.Marshal(pa)
	if err != nil {
		t.Fatal(err)
	}

	// read role: SELECT authorized, INSERT not authorized -> plugin deny.
	readCert := makeCertWithRoleExt(t, []string{"gateway:mysql-read"}, oidPrincipalAuthorization, paVal)
	r := RunAccessPipeline([]*x509.Certificate{readCert}, &PipelineConfig{
		CapabilityPluginRegistry: reg,
	})
	if r.Granted {
		t.Fatalf("expected plugin denial for INSERT not in role_map, got granted: %s", r.DenyReason)
	}

	// admin role: wildcard authorization -> allow.
	adminCert := makeCertWithRoleExt(t, []string{"gateway:admin"}, oidPrincipalAuthorization, paVal)
	r2 := RunAccessPipeline([]*x509.Certificate{adminCert}, &PipelineConfig{
		CapabilityPluginRegistry: reg,
	})
	if !r2.Granted {
		t.Fatalf("expected admin granted, got: %s", r2.DenyReason)
	}
}

func TestPipelineRiskMonitorSignal(t *testing.T) {
	reg := NewPluginRegistry()
	cfgs := PluginConfigs{
		"tcp": {
			Type:   "allowlist",
			Config: map[string]interface{}{"allow": []string{"tunnel:prod"}, "default_action": "deny"},
		},
	}
	if err := BuildPluginsFromConfig(reg, cfgs); err != nil {
		t.Fatal(err)
	}

	aic := AIC{
		AgentId:      "agent-1",
		PrincipalUid: PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "user@varwof.com"},
		Capabilities: []Capability{{SchemeId: "tcp", CapabilityId: "tunnel:staging"}},
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
	aicVal, _ := asn1.Marshal(aic)
	cert := makeCertWithExt(t, oidAIC, aicVal)
	chain := []*x509.Certificate{cert}

	var fired atomic.Int32
	m := NewRiskMonitor(RiskMonitorConfig{
		Rules: []RiskRule{{
			Name: "abuse", Signals: []string{"plugin_deny"}, Threshold: 2,
			WindowSeconds: 60, Action: "revoke", Reason: "capability abuse",
		}},
		OnAction: func(agentId, action, reason string) {
			if agentId != "agent-1" {
				t.Errorf("unexpected agent %q", agentId)
			}
			fired.Add(1)
		},
	})

	cfg := &PipelineConfig{
		RequireAIC:               true,
		CapabilityPluginRegistry: reg,
		RiskMonitor:              m,
	}
	// Two plugin_deny -> trigger action; agentId correctly extracted from AIC
	for i := 0; i < 2; i++ {
		r := RunAccessPipeline(chain, cfg)
		if r.Granted {
			t.Fatal("expected denial")
		}
	}
	if fired.Load() != 1 {
		t.Fatalf("expected 1 risk action, got %d", fired.Load())
	}
}

func TestPipelinePluginsNoMatchingScheme(t *testing.T) {
	reg := NewPluginRegistry()
	cfgs := PluginConfigs{
		"http": {
			Type:   "allowlist",
			Config: map[string]interface{}{"allow": []string{"route:admin"}, "default_action": "deny"},
		},
	}
	if err := BuildPluginsFromConfig(reg, cfgs); err != nil {
		t.Fatal(err)
	}

	aic := AIC{
		AgentId:      "agent-1",
		PrincipalUid: PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "user@varwof.com"},
		Capabilities: []Capability{{SchemeId: "tcp", CapabilityId: "tunnel:prod"}},
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
	aicVal, _ := asn1.Marshal(aic)
	cert := makeCertWithExt(t, oidAIC, aicVal)
	chain := []*x509.Certificate{cert}
	// Phase 1: this gateway does not serve tcp scheme (no plugin) -> ignore, allow connection.
	// Multi-protocol Agent declaring unrelated scheme does not block connection (P2-A-06 unrelated scheme ignored).
	r := RunAccessPipeline(chain, &PipelineConfig{
		RequireAIC:               true,
		CapabilityPluginRegistry: reg,
	})
	if !r.Granted {
		t.Fatalf("expected allow (unrelated scheme ignored), got: %s", r.DenyReason)
	}
}

func TestPipelinePluginsNilRegistry(t *testing.T) {
	aic := AIC{
		AgentId:      "agent-1",
		PrincipalUid: PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "user@varwof.com"},
		Capabilities: []Capability{{SchemeId: "tcp", CapabilityId: "tunnel:prod"}},
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
	aicVal, _ := asn1.Marshal(aic)
	cert := makeCertWithExt(t, oidAIC, aicVal)
	chain := []*x509.Certificate{cert}
	r := RunAccessPipeline(chain, &PipelineConfig{
		RequireAIC: true,
	})
	if !r.Granted {
		t.Fatalf("expected allow with nil registry: %s", r.DenyReason)
	}
}

func TestPipelineDisallowRepresentative(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	aic := AIC{
		AgentId:        "agent-imp",
		PrincipalUid:   PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "user@varwof.com"},
		DelegationMode: DelegationRepresentative,
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
	aicVal, _ := asn1.Marshal(aic)
	pa := PrincipalAuthorization{
		DelegationPolicy: DelegationPolicy{Version: 1, AllowedMode: 1},
	}
	paVal, _ := asn1.Marshal(pa)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: oidAIC, Value: aicVal},
			{Id: oidUserPermission, Value: paVal},
		},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	chain := []*x509.Certificate{cert}
	r := RunAccessPipeline(chain, &PipelineConfig{
		RequireAIC:             true,
		DisallowRepresentative: true,
	})
	if r.Granted {
		t.Fatal("expected denial for representative mode")
	}

	aic2 := AIC{
		AgentId:      "agent-auth",
		PrincipalUid: PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "user@varwof.com"},
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
	aicVal2, _ := asn1.Marshal(aic2)
	pa2 := PrincipalAuthorization{
		DelegationPolicy: DelegationPolicy{Version: 1, AllowedMode: 0},
	}
	paVal2, _ := asn1.Marshal(pa2)
	tmpl2 := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: oidAIC, Value: aicVal2},
			{Id: oidUserPermission, Value: paVal2},
		},
	}
	der2, _ := x509.CreateCertificate(rand.Reader, tmpl2, tmpl2, &key.PublicKey, key)
	cert2, _ := x509.ParseCertificate(der2)
	chain2 := []*x509.Certificate{cert2}
	r2 := RunAccessPipeline(chain2, &PipelineConfig{
		RequireAIC:             true,
		DisallowRepresentative: true,
	})
	if !r2.Granted {
		t.Fatalf("expected allow for authorized mode: %s", r2.DenyReason)
	}
}

// TestPipelineAuthorizationConstraintsEnforced verifies authorizationConstraints
// (G1: three-gateway wiring of EnforceConstraints/StrictConstraints) are enforced
// in RunAccessPipeline: CIDR out-of-range denied, time-window outside denied,
// unknown type denied in strict mode, not enforced when EnforceConstraints=false
// (backward compatible).
func TestPipelineAuthorizationConstraintsEnforced(t *testing.T) {
	cidrOK := makeAICCertWithConstraints(t, []Capability{cidrCap(`["10.0.0.0/8"]`)})
	cidrBad := makeAICCertWithConstraints(t, []Capability{cidrCap(`["10.0.0.0/8"]`)})
	unknown := makeAICCertWithConstraints(t, []Capability{constrCap("custom:type", `{}`)})

	t.Run("cidr_allowed", func(t *testing.T) {
		r := RunAccessPipeline([]*x509.Certificate{cidrOK}, &PipelineConfig{
			ClientIP:           "10.1.2.3",
			EnforceConstraints: true,
		})
		if !r.Granted {
			t.Fatalf("expected allow, got %s", r.DenyReason)
		}
	})

	t.Run("cidr_denied_when_enforced", func(t *testing.T) {
		r := RunAccessPipeline([]*x509.Certificate{cidrBad}, &PipelineConfig{
			ClientIP:           "192.168.1.1",
			EnforceConstraints: true,
		})
		if r.Granted {
			t.Fatal("expected deny for IP outside allowed CIDR when enforced")
		}
	})

	t.Run("cidr_not_enforced_by_default", func(t *testing.T) {
		r := RunAccessPipeline([]*x509.Certificate{cidrBad}, &PipelineConfig{
			ClientIP: "192.168.1.1",
		})
		if !r.Granted {
			t.Fatalf("expected allow (constraints off by default), got %s", r.DenyReason)
		}
	})

	t.Run("time_window_inside", func(t *testing.T) {
		cert := makeAICCertWithConstraints(t, []Capability{
			timeWindowCap(`{"start":"00:00","end":"23:59"}`),
		})
		r := RunAccessPipeline([]*x509.Certificate{cert}, &PipelineConfig{
			ClientIP:           "10.1.2.3",
			EnforceConstraints: true,
		})
		if !r.Granted {
			t.Fatalf("expected allow inside window, got %s", r.DenyReason)
		}
	})

	t.Run("time_window_outside", func(t *testing.T) {
		cert := makeAICCertWithConstraints(t, []Capability{
			timeWindowCap(`{"start":"00:00","end":"00:00"}`),
		})
		r := RunAccessPipeline([]*x509.Certificate{cert}, &PipelineConfig{
			ClientIP:           "10.1.2.3",
			EnforceConstraints: true,
		})
		if r.Granted {
			t.Fatal("expected deny outside window")
		}
	})

	t.Run("unknown_strict_denied", func(t *testing.T) {
		r := RunAccessPipeline([]*x509.Certificate{unknown}, &PipelineConfig{
			ClientIP:           "10.1.2.3",
			EnforceConstraints: true,
			StrictConstraints:  true,
		})
		if r.Granted {
			t.Fatal("expected deny for unknown constraint in strict mode")
		}
	})

	t.Run("unknown_lenient_allowed", func(t *testing.T) {
		r := RunAccessPipeline([]*x509.Certificate{unknown}, &PipelineConfig{
			ClientIP:           "10.1.2.3",
			EnforceConstraints: true,
		})
		if !r.Granted {
			t.Fatalf("expected allow for unknown constraint in lenient mode, got %s", r.DenyReason)
		}
	})
}

// TestPipelineParameterBoundary verifies parameter-level boundary checking
// (P1-B-11 example semantics): principal authorizes max_rows=1000,
// Agent declares 100 -> allow; declares 5000 -> deny.
func TestPipelineParameterBoundary(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	reg := NewParameterValidatorRegistry()
	if err := reg.Register(MaxRowsValidator); err != nil {
		t.Fatal(err)
	}

	// makeCert constructs certificate with both AIC and PA extensions.
	makeCert := func(t *testing.T, aicCaps []Capability, paGrants []Capability, serial int64) *x509.Certificate {
		t.Helper()
		aic := AIC{
			AgentId:      "agent-1",
			PrincipalUid: PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "user@varwof.com"},
			Capabilities: aicCaps,
			DelegationAuthorization: DelegationAuthorization{
				Reason:             Reason{ReasonCode: "TEST", Description: "test"},
				Nonce:              make([]byte, 32),
				RequestedLifetime:  3600,
				SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
			},
		}
		aicVal, _ := asn1.Marshal(aic)
		pa := PrincipalAuthorization{Grants: paGrants}
		paVal, _ := asn1.Marshal(pa)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: "agent"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			ExtraExtensions: []pkix.Extension{
				{Id: oidAIC, Value: aicVal},
				{Id: oidUserPermission, Value: paVal},
			},
		}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		cert, _ := x509.ParseCertificate(der)
		return cert
	}

	paGrant := Capability{SchemeId: "report", CapabilityId: "list", Parameters: []byte(`{"max_rows": 1000}`)}

	t.Run("declared within boundary", func(t *testing.T) {
		cert := makeCert(t, []Capability{{SchemeId: "report", CapabilityId: "list", Parameters: []byte(`{"max_rows": 100}`)}}, []Capability{paGrant}, 1)
		r := RunAccessPipeline([]*x509.Certificate{cert}, &PipelineConfig{
			RequireAIC:          true,
			ParameterValidators: reg,
		})
		if !r.Granted {
			t.Fatalf("declared 100 within 1000 should be allowed: %s", r.DenyReason)
		}
	})

	t.Run("declared exceeds boundary", func(t *testing.T) {
		cert := makeCert(t, []Capability{{SchemeId: "report", CapabilityId: "list", Parameters: []byte(`{"max_rows": 5000}`)}}, []Capability{paGrant}, 2)
		r := RunAccessPipeline([]*x509.Certificate{cert}, &PipelineConfig{
			RequireAIC:          true,
			ParameterValidators: reg,
		})
		if r.Granted {
			t.Fatal("declared 5000 > 1000 should be denied")
		}
		if r.DenyReason == "" {
			t.Fatal("expected non-empty deny reason")
		}
	})

	t.Run("no validator registry → pass", func(t *testing.T) {
		cert := makeCert(t, []Capability{{SchemeId: "report", CapabilityId: "list", Parameters: []byte(`{"max_rows": 5000}`)}}, []Capability{paGrant}, 3)
		r := RunAccessPipeline([]*x509.Certificate{cert}, &PipelineConfig{
			RequireAIC: true,
		})
		if !r.Granted {
			t.Fatalf("no validators configured should allow: %s", r.DenyReason)
		}
	})
}

// TestPipelineCredentialBundleUserAuth verifies credential bundle prioritizes
// principal certificate parsing (P1-B-27/P1-B-29): when RequireUserAuth is set,
// uses credential bundle Principal certificate for signature verification,
// rejects on keyHash mismatch (Fail-Close).
func TestPipelineCredentialBundleUserAuth(t *testing.T) {
	pki := newTestBundlePKI(t)

	// principal certificate (with PA, key capable of verifying DA)
	principalKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	principalTmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(10),
		Subject:         pkix.Name{CommonName: "principal"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{paExt()},
	}
	principalDER, _ := x509.CreateCertificate(rand.Reader, principalTmpl, pki.root, &principalKey.PublicKey, pki.rootKey)
	principal, _ := x509.ParseCertificate(principalDER)

	// agent certificate (with AIC, DA signed by principal's private key)
	spki := sha256.Sum256(principal.RawSubjectPublicKeyInfo)
	aic := AIC{
		Version: 1,
		AgentId: "agent-1",
		PrincipalUid: PrincipalUid{
			Version:    1,
			Realm:      "varwof",
			Identifier: "user@varwof.com",
			KeyHash:    spki[:],
			HashAlgo:   AlgorithmIdentifier{Algorithm: OIDSHA256},
		},
	}
	// Build real DA signature
	signed := signDA(t, &aic, principalKey, principal)
	signedVal, _ := asn1.Marshal(*signed)
	agent := pki.issueLeaf(t, "agent", 20, []pkix.Extension{{Id: oidAIC, Value: signedVal}})

	t.Run("bundle provides principal → allow", func(t *testing.T) {
		bundle, _ := NewCredentialBundle([]*x509.Certificate{agent}, []*x509.Certificate{principal}, []*x509.Certificate{pki.root})
		r := RunAccessPipeline([]*x509.Certificate{agent}, &PipelineConfig{
			RequireAIC:       true,
			RequireUserAuth:  true,
			CredentialBundle: bundle,
		})
		if !r.Granted {
			t.Fatalf("bundle principal should allow user auth: %s", r.DenyReason)
		}
	})

	t.Run("bundle mismatched principal → deny", func(t *testing.T) {
		otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		otherDER, _ := x509.CreateCertificate(rand.Reader, principalTmpl, pki.root, &otherKey.PublicKey, pki.rootKey)
		other, _ := x509.ParseCertificate(otherDER)
		bundle, _ := NewCredentialBundle([]*x509.Certificate{agent}, []*x509.Certificate{other}, []*x509.Certificate{pki.root})
		r := RunAccessPipeline([]*x509.Certificate{agent}, &PipelineConfig{
			RequireAIC:       true,
			RequireUserAuth:  true,
			CredentialBundle: bundle,
		})
		if r.Granted {
			t.Fatal("bundle with mismatched principal should deny")
		}
	})

	t.Run("no bundle, no resolver → fallback to self (agent != user) deny", func(t *testing.T) {
		r := RunAccessPipeline([]*x509.Certificate{agent}, &PipelineConfig{
			RequireAIC:      true,
			RequireUserAuth: true,
		})
		if r.Granted {
			t.Fatal("no bundle/resolver: agent==user self-verify should deny")
		}
	})
}

func TestTwoStageCapabilityRouting(t *testing.T) {
	// Bug fix #1: multiple declared capabilities (including unauthorized/unrelated schemes)
	// no longer incorrectly deny authorized capabilities.
	// AIC declares tcp:tunnel:prod (gateway serves + plugin allow) + varwof/demo-mysql-v1:admin (unrelated scheme).
	// Gateway only serves tcp scheme (allowlist plugin), varwof/demo-mysql-v1 has no plugin -> ignore (P2-A-06).
	reg := NewPluginRegistry()
	cfgs := PluginConfigs{
		"tcp": {
			Type:   "allowlist",
			Config: map[string]interface{}{"allow": []string{"tunnel:prod"}, "default_action": "deny"},
		},
	}
	if err := BuildPluginsFromConfig(reg, cfgs); err != nil {
		t.Fatal(err)
	}

	aic := AIC{
		AgentId:      "agent-1",
		PrincipalUid: PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "user@varwof.com"},
		Capabilities: []Capability{
			{SchemeId: "tcp", CapabilityId: "tunnel:prod"},
			{SchemeId: "varwof/demo-mysql-v1", CapabilityId: "admin"}, // unrelated scheme, gateway does not serve
		},
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
	aicVal, _ := asn1.Marshal(aic)
	cert := makeCertWithExt(t, oidAIC, aicVal)
	chain := []*x509.Certificate{cert}
	r := RunAccessPipeline(chain, &PipelineConfig{
		RequireAIC:               true,
		CapabilityPluginRegistry: reg,
	})
	if !r.Granted {
		t.Fatalf("expected allow (tcp authorized, varwof/demo-mysql-v1 ignored): %s", r.DenyReason)
	}
}

func TestTwoStageCapabilityRoutingDeny(t *testing.T) {
	// Phase 1: declarations denied by plugin within a scheme served by this gateway reject the connection.
	reg := NewPluginRegistry()
	cfgs := PluginConfigs{
		"tcp": {
			Type:   "allowlist",
			Config: map[string]interface{}{"allow": []string{"tunnel:prod"}, "default_action": "deny"},
		},
	}
	if err := BuildPluginsFromConfig(reg, cfgs); err != nil {
		t.Fatal(err)
	}

	aic := AIC{
		AgentId:      "agent-1",
		PrincipalUid: PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "user@varwof.com"},
		Capabilities: []Capability{{SchemeId: "tcp", CapabilityId: "tunnel:staging"}},
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
	aicVal, _ := asn1.Marshal(aic)
	cert := makeCertWithExt(t, oidAIC, aicVal)
	chain := []*x509.Certificate{cert}
	r := RunAccessPipeline(chain, &PipelineConfig{
		RequireAIC:               true,
		CapabilityPluginRegistry: reg,
	})
	if r.Granted {
		t.Fatal("expected denial for capability not in allowlist")
	}
}

func TestCheckOperationCapability(t *testing.T) {
	reg := NewPluginRegistry()
	cfgs := PluginConfigs{
		"tcp": {
			Type:   "allowlist",
			Config: map[string]interface{}{"allow": []string{"tunnel:prod"}, "default_action": "deny"},
		},
	}
	if err := BuildPluginsFromConfig(reg, cfgs); err != nil {
		t.Fatal(err)
	}

	// Operation scheme has plugin and allowlist hits -> allow
	res, err := CheckOperationCapability(reg, &Capability{SchemeId: "tcp", CapabilityId: "tunnel:prod"}, &PluginContext{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Decision != PluginAllow {
		t.Fatalf("expected allow, got %v", res.Decision)
	}

	// Operation scheme has plugin but allowlist does not hit -> deny
	res, err = CheckOperationCapability(reg, &Capability{SchemeId: "tcp", CapabilityId: "tunnel:staging"}, &PluginContext{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Decision != PluginDeny {
		t.Fatalf("expected deny, got %v", res.Decision)
	}
}

func TestCheckOperationCapabilityFailClosed(t *testing.T) {
	reg := NewPluginRegistry()
	cfgs := PluginConfigs{
		"http": {
			Type:   "allowlist",
			Config: map[string]interface{}{"allow": []string{"route:admin"}, "default_action": "deny"},
		},
	}
	if err := BuildPluginsFromConfig(reg, cfgs); err != nil {
		t.Fatal(err)
	}

	// Phase 2: current operation scheme has no plugin -> fail-closed deny (P2-A-06)
	res, err := CheckOperationCapability(reg, &Capability{SchemeId: "tcp", CapabilityId: "tunnel:prod"}, &PluginContext{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Decision != PluginDeny {
		t.Fatalf("expected fail-closed deny, got %v", res.Decision)
	}
	if res.Reason == "" {
		t.Fatal("expected reason for fail-closed deny")
	}

	// nil registry / nil capability -> error
	if _, err := CheckOperationCapability(nil, &Capability{SchemeId: "tcp", CapabilityId: "tunnel:prod"}, nil); err == nil {
		t.Fatal("expected error for nil registry")
	}
	if _, err := CheckOperationCapability(reg, nil, nil); err == nil {
		t.Fatal("expected error for nil capability")
	}
}

func aicWithAgent(t *testing.T, agentID, capabilityID string) *x509.Certificate {
	t.Helper()
	aic := AIC{
		AgentId:      agentID,
		PrincipalUid: PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "user@varwof.com"},
		Capabilities: []Capability{{SchemeId: "tcp", CapabilityId: capabilityID}},
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
	aicVal, _ := asn1.Marshal(aic)
	return makeCertWithExt(t, oidAIC, aicVal)
}

// TestPipelineBranchResolver task 5b: branch control wiring -- Agent hitting branch uses
// branch version policy, fallback to current version when not matched.
// Asserts plugin evaluation and audit version binding both use branch version.
func TestPipelineBranchResolver(t *testing.T) {
	pm := NewPolicyManager(NewPluginRegistry())
	v1, _ := pm.Publish(PluginConfigs{
		"tcp": {Type: "allowlist", Config: map[string]interface{}{"allow": []string{"tunnel:prod"}, "default_action": "deny"}},
	}, "api", "admin@corp")
	_, _ = pm.Publish(PluginConfigs{
		"tcp": {Type: "allowlist", Config: map[string]interface{}{"allow": []string{"tunnel:prod", "tunnel:staging"}, "default_action": "deny"}},
	}, "api", "admin@corp")
	if err := pm.SetBranches([]PolicyBranch{{ID: "canary", AgentID: "agent-canary-*", Version: v1, Priority: 10}}); err != nil {
		t.Fatal(err)
	}

	resolver := func(agentID string) (uint64, *PluginRegistry) { return pm.SelectRegistry(agentID) }

	// canary Agent declares staging -> hits v1 branch (deny)
	chain := []*x509.Certificate{aicWithAgent(t, "agent-canary-9", "tunnel:staging")}
	r := RunAccessPipeline(chain, &PipelineConfig{
		RequireAIC:               true,
		CapabilityPluginResolver: resolver,
	})
	if r.Granted {
		t.Fatal("expected deny for canary agent hitting v1 branch")
	}

	// regular Agent declares staging -> falls back to current v2 (allow)
	chain = []*x509.Certificate{aicWithAgent(t, "agent-main-1", "tunnel:staging")}
	r = RunAccessPipeline(chain, &PipelineConfig{
		RequireAIC:               true,
		CapabilityPluginResolver: resolver,
	})
	if !r.Granted {
		t.Fatalf("expected allow for mainline agent, got: %s", r.DenyReason)
	}
}

// TestPipelineBranchResolverPolicyVersion asserts audit entry binds branch version after hitting a branch.
func TestPipelineBranchResolverPolicyVersion(t *testing.T) {
	pm := NewPolicyManager(NewPluginRegistry())
	v1, _ := pm.Publish(PluginConfigs{
		"tcp": {Type: "allowlist", Config: map[string]interface{}{"allow": []string{"tunnel:prod"}, "default_action": "deny"}},
	}, "api", "admin@corp")
	_, _ = pm.Publish(PluginConfigs{
		"tcp": {Type: "allowlist", Config: map[string]interface{}{"allow": []string{"tunnel:prod", "tunnel:staging"}, "default_action": "deny"}},
	}, "api", "admin@corp")
	_ = pm.SetBranches([]PolicyBranch{{ID: "canary", AgentID: "agent-canary-*", Version: v1, Priority: 10}})

	auditFile := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := NewAuditLogger(auditFile, nil, 10*1024*1024, 3)
	if err != nil {
		t.Fatal(err)
	}
	chain := []*x509.Certificate{aicWithAgent(t, "agent-canary-5", "tunnel:prod")}
	r := RunAccessPipeline(chain, &PipelineConfig{
		RequireAIC:               true,
		CapabilityPluginResolver: func(agentID string) (uint64, *PluginRegistry) { return pm.SelectRegistry(agentID) },
		AuditLogger:              logger,
	})
	if !r.Granted {
		t.Fatalf("expected allow: %s", r.DenyReason)
	}
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}
	entries, err := ReadAuditEntries(auditFile, AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Action == string(ActionPluginDecision) && e.PolicyVersion == v1 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("no plugin decision audit bound to branch version %d; entries=%d", v1, len(entries))
	}
}

// TestPipelineOfflineLifetime verifies G2(b): offline mode enforces remaining cert validity <= upper bound.
// When OfflineMaxCertLifetime>0, remaining validity exceeding limit -> deny; within limit -> allow;
// 0 (not enforced) -> always allow.
func TestPipelineOfflineLifetime(t *testing.T) {
	makeAICCert := func(validity time.Duration) *x509.Certificate {
		t.Helper()
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		aic := AIC{
			AgentId:      "agent-offline",
			PrincipalUid: PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "user@varwof.com"},
			Capabilities: []Capability{{SchemeId: "tcp", CapabilityId: "tunnel:prod"}},
			DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
				Nonce:              make([]byte, 32),
				RequestedLifetime:  3600,
				SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
			},
		}
		aicVal, _ := asn1.Marshal(aic)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: "agent-offline"},
			NotBefore:    time.Now().Add(-time.Minute),
			NotAfter:     time.Now().Add(validity),
			ExtraExtensions: []pkix.Extension{
				{Id: oidAIC, Value: aicVal},
			},
		}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		cert, _ := x509.ParseCertificate(der)
		return cert
	}

	offline := time.Hour // G2(b): offline mode enforces <=1h.

	t.Run("remaining exceeds limit rejected", func(t *testing.T) {
		cert := makeAICCert(5 * time.Hour)
		r := RunAccessPipeline([]*x509.Certificate{cert}, &PipelineConfig{
			RequireAIC:             true,
			OfflineMaxCertLifetime: offline,
		})
		if r.Granted {
			t.Fatal("long-validity cert must be rejected in offline mode (G2(b))")
		}
		if !strings.Contains(r.DenyReason, "offline mode") {
			t.Fatalf("deny reason should mention offline mode, got: %s", r.DenyReason)
		}
	})

	t.Run("within limit allowed", func(t *testing.T) {
		cert := makeAICCert(30 * time.Minute)
		r := RunAccessPipeline([]*x509.Certificate{cert}, &PipelineConfig{
			RequireAIC:             true,
			OfflineMaxCertLifetime: offline,
		})
		if !r.Granted {
			t.Fatalf("short-validity cert must be allowed in offline mode: %s", r.DenyReason)
		}
	})

	t.Run("disabled allows any", func(t *testing.T) {
		cert := makeAICCert(24 * time.Hour)
		r := RunAccessPipeline([]*x509.Certificate{cert}, &PipelineConfig{
			RequireAIC: true,
		})
		if !r.Granted {
			t.Fatalf("OfflineMaxCertLifetime=0 must not restrict: %s", r.DenyReason)
		}
	})
}

// TestOfflineLifetimeFor verifies G2(b) helper: OCSPFallbackAllow and
// OCSPFallbackCRL -> 1h cap (finding 11), deny/disabled -> 0.
func TestOfflineLifetimeFor(t *testing.T) {
	for _, fb := range []string{OCSPFallbackAllow, OCSPFallbackCRL} {
		if got := OfflineLifetimeFor(fb); got != time.Hour {
			t.Fatalf("%q → want 1h, got %s", fb, got)
		}
	}
	for _, fb := range []string{OCSPFallbackDeny, "", "bogus"} {
		if got := OfflineLifetimeFor(fb); got != 0 {
			t.Fatalf("%q → want 0, got %s", fb, got)
		}
	}
}
