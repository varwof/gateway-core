package gw

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"testing"
)

// makeAICCertWithCaps builds an AIC certificate with the given capabilities.
func makeAICCertWithCaps(t *testing.T, caps []Capability) *x509.Certificate {
	t.Helper()
	aic := AIC{
		AgentId:      "agent-cap-glob",
		PrincipalUid: PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "user@varwof.com"},
		Capabilities: caps,
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
	return makeCertWithExt(t, oidAIC, aicVal)
}

// TestRequiredCapabilitiesGlobMatch verifies glob matching semantics for RequiredCapabilities checks.
// Matching direction: policy requirement (id) is satisfied when covered by AIC declaration (pattern) — wildcard on the declaration side can authorize requests with specifics.
func TestRequiredCapabilitiesGlobMatch(t *testing.T) {
	// Simulate mysql example: AIC declares SELECT:* (wildcard), walkthrough requests varwof/demo-mysql-v1:SELECT:*
	cert := makeAICCertWithCaps(t, []Capability{{SchemeId: "varwof/demo-mysql-v1", CapabilityId: "SELECT:*"}})
	base := AdmissionConfig{RequireAIC: true}

	cases := []struct {
		name    string
		req     string
		wantErr bool
	}{
		{"fullname exact", "varwof/demo-mysql-v1:SELECT:*", false},
		{"fullname detail covered by wildcard", "varwof/demo-mysql-v1:SELECT:/api/tables", false},
		{"bare capabilityId", "SELECT:*", false},
		{"other op denied", "varwof/demo-mysql-v1:INSERT:*", true},
		{"other scheme denied", "http:GET:/admin", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			cfg.RequiredCapabilities = []string{tc.req}
			res := CheckAdmission(cert, cfg)
			denied := res.Decision == DecisionDeny
			if denied != tc.wantErr {
				t.Fatalf("req %q: denied=%v reason=%q, wantErr=%v", tc.req, denied, res.Reason, tc.wantErr)
			}
		})
	}
}

// TestRequiredCapabilitiesGlobDeclTooNarrow verifies rejection when declaration is too narrow:
// declaration is a specific capability, unable to cover a wildcard requirement.
func TestRequiredCapabilitiesGlobDeclTooNarrow(t *testing.T) {
	cert := makeAICCertWithCaps(t, []Capability{{SchemeId: "varwof/demo-mysql-v1", CapabilityId: "SELECT:/api/tables"}})
	cfg := AdmissionConfig{RequireAIC: true, RequiredCapabilities: []string{"varwof/demo-mysql-v1:SELECT:*"}}
	res := CheckAdmission(cert, cfg)
	if res.Decision != DecisionDeny {
		t.Fatalf("narrow decl should not cover wildcard req: %v", res.Decision)
	}
}

// TestRBACPluginGlobMatch verifies rbac plugin role_map glob matching: a single pattern authorizes multiple capabilities.
func TestRBACPluginGlobMatch(t *testing.T) {
	build := func(roleMap map[string]interface{}) *PluginRegistry {
		r := NewPluginRegistry()
		if err := BuildPluginsFromConfig(r, PluginConfigs{
			"varwof/demo-mysql-v1": {
				Type: "rbac",
				Config: map[string]interface{}{
					"role_map":       roleMap,
					"default_action": "deny",
				},
			},
		}); err != nil {
			t.Fatal(err)
		}
		return r
	}

	ctx := &PluginContext{Context: context.Background(), Roles: []string{"mysql-read"}}

	t.Run("scheme wildcard", func(t *testing.T) {
		r := build(map[string]interface{}{"mysql-read": []string{"varwof/demo-mysql-v1:*"}})
		cap := &Capability{SchemeId: "varwof/demo-mysql-v1", CapabilityId: "SELECT:*"}
		res, err := r.Execute("varwof/demo-mysql-v1", cap, ctx)
		if err != nil {
			t.Fatal(err)
		}
		if res.Decision != PluginAllow {
			t.Fatalf("varwof/demo-mysql-v1:* should allow varwof/demo-mysql-v1:SELECT:*: %v", res.Decision)
		}
	})

	t.Run("fullname exact", func(t *testing.T) {
		r := build(map[string]interface{}{"mysql-read": []string{"varwof/demo-mysql-v1:SELECT:*"}})
		res, err := r.Execute("varwof/demo-mysql-v1", &Capability{SchemeId: "varwof/demo-mysql-v1", CapabilityId: "SELECT:*"}, ctx)
		if err != nil {
			t.Fatal(err)
		}
		if res.Decision != PluginAllow {
			t.Fatalf("varwof/demo-mysql-v1:SELECT:* should allow: %v", res.Decision)
		}
	})

	t.Run("bare capabilityId", func(t *testing.T) {
		r := build(map[string]interface{}{"mysql-read": []string{"SELECT:*"}})
		res, err := r.Execute("varwof/demo-mysql-v1", &Capability{SchemeId: "varwof/demo-mysql-v1", CapabilityId: "SELECT:*"}, ctx)
		if err != nil {
			t.Fatal(err)
		}
		if res.Decision != PluginAllow {
			t.Fatalf("SELECT:* should allow: %v", res.Decision)
		}
	})

	t.Run("insert denied by select-only", func(t *testing.T) {
		r := build(map[string]interface{}{"mysql-read": []string{"varwof/demo-mysql-v1:SELECT:*"}})
		res, err := r.Execute("varwof/demo-mysql-v1", &Capability{SchemeId: "varwof/demo-mysql-v1", CapabilityId: "INSERT:*"}, ctx)
		if err != nil {
			t.Fatal(err)
		}
		if res.Decision != PluginDeny {
			t.Fatalf("INSERT should be denied: %v", res.Decision)
		}
	})

	t.Run("unmapped role denied", func(t *testing.T) {
		r := build(map[string]interface{}{"mysql-admin": []string{"*"}})
		res, err := r.Execute("varwof/demo-mysql-v1", &Capability{SchemeId: "varwof/demo-mysql-v1", CapabilityId: "SELECT:*"}, ctx)
		if err != nil {
			t.Fatal(err)
		}
		if res.Decision != PluginDeny {
			t.Fatalf("unmapped role should be denied: %v", res.Decision)
		}
	})
}
