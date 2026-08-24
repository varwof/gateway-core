package gw

import (
	"context"
	"encoding/json"
	"testing"
)

func TestBuildFromConfig_Empty(t *testing.T) {
	r := NewPluginRegistry()
	if err := BuildPluginsFromConfig(r, nil); err != nil {
		t.Fatal(err)
	}
	if r.Len() != 0 {
		t.Fatalf("expected 0 plugins, got %d", r.Len())
	}
}

func TestBuildFromConfig_Allowlist(t *testing.T) {
	r := NewPluginRegistry()
	cfgs := PluginConfigs{
		"tcp": {
			Type: "allowlist",
			Config: map[string]interface{}{
				"allow":          []string{"tunnel:prod", "tunnel:staging"},
				"default_action": "deny",
			},
		},
	}
	if err := BuildPluginsFromConfig(r, cfgs); err != nil {
		t.Fatal(err)
	}
	if r.Len() != 1 {
		t.Fatalf("expected 1 plugin, got %d", r.Len())
	}
	ctx := &PluginContext{Context: context.Background()}
	// allowed
	res, err := r.Execute("tcp", &Capability{CapabilityId: "tunnel:prod"}, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != PluginAllow {
		t.Fatalf("expected allow, got %v", res.Decision)
	}
	// denied
	res, err = r.Execute("tcp", &Capability{CapabilityId: "tunnel:admin"}, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != PluginDeny {
		t.Fatalf("expected deny, got %v", res.Decision)
	}
}

func TestBuildFromConfig_Denylist(t *testing.T) {
	r := NewPluginRegistry()
	cfgs := PluginConfigs{
		"http": {
			Type: "denylist",
			Config: map[string]interface{}{
				"deny":           []string{"route:admin"},
				"default_action": "allow",
			},
		},
	}
	if err := BuildPluginsFromConfig(r, cfgs); err != nil {
		t.Fatal(err)
	}
	ctx := &PluginContext{Context: context.Background()}
	// denied
	res, err := r.Execute("http", &Capability{CapabilityId: "route:admin"}, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != PluginDeny {
		t.Fatalf("expected deny, got %v", res.Decision)
	}
	// allowed (default)
	res, err = r.Execute("http", &Capability{CapabilityId: "route:metrics"}, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != PluginAllow {
		t.Fatalf("expected allow, got %v", res.Decision)
	}
}

func TestBuildFromConfig_RBAC(t *testing.T) {
	r := NewPluginRegistry()
	cfgs := PluginConfigs{
		"quic": {
			Type: "rbac",
			Config: map[string]interface{}{
				"role_map": map[string]interface{}{
					"admin": []string{"stream:control", "stream:video"},
					"ops":   []string{"stream:metrics"},
				},
				"default_action": "deny",
			},
		},
	}
	if err := BuildPluginsFromConfig(r, cfgs); err != nil {
		t.Fatal(err)
	}
	ctx := &PluginContext{Context: context.Background()}
	// admin can access stream:control
	ctx.Roles = []string{"admin"}
	res, err := r.Execute("quic", &Capability{CapabilityId: "stream:control"}, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != PluginAllow {
		t.Fatalf("admin: expected allow, got %v", res.Decision)
	}
	// ops cannot access stream:control
	ctx.Roles = []string{"ops"}
	res, err = r.Execute("quic", &Capability{CapabilityId: "stream:control"}, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != PluginDeny {
		t.Fatalf("ops: expected deny, got %v", res.Decision)
	}
	// ops can access stream:metrics
	res, err = r.Execute("quic", &Capability{CapabilityId: "stream:metrics"}, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != PluginAllow {
		t.Fatalf("ops: expected allow for metrics, got %v", res.Decision)
	}
	// unknown role -> default deny
	ctx.Roles = []string{"auditor"}
	res, err = r.Execute("quic", &Capability{CapabilityId: "stream:metrics"}, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != PluginDeny {
		t.Fatalf("auditor: expected deny, got %v", res.Decision)
	}
}

func TestBuildFromConfig_RBAC_DefaultAllow(t *testing.T) {
	r := NewPluginRegistry()
	cfgs := PluginConfigs{
		"tcp": {
			Type: "rbac",
			Config: map[string]interface{}{
				"role_map": map[string]interface{}{
					"ops": []string{"tunnel:staging"},
				},
				"default_action": "allow",
			},
		},
	}
	if err := BuildPluginsFromConfig(r, cfgs); err != nil {
		t.Fatal(err)
	}
	ctx := &PluginContext{Context: context.Background(), Roles: []string{"unknown"}}
	res, err := r.Execute("tcp", &Capability{CapabilityId: "anything"}, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != PluginAllow {
		t.Fatalf("default allow: expected allow, got %v", res.Decision)
	}
}

func TestBuildFromConfig_RBAC_Wildcard(t *testing.T) {
	r := NewPluginRegistry()
	cfgs := PluginConfigs{
		"varwof/demo-mysql-v1": {
			Type: "rbac",
			Config: map[string]interface{}{
				"role_map": map[string]interface{}{
					"gateway:mysql-ops": []string{"*"},
				},
				"default_action": "deny",
			},
		},
	}
	if err := BuildPluginsFromConfig(r, cfgs); err != nil {
		t.Fatal(err)
	}
	ctx := &PluginContext{Context: context.Background(), Roles: []string{"gateway:mysql-ops"}}
	// wildcard grants any capability
	res, err := r.Execute("varwof/demo-mysql-v1", &Capability{SchemeId: "varwof/demo-mysql-v1", CapabilityId: "DELETE:*"}, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != PluginAllow {
		t.Fatalf("wildcard: expected allow, got %v", res.Decision)
	}
}

func TestBuildFromConfig_WebhookInvalid(t *testing.T) {
	r := NewPluginRegistry()
	cfgs := PluginConfigs{
		"tcp": {Type: "webhook", Config: map[string]interface{}{}},
	}
	err := BuildPluginsFromConfig(r, cfgs)
	if err == nil {
		t.Fatal("expected error for webhook without url")
	}
}

func TestBuildFromConfig_UnknownType(t *testing.T) {
	r := NewPluginRegistry()
	cfgs := PluginConfigs{
		"tcp": {Type: "magic", Config: map[string]interface{}{}},
	}
	err := BuildPluginsFromConfig(r, cfgs)
	if err == nil {
		t.Fatal("expected error for unknown type")
	}
}

func TestBuildFromConfig_NilValue(t *testing.T) {
	r := NewPluginRegistry()
	cfgs := PluginConfigs{"tcp": nil}
	if err := BuildPluginsFromConfig(r, cfgs); err != nil {
		t.Fatal(err)
	}
	if r.Len() != 0 {
		t.Fatalf("expected 0 plugins, got %d", r.Len())
	}
}

func TestBuildFromConfig_Replace(t *testing.T) {
	r := NewPluginRegistry()
	cfgs := PluginConfigs{
		"tcp": {Type: "allowlist", Config: map[string]interface{}{"allow": []string{"a"}}},
	}
	if err := BuildPluginsFromConfig(r, cfgs); err != nil {
		t.Fatal(err)
	}
	// rebuild with different config
	cfgs2 := PluginConfigs{
		"tcp": {Type: "denylist", Config: map[string]interface{}{"deny": []string{"b"}}},
	}
	if err := BuildPluginsFromConfig(r, cfgs2); err != nil {
		t.Fatal(err)
	}
	// old allowlist should be gone; new denylist in place
	ctx := &PluginContext{Context: context.Background()}
	_, err := r.Execute("tcp", &Capability{CapabilityId: "a"}, ctx)
	if err != nil {
		t.Fatal("scheme tcp should still be registered")
	}
}

func TestPluginTypeName(t *testing.T) {
	r := NewPluginRegistry()
	cfgs := PluginConfigs{
		"tcp": {Type: "allowlist", Config: map[string]interface{}{"allow": []string{"x"}}},
		"udp": {Type: "denylist", Config: map[string]interface{}{"deny": []string{"y"}}},
		"quic": {Type: "rbac", Config: map[string]interface{}{
			"role_map":       map[string]interface{}{"admin": []string{"z"}},
			"default_action": "deny",
		}},
	}
	if err := BuildPluginsFromConfig(r, cfgs); err != nil {
		t.Fatal(err)
	}
	tcpP, _ := r.Find("tcp")
	if PluginTypeName(tcpP) != "allowlist" {
		t.Fatalf("expected allowlist, got %s", PluginTypeName(tcpP))
	}
	udpP, _ := r.Find("udp")
	if PluginTypeName(udpP) != "denylist" {
		t.Fatalf("expected denylist, got %s", PluginTypeName(udpP))
	}
	quicP, _ := r.Find("quic")
	if PluginTypeName(quicP) != "rbac" {
		t.Fatalf("expected rbac, got %s", PluginTypeName(quicP))
	}
}

func TestPluginConfigJSON(t *testing.T) {
	raw := `{
		"tcp": {
			"type": "allowlist",
			"config": {
				"allow": ["tunnel:prod", "tunnel:staging"],
				"default_action": "deny"
			}
		},
		"http": {
			"type": "rbac",
			"config": {
				"role_map": { "admin": ["route:admin"] },
				"default_action": "deny"
			}
		}
	}`
	var cfgs PluginConfigs
	if err := json.Unmarshal([]byte(raw), &cfgs); err != nil {
		t.Fatal(err)
	}
	if len(cfgs) != 2 {
		t.Fatalf("expected 2 configs, got %d", len(cfgs))
	}
	r := NewPluginRegistry()
	if err := BuildPluginsFromConfig(r, cfgs); err != nil {
		t.Fatal(err)
	}
	if r.Len() != 2 {
		t.Fatalf("expected 2 plugins, got %d", r.Len())
	}
}
