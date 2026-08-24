// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"context"
	"testing"
)

func allowlistConfig(allow []string) PluginConfigs {
	return PluginConfigs{
		"tcp": {
			Type: "allowlist",
			Config: map[string]interface{}{
				"allow":          allow,
				"default_action": "deny",
			},
		},
	}
}

func runPluginDecision(t *testing.T, reg *PluginRegistry, capabilityID string) PluginDecision {
	t.Helper()
	ctx := &PluginContext{Context: context.Background()}
	res, err := reg.Execute("tcp", &Capability{CapabilityId: capabilityID}, ctx)
	if err != nil {
		t.Fatalf("execute %q: %v", capabilityID, err)
	}
	return res.Decision
}

func TestPolicyManager_PublishAndVersion(t *testing.T) {
	reg := NewPluginRegistry()
	pm := NewPolicyManager(reg)

	v1, err := pm.Publish(allowlistConfig([]string{"tunnel:prod"}), "api", "admin@corp")
	if err != nil {
		t.Fatal(err)
	}
	if v1 != 1 {
		t.Fatalf("expected version 1, got %d", v1)
	}
	if pm.CurrentVersion() != 1 {
		t.Fatalf("current version = %d", pm.CurrentVersion())
	}
	if got := runPluginDecision(t, reg, "tunnel:prod"); got != PluginAllow {
		t.Fatalf("v1 allow failed: %v", got)
	}

	v2, err := pm.Publish(allowlistConfig([]string{"tunnel:staging"}), "sighup", "")
	if err != nil {
		t.Fatal(err)
	}
	if v2 != 2 {
		t.Fatalf("expected version 2, got %d", v2)
	}
	// v2 policy takes effect
	if got := runPluginDecision(t, reg, "tunnel:staging"); got != PluginAllow {
		t.Fatalf("v2 allow failed: %v", got)
	}
	if got := runPluginDecision(t, reg, "tunnel:prod"); got != PluginDeny {
		t.Fatalf("v2 should deny prod: %v", got)
	}
}

func TestPolicyManager_Rollback(t *testing.T) {
	reg := NewPluginRegistry()
	pm := NewPolicyManager(reg)

	_, _ = pm.Publish(allowlistConfig([]string{"tunnel:prod"}), "api", "admin@corp")
	v2, _ := pm.Publish(allowlistConfig([]string{"tunnel:staging"}), "api", "admin@corp")

	// Rollback to v1 → produces new version v3 (version number does not go back)
	v3, err := pm.Rollback(1, "api", "admin@corp")
	if err != nil {
		t.Fatal(err)
	}
	if v3 <= v2 {
		t.Fatalf("rollback version %d must exceed %d", v3, v2)
	}
	if pm.CurrentVersion() != v3 {
		t.Fatalf("current version = %d, want %d", pm.CurrentVersion(), v3)
	}
	if got := runPluginDecision(t, reg, "tunnel:prod"); got != PluginAllow {
		t.Fatalf("rollback restore v1 allow failed: %v", got)
	}

	// History contains all 3 snapshots
	hist := pm.History()
	if len(hist) != 3 {
		t.Fatalf("history length = %d, want 3", len(hist))
	}
	if hist[2].RolledBackFrom != 1 {
		t.Fatalf("rollback source = %d, want 1", hist[2].RolledBackFrom)
	}
}

func TestPolicyManager_RollbackUnknownVersion(t *testing.T) {
	pm := NewPolicyManager(NewPluginRegistry())
	_, _ = pm.Publish(allowlistConfig([]string{"tunnel:prod"}), "api", "admin@corp")
	if _, err := pm.Rollback(99, "api", "admin@corp"); err == nil {
		t.Fatal("expected error for unknown version")
	}
}

func TestPolicyManager_RollbackMinBlocked(t *testing.T) {
	pm := NewPolicyManager(NewPluginRegistry())
	pm.MinRollbackVersion = 2
	_, _ = pm.Publish(allowlistConfig([]string{"tunnel:prod"}), "api", "admin@corp")
	_, _ = pm.Publish(allowlistConfig([]string{"tunnel:staging"}), "api", "admin@corp")
	if _, err := pm.Rollback(1, "api", "admin@corp"); err == nil {
		t.Fatal("expected rollback below min to be blocked")
	}
}

func TestPolicyManager_MaxHistoryTrim(t *testing.T) {
	pm := NewPolicyManager(NewPluginRegistry())
	pm.MaxHistory = 3
	for i := 0; i < 6; i++ {
		if _, err := pm.Publish(allowlistConfig([]string{"tunnel:prod"}), "api", ""); err != nil {
			t.Fatal(err)
		}
	}
	hist := pm.History()
	if len(hist) != 3 {
		t.Fatalf("history trimmed to %d, want 3", len(hist))
	}
	if hist[0].Version != 4 {
		t.Fatalf("first retained version = %d, want 4", hist[0].Version)
	}
	if pm.CurrentVersion() != 6 {
		t.Fatalf("current version = %d, want 6", pm.CurrentVersion())
	}
}

func TestPolicyManager_PublishInvalidConfig(t *testing.T) {
	pm := NewPolicyManager(NewPluginRegistry())
	bad := PluginConfigs{
		"tcp": {Type: "unknown-type-xyz", Config: map[string]interface{}{}},
	}
	if _, err := pm.Publish(bad, "api", ""); err == nil {
		t.Fatal("expected error for unknown plugin type")
	}
	if pm.CurrentVersion() != 0 {
		t.Fatalf("version must stay 0 on failed publish, got %d", pm.CurrentVersion())
	}
}

func TestPolicyManager_ResetAndSnapshotJSON(t *testing.T) {
	pm := NewPolicyManager(NewPluginRegistry())
	_, _ = pm.Publish(allowlistConfig([]string{"tunnel:prod"}), "api", "admin@corp")
	snap := pm.ActiveSnapshot()
	if snap == nil {
		t.Fatal("active snapshot nil")
	}
	j := snap.SnapshotJSON()
	if j["version"].(uint64) != 1 {
		t.Fatalf("snapshot version = %v", j["version"])
	}
	if j["source"].(string) != "api" {
		t.Fatalf("snapshot source = %v", j["source"])
	}
	if j["operator"].(string) != "admin@corp" {
		t.Fatalf("snapshot operator = %v", j["operator"])
	}
	pm.Reset()
	if pm.CurrentVersion() != 0 || pm.ActiveSnapshot() != nil {
		t.Fatal("reset failed")
	}
	if len(pm.History()) != 0 {
		t.Fatal("history not cleared")
	}
}

func TestPolicyManager_Branches(t *testing.T) {
	pm := NewPolicyManager(NewPluginRegistry())
	v1, _ := pm.Publish(allowlistConfig([]string{"tunnel:prod"}), "api", "admin@corp")
	v2, _ := pm.Publish(allowlistConfig([]string{"tunnel:prod", "tunnel:stage"}), "api", "admin@corp")

	branches := []PolicyBranch{
		{ID: "canary", AgentID: "agent-canary-*", Version: v1, Priority: 10},
		{ID: "all", AgentID: "*", Version: v2, Priority: 0},
	}
	if err := pm.SetBranches(branches); err != nil {
		t.Fatalf("set branches: %v", err)
	}

	// Hits canary branch → v1 config (only tunnel:prod allowed)
	version, reg := pm.SelectRegistry("agent-canary-001")
	if version != v1 {
		t.Fatalf("canary version = %d, want %d", version, v1)
	}
	if got := runPluginDecision(t, reg, "tunnel:stage"); got != PluginDeny {
		t.Fatalf("canary stage decision = %v, want deny", got)
	}
	if got := runPluginDecision(t, reg, "tunnel:prod"); got != PluginAllow {
		t.Fatalf("canary prod decision = %v, want allow", got)
	}

	// Other agents → fall back to current version v2
	version, reg = pm.SelectRegistry("agent-main-9")
	if version != v2 {
		t.Fatalf("main version = %d, want %d", version, v2)
	}
	if got := runPluginDecision(t, reg, "tunnel:stage"); got != PluginAllow {
		t.Fatalf("main stage decision = %v, want allow", got)
	}
}

func TestPolicyManager_BranchesPriorityAndFallback(t *testing.T) {
	pm := NewPolicyManager(NewPluginRegistry())
	v1, _ := pm.Publish(allowlistConfig([]string{"tunnel:prod"}), "api", "admin@corp")
	_, _ = pm.Publish(allowlistConfig([]string{"tunnel:prod", "tunnel:stage"}), "api", "admin@corp")

	// Priority: exact agent match overrides prefix wildcard
	if err := pm.SetBranches([]PolicyBranch{
		{ID: "prefix", AgentID: "agent-a-*", Version: v1, Priority: 1},
		{ID: "exact", AgentID: "agent-a-007", Version: v1, Priority: 9},
	}); err != nil {
		t.Fatalf("set branches: %v", err)
	}
	version, _ := pm.SelectRegistry("agent-a-007")
	if version != v1 {
		t.Fatalf("exact match version = %d, want %d", version, v1)
	}
	version, _ = pm.SelectRegistry("agent-a-008")
	if version != v1 {
		t.Fatalf("prefix match version = %d, want %d", version, v1)
	}

	// No matching branch → fall back to current version
	if err := pm.SetBranches([]PolicyBranch{
		{ID: "only", AgentID: "agent-x-*", Version: v1, Priority: 5},
	}); err != nil {
		t.Fatalf("set branches: %v", err)
	}
	version, _ = pm.SelectRegistry("agent-y-1")
	if version != 2 {
		t.Fatalf("fallback version = %d, want 2 (current)", version)
	}

	// Clear branches → all fall back to current version
	pm.ClearBranches()
	version, _ = pm.SelectRegistry("agent-x-1")
	if version != 2 {
		t.Fatalf("after clear version = %d, want 2", version)
	}
}

func TestPolicyManager_SetBranchesValidation(t *testing.T) {
	pm := NewPolicyManager(NewPluginRegistry())
	v1, _ := pm.Publish(allowlistConfig([]string{"tunnel:prod"}), "api", "admin@corp")

	if err := pm.SetBranches([]PolicyBranch{{AgentID: "*", Version: v1}}); err == nil {
		t.Fatal("missing id accepted")
	}
	if err := pm.SetBranches([]PolicyBranch{{ID: "b1", Version: v1}}); err == nil {
		t.Fatal("missing agent_id accepted")
	}
	if err := pm.SetBranches([]PolicyBranch{{ID: "b1", AgentID: "*", Version: 99}}); err == nil {
		t.Fatal("unpublished version accepted")
	}
	if err := pm.SetBranches([]PolicyBranch{
		{ID: "b1", AgentID: "*", Version: v1},
		{ID: "b1", AgentID: "a-*", Version: v1},
	}); err == nil {
		t.Fatal("duplicate id accepted")
	}
	if got := len(pm.Branches()); got != 0 {
		t.Fatalf("branches should be empty after rejected set, got %d", got)
	}
}

func TestPolicyManager_SelectRegistryDoesNotPolluteActive(t *testing.T) {
	pm := NewPolicyManager(NewPluginRegistry())
	v1, _ := pm.Publish(allowlistConfig([]string{"tunnel:prod"}), "api", "admin@corp")
	_, _ = pm.Publish(allowlistConfig([]string{"tunnel:prod", "tunnel:stage"}), "api", "admin@corp")
	_ = pm.SetBranches([]PolicyBranch{{ID: "b", AgentID: "*", Version: v1, Priority: 1}})

	// Branch hit returns v1's isolated registry, does not modify active registry
	version, reg := pm.SelectRegistry("anything")
	if version != v1 {
		t.Fatalf("branch version = %d, want %d", version, v1)
	}
	// active registry is still the latest v2 config
	if got := runPluginDecision(t, pm.Registry(), "tunnel:stage"); got != PluginAllow {
		t.Fatalf("active registry stage = %v, want allow", got)
	}
	// Branch registry is a different instance from active
	if reg == pm.Registry() {
		t.Fatal("branch registry aliases active registry")
	}
}

func TestMatchAgentPattern(t *testing.T) {
	cases := []struct {
		agent, pattern string
		want           bool
	}{
		{"a-1", "*", true},
		{"a-1", "a-1", true},
		{"a-1", "a-*", true},
		{"a-1", "a-123", false},
		{"b-9", "a-*", false},
		{"", "*", true},
		{"", "a-*", false},
	}
	for _, c := range cases {
		if got := matchAgentPattern(c.agent, c.pattern); got != c.want {
			t.Errorf("matchAgentPattern(%q, %q) = %v, want %v", c.agent, c.pattern, got, c.want)
		}
	}
}
