package gw

import (
	"testing"

	pki "github.com/varwof/types"
)

func TestAICCapabilityMatchPriority(t *testing.T) {
	caps := []Capability{
		{SchemeId: "database", CapabilityId: "query:*"},
		{SchemeId: "varwof/demo-mysql-v1", CapabilityId: "SELECT:*"},
	}
	tests := []struct {
		req      string
		priority int
	}{
		{"database:query:SELECT", pki.MatchPrioritySingle},
		{"varwof/demo-mysql-v1:SELECT:/api/tables", pki.MatchPrioritySingle},
		{"varwof/demo-mysql-v1:SELECT:*,extra", pki.MatchPrioritySingle},
		{"varwof/demo-mysql-v1:SELECT:extra:more", pki.MatchPriorityNoMatch},
	}
	for _, tt := range tests {
		if got := aicCapabilityMatchPriority(caps, tt.req); got != tt.priority {
			t.Fatalf("aicCapabilityMatchPriority(%q) = %d, want %d", tt.req, got, tt.priority)
		}
	}
}

func TestAICCapabilityDecision_DenyOverrides(t *testing.T) {
	caps := []Capability{{SchemeId: "database", CapabilityId: "query:SELECT"}}
	// Exact allow should beat multi-segment deny.
	if !aicCapabilityDecision(caps, "database:query:SELECT", []string{"database:**"}) {
		t.Fatal("exact allow should beat multi deny")
	}
	// Same-segment deny overrides allow.
	if aicCapabilityDecision(caps, "database:query:SELECT", []string{"database:query:SELECT"}) {
		t.Fatal("deny should override allow")
	}
	// No match → false.
	if aicCapabilityDecision(caps, "other:thing", []string{"database:**"}) {
		t.Fatal("no match should be false")
	}
	// Empty denyRules → falls back to allow-only semantics.
	if !aicCapabilityDecision(caps, "database:query:SELECT", nil) {
		t.Fatal("empty deny rules should fall back to allow semantics")
	}
	if aicCapabilityDecision(caps, "nope:nope", nil) {
		t.Fatal("empty deny rules should still require match")
	}
}
