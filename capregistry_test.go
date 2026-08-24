// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"crypto/x509"
	"encoding/asn1"
	"strings"
	"testing"
)

// mockCapRegistry is a test stub for the CapabilityRegistry interface.
type mockCapRegistry struct {
	known map[string]bool // full capability IDs
}

func (m *mockCapRegistry) ValidateCapability(formatted string) error {
	if m.known[formatted] {
		return nil
	}
	return &regError{msg: "unknown capability " + formatted}
}

func (m *mockCapRegistry) Enabled() bool { return m != nil }

type regError struct{ msg string }

func (e *regError) Error() string { return e.msg }

// TestPipelineCapRegistryRejectsUnregistered verifies data-plane capability registration validation:
// AIC declares an unregistered capability → connection rejected.
func TestPipelineCapRegistryRejectsUnregistered(t *testing.T) {
	aic := AIC{
		AgentId:      "agent-1",
		PrincipalUid: PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "user@varwof.com"},
		Capabilities: []Capability{{SchemeId: "varwof/core", CapabilityId: "no:such"}},
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
	cert := makeCertWithExt(t, oidAIC, aicVal)
	chain := []*x509.Certificate{cert}

	reg := &mockCapRegistry{known: map[string]bool{"varwof/core:cert:issue": true}}
	r := RunAccessPipeline(chain, &PipelineConfig{
		RequireAIC:         true,
		CapabilityRegistry: reg,
	})
	if r.Granted {
		t.Error("expected denial for unregistered capability")
	}
	if !strings.Contains(r.DenyReason, "not registered") {
		t.Errorf("deny reason = %q, want 'not registered'", r.DenyReason)
	}
}

// TestPipelineCapRegistryAllowsRegistered verifies that registered capabilities pass through the data plane.
func TestPipelineCapRegistryAllowsRegistered(t *testing.T) {
	aic := AIC{
		AgentId:      "agent-1",
		PrincipalUid: PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "user@varwof.com"},
		Capabilities: []Capability{{SchemeId: "varwof/core", CapabilityId: "cert:issue"}},
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
	cert := makeCertWithExt(t, oidAIC, aicVal)
	chain := []*x509.Certificate{cert}

	reg := &mockCapRegistry{known: map[string]bool{"varwof/core:cert:issue": true}}
	r := RunAccessPipeline(chain, &PipelineConfig{
		RequireAIC:         true,
		CapabilityRegistry: reg,
	})
	if !r.Granted {
		t.Fatalf("expected allow for registered capability: %s", r.DenyReason)
	}
}

// TestPipelineCapRegistryDisabled verifies that validation is skipped when the registry is disabled (nil).
func TestPipelineCapRegistryDisabled(t *testing.T) {
	aic := AIC{
		AgentId:      "agent-1",
		PrincipalUid: PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "user@varwof.com"},
		Capabilities: []Capability{{SchemeId: "varwof/core", CapabilityId: "no:such"}},
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
	cert := makeCertWithExt(t, oidAIC, aicVal)
	chain := []*x509.Certificate{cert}

	// CapabilityRegistry is nil → validation skipped, connection allowed (backward compatible)
	r := RunAccessPipeline(chain, &PipelineConfig{RequireAIC: true})
	if !r.Granted {
		t.Fatalf("expected allow when registry disabled: %s", r.DenyReason)
	}
}

// TestGlobalCapRegistryFallback verifies package-level default registry fallback:
// when PipelineConfig.CapabilityRegistry is nil, the registry from SetGlobalCapabilityRegistry is used.
func TestGlobalCapRegistryFallback(t *testing.T) {
	aic := AIC{
		AgentId:      "agent-1",
		PrincipalUid: PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "user@varwof.com"},
		Capabilities: []Capability{{SchemeId: "varwof/core", CapabilityId: "no:such"}},
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
	cert := makeCertWithExt(t, oidAIC, aicVal)
	chain := []*x509.Certificate{cert}

	// Set package-level registry (only recognizes varwof/core:cert:issue)
	SetGlobalCapabilityRegistry(&mockCapRegistry{known: map[string]bool{"varwof/core:cert:issue": true}})
	defer SetGlobalCapabilityRegistry(nil) // Cleanup to avoid affecting other tests

	// PipelineConfig has no explicit injection → falls back to global → rejects unregistered capabilities
	r := RunAccessPipeline(chain, &PipelineConfig{RequireAIC: true})
	if r.Granted {
		t.Error("expected denial via global registry fallback")
	}
	if !strings.Contains(r.DenyReason, "not registered") {
		t.Errorf("deny reason = %q, want 'not registered'", r.DenyReason)
	}

	// Explicitly inject a different registry → not affected by global (config takes priority)
	// Note: nil interface cannot be explicitly expressed; use a different registry to override
	SetGlobalCapabilityRegistry(&mockCapRegistry{known: map[string]bool{"varwof/core:no:such": true}})
	r2 := RunAccessPipeline(chain, &PipelineConfig{RequireAIC: true})
	if !r2.Granted {
		t.Errorf("expected allow with permissive global registry: %s", r2.DenyReason)
	}
}
