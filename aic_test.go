// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
	"time"
)

func TestParseAICExtension_NilCert(t *testing.T) {
	aic, err := ParseAIC(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if aic != nil {
		t.Fatal("expected nil for nil cert")
	}
}

func TestParseAICExtension_NoExt(t *testing.T) {
	cert := makeCertWithExt(t, asn1.ObjectIdentifier{1, 2, 3, 4}, []byte{0x05, 0x00})
	aic, err := ParseAIC(cert)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if aic != nil {
		t.Fatal("expected nil for cert without AIC extension")
	}
}

func TestParseAICExtension_Valid(t *testing.T) {
	aic := AIC{
		Version:      1,
		AgentId:      "agent-001",
		PrincipalUid: PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "user@varwof.com"},
		Capabilities: []Capability{
			{SchemeId: "tcp", CapabilityId: "gateway:ops", Parameters: []byte{1, 2, 3}},
		},
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			SignatureValue:     []byte{0xcc, 0xdd},
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
			Timestamp:          time.Now(),
			RequestedLifetime:  3600,
		},
	}
	val, err := asn1.Marshal(aic)
	if err != nil {
		t.Fatal(err)
	}

	cert := makeCertWithExt(t, oidAIC, val)
	parsed, err := ParseAIC(cert)
	if err != nil {
		t.Fatalf("ParseAICExtension: %v", err)
	}
	if parsed == nil {
		t.Fatal("expected non-nil")
	}
	if parsed.AgentId != "agent-001" {
		t.Fatalf("AgentId: expected agent-001, got %s", parsed.AgentId)
	}
	if parsed.PrincipalUid.Identifier != "user@varwof.com" {
		t.Fatalf("PrincipalUid: got %s", parsed.PrincipalUid.Identifier)
	}
	if len(parsed.Capabilities) != 1 {
		t.Fatalf("Capabilities len: expected 1, got %d", len(parsed.Capabilities))
	}
}

func TestParseAICExtension_Malformed(t *testing.T) {
	_, err := ParseAIC(makeCertWithExt(t, oidAIC, []byte{0xff}))
	if err == nil {
		t.Fatal("expected error for malformed AIC extension")
	}
}

func TestAICExtension_Principal(t *testing.T) {
	var nilAIC *AIC
	if got := nilAIC.Principal(); got != "" {
		t.Fatalf("nil AIC Principal: expected empty, got %s", got)
	}

	aic := &AIC{PrincipalUid: PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "user@varwof.com"}}
	if got := aic.Principal(); got != "varwof:user@varwof.com:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
		t.Fatalf("unexpected principal string: %s", got)
	}
}

func TestAICExtension_CheckPermission(t *testing.T) {
	var nilAIC *AIC
	if nilAIC.CheckPermission("anything") {
		t.Fatal("nil AIC should not have permissions")
	}

	aic := &AIC{
		Capabilities: []Capability{
			{SchemeId: "http", CapabilityId: "gateway:ops"},
			{SchemeId: "tcp", CapabilityId: "gateway:admin"},
		},
	}
	// FullID semantics: capabilities are matched by the full scheme:capabilityId identifier.
	// Note the original test uses CapabilityId with a "gateway:" prefix, FullID = scheme + ":" + capabilityId.
	if !aic.CheckPermission("http:gateway:ops") {
		t.Fatal("expected http:gateway:ops to be found")
	}
	if !aic.CheckPermission("tcp:gateway:admin") {
		t.Fatal("expected tcp:gateway:admin to be found")
	}
	// Requests without scheme do not match capabilities that include a scheme
	if aic.CheckPermission("gateway:ops") {
		t.Fatal("gateway:ops should not match http:gateway:ops (missing scheme)")
	}
	if aic.CheckPermission("gateway:audit") {
		t.Fatal("gateway:audit should not be found")
	}
}

func TestAICExtension_HasProtocol(t *testing.T) {
	var nilAIC *AIC
	if nilAIC.HasProtocol("tcp") {
		t.Fatal("nil AIC should not have protocols")
	}

	aic := &AIC{
		Capabilities: []Capability{
			{SchemeId: "http", CapabilityId: "gateway:read"},
			{SchemeId: "tcp", CapabilityId: "gateway:ops"},
		},
	}
	if !aic.HasProtocol("http") {
		t.Fatal("expected http protocol")
	}
	if !aic.HasProtocol("tcp") {
		t.Fatal("expected tcp protocol")
	}
	if aic.HasProtocol("udp") {
		t.Fatal("udp protocol should not be present")
	}
}

func TestAICExtension_IntersectPermissionsStr(t *testing.T) {
	aic := &AIC{
		Capabilities: []Capability{
			{SchemeId: "", CapabilityId: "gateway:read"},
			{SchemeId: "", CapabilityId: "gateway:write"},
			{SchemeId: "", CapabilityId: "gateway:ops"},
		},
	}

	got := aic.IntersectPermissionsStr([]string{"gateway:read", "gateway:admin"})
	if len(got) != 1 || got[0] != "gateway:read" {
		t.Fatalf("expected [gateway:read], got %v", got)
	}

	got2 := aic.IntersectPermissionsStr([]string{"gateway:audit", "gateway:delete"})
	if len(got2) != 0 {
		t.Fatalf("expected empty, got %v", got2)
	}

	var nilAIC *AIC
	if got3 := nilAIC.IntersectPermissionsStr([]string{"gateway:read"}); got3 != nil {
		t.Fatalf("expected nil for nil AIC, got %v", got3)
	}

	if got4 := aic.IntersectPermissionsStr(nil); got4 != nil {
		t.Fatalf("expected nil for nil input, got %v", got4)
	}
}

func TestAICExtension_IntersectPermissionsStrAny(t *testing.T) {
	aic := &AIC{
		Capabilities: []Capability{
			{SchemeId: "", CapabilityId: "gateway:read"},
			{SchemeId: "", CapabilityId: "gateway:ops"},
		},
	}

	got := aic.IntersectPermissionsStrAny("gateway:read, gateway:ops, gateway:admin")
	if len(got) != 2 {
		t.Fatalf("expected 2 matches, got %v", got)
	}

	got2 := aic.IntersectPermissionsStrAny("")
	if got2 != nil {
		t.Fatalf("expected nil for empty string, got %v", got2)
	}

	var nilAIC *AIC
	if got3 := nilAIC.IntersectPermissionsStrAny("gateway:read"); got3 != nil {
		t.Fatalf("expected nil for nil AIC, got %v", got3)
	}
}

func TestMatchCapability_Exact(t *testing.T) {
	if !matchCapability("gateway:admin", "gateway:admin") {
		t.Fatal("exact match should succeed")
	}
	if matchCapability("gateway:admin", "gateway:ops") {
		t.Fatal("different string should not match")
	}
}

func TestMatchCapability_Glob(t *testing.T) {
	if !matchCapability("gateway:admin", "gateway:*") {
		t.Fatal("glob * should match gateway:admin")
	}
	if !matchCapability("gateway:read", "gateway:*") {
		t.Fatal("glob * should match gateway:read")
	}
	if matchCapability("tcp:admin", "gateway:*") {
		t.Fatal("glob * should not match tcp:admin")
	}
	if !matchCapability("gateway:admin", "*:admin") {
		t.Fatal("glob *:admin should match gateway:admin")
	}
	if !matchCapability("gateway:admin", "gateway:?dmin") {
		t.Fatal("glob ? should match single char")
	}
}

func TestCheckPermission_Glob(t *testing.T) {
	aic := &AIC{
		Capabilities: []Capability{
			{SchemeId: "", CapabilityId: "gateway:read"},
			{SchemeId: "", CapabilityId: "gateway:ops"},
		},
	}
	if !aic.CheckPermission("gateway:*") {
		t.Fatal("glob gateway:* should match")
	}
	if aic.CheckPermission("tcp:*") {
		t.Fatal("glob tcp:* should not match")
	}
}

func TestIntersectPermissionsStr_Glob(t *testing.T) {
	aic := &AIC{
		Capabilities: []Capability{
			{SchemeId: "", CapabilityId: "gateway:admin"},
			{SchemeId: "", CapabilityId: "gateway:ops"},
		},
	}
	got := aic.IntersectPermissionsStr([]string{"gateway:*"})
	if len(got) != 2 {
		t.Fatalf("glob gateway:* should match both, got %v", got)
	}
	if got[0] != "gateway:admin" || got[1] != "gateway:ops" {
		t.Fatalf("expected [gateway:admin gateway:ops], got %v", got)
	}
	got2 := aic.IntersectPermissionsStr([]string{"gateway:admin", "tcp:*"})
	if len(got2) != 1 || got2[0] != "gateway:admin" {
		t.Fatalf("expected [gateway:admin], got %v", got2)
	}
}

func TestIntersectPermissionsStrAny_Glob(t *testing.T) {
	aic := &AIC{
		Capabilities: []Capability{
			{SchemeId: "", CapabilityId: "gateway:read"},
			{SchemeId: "", CapabilityId: "gateway:ops"},
		},
	}
	got := aic.IntersectPermissionsStrAny("gateway:*")
	if len(got) != 2 {
		t.Fatalf("glob gateway:* should match both, got %v", got)
	}
	if got[0] != "gateway:read" || got[1] != "gateway:ops" {
		t.Fatalf("expected [gateway:read gateway:ops], got %v", got)
	}
}

func TestParseAICExtension_CapabilityOverflow(t *testing.T) {
	// Marshal a minimal AIC with empty fields — just validates the struct
	// roundtrip still works after field reorder.
	aic := AIC{
		Version:      1,
		AgentId:      "agent-cov",
		PrincipalUid: PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "cov@varwof.com"},
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
	val, err := asn1.Marshal(aic)
	if err != nil {
		t.Fatal(err)
	}
	cert := makeCertWithExt(t, oidAIC, val)
	parsed, err := ParseAIC(cert)
	if err != nil {
		t.Fatalf("ParseAICExtension: %v", err)
	}
	if parsed == nil || parsed.AgentId != "agent-cov" {
		t.Fatal("roundtrip failed after field reorder")
	}
}

func TestValidateAICExtension_Nil(t *testing.T) {
	if err := ValidateAIC(nil); err != nil {
		t.Fatal(err)
	}
}

func TestValidateAICExtension_CapabilityCountOverflow(t *testing.T) {
	caps := make([]Capability, 257)
	for i := range caps {
		caps[i] = Capability{SchemeId: "s", CapabilityId: "c"}
	}
	aic := &AIC{
		Version:      1,
		AgentId:      "test",
		PrincipalUid: PrincipalUid{Version: 1, Realm: "r", Identifier: "i", KeyHash: make([]byte, 32)},
		Capabilities: caps,
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}},
			RequestedLifetime:  3600,
		},
	}
	err := ValidateAIC(aic)
	if err == nil || err.Error() != "aic: capabilities count 257 exceeds max 256" {
		t.Fatalf("expected overflow error, got: %v", err)
	}
}

func TestValidateAICExtension_SchemeIdTooLong(t *testing.T) {
	longScheme := make([]byte, 129)
	for i := range longScheme {
		longScheme[i] = 'a'
	}
	aic := &AIC{
		Version: 1,
		AgentId: "test",
		PrincipalUid: PrincipalUid{Version: 1, Realm: "r", Identifier: "i",
			KeyHash: make([]byte, 32), HashAlgo: AlgorithmIdentifier{Algorithm: OIDSHA256}},
		Capabilities: []Capability{{SchemeId: string(longScheme), CapabilityId: "cap"}},
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}},
			RequestedLifetime:  3600,
		},
	}
	err := ValidateAIC(aic)
	if err == nil {
		t.Fatal("expected schemeId too long error")
	}
}

func TestValidateAICExtension_UnknownCriticalExtension(t *testing.T) {
	aic := &AIC{
		Version: 1,
		AgentId: "test",
		PrincipalUid: PrincipalUid{Version: 1, Realm: "r", Identifier: "i",
			KeyHash: make([]byte, 32), HashAlgo: AlgorithmIdentifier{Algorithm: OIDSHA256}},
		Capabilities: []Capability{{SchemeId: "s", CapabilityId: "c"}},
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}},
			RequestedLifetime:  3600,
		},
		Extensions: []ExtField{
			{ExtnID: asn1.ObjectIdentifier{1, 2, 3, 4, 5}, Critical: true, ExtnValue: []byte{0x05, 0x00}},
		},
	}
	err := ValidateAIC(aic)
	if err == nil {
		t.Fatal("expected unknown critical extension error")
	}
}

func TestValidateAICExtension_KnownCriticalExtension(t *testing.T) {
	aic := &AIC{
		Version: 1,
		AgentId: "test",
		PrincipalUid: PrincipalUid{Version: 1, Realm: "r", Identifier: "i",
			KeyHash: make([]byte, 32), HashAlgo: AlgorithmIdentifier{Algorithm: OIDSHA256}},
		Capabilities: []Capability{{SchemeId: "s", CapabilityId: "c"}},
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}},
			RequestedLifetime:  3600,
		},
		Extensions: []ExtField{
			{ExtnID: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 2}, Critical: true, ExtnValue: []byte{0x05, 0x00}},
		},
	}
	err := ValidateAIC(aic)
	if err != nil {
		t.Fatalf("known critical extension should not fail: %v", err)
	}
}

func TestIsKnownExtension(t *testing.T) {
	known := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 2}
	if !isKnownExtension(known) {
		t.Fatal("expected known OID to be recognized")
	}
	unknown := asn1.ObjectIdentifier{1, 2, 3, 4, 5}
	if isKnownExtension(unknown) {
		t.Fatal("expected unknown OID to not be recognized")
	}
}

func TestValidateAICExtension_NonceWrongLength(t *testing.T) {
	aic := &AIC{
		Version: 1,
		AgentId: "test",
		PrincipalUid: PrincipalUid{Version: 1, Realm: "r", Identifier: "i",
			KeyHash: make([]byte, 32), HashAlgo: AlgorithmIdentifier{Algorithm: OIDSHA256}},
		Capabilities: []Capability{{SchemeId: "s", CapabilityId: "c"}},
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 16),
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}},
			RequestedLifetime:  3600,
		},
	}
	err := ValidateAIC(aic)
	if err == nil {
		t.Fatal("expected nonce length error")
	}
}

func TestMatchCapability(t *testing.T) {
	tests := []struct {
		id, pattern string
		want        bool
	}{
		{"gateway:read", "gateway:read", true},
		{"gateway:read", "gateway:*", true},
		{"gateway:read", "*:read", true},
		{"gateway:read", "gateway:write", false},
		{"a/b/c", "a/*/c", true},
		{"a/b/c", "a/b/c", true},
		{"a/b/c", "a/b", false},
		{"a/b/c/d", "a/*/d", false},
	}
	for _, tt := range tests {
		if got := matchCapability(tt.id, tt.pattern); got != tt.want {
			t.Errorf("matchCapability(%q, %q) = %v, want %v", tt.id, tt.pattern, got, tt.want)
		}
	}
}

func TestMatchCapability_DoubleStar(t *testing.T) {
	tests := []struct {
		id, pattern string
		want        bool
	}{
		{"a/b/c", "**", true},
		{"a/b/c", "**/c", true},
		{"a/b/c", "a/**", true},
		{"a/b/c", "a/**/c", true},
		{"a/b/c/d", "a/**/d", true},
		{"a/b/c/d/e", "a/**/e", true},
		{"a/b/c/d/e", "a/**/d/e", true},
		{"a/b/c", "a/**/x", false},
		{"a/b/c", "a/**/b/c/d", false},
		{"x/y/z", "a/**/z", false},
		{"a/b", "a/**/b", true},
		{"a/b", "a/**", true},
	}
	for _, tt := range tests {
		if got := matchCapability(tt.id, tt.pattern); got != tt.want {
			t.Errorf("matchCapability(%q, %q) = %v, want %v", tt.id, tt.pattern, got, tt.want)
		}
	}
}

func TestMatchDoubleStar_EdgeCases(t *testing.T) {
	tests := []struct {
		id, pattern string
		want        bool
	}{
		{"a/b", "**/b", true},
		{"b", "**/b", true},
		{"a/b", "a/**", true},
		{"a", "a/**", true},
		{"a/b/..", "a/**", false},
		{"a/b/c", "a/**/..", false},
	}
	for _, tt := range tests {
		if got := matchDoubleStar(tt.id, tt.pattern); got != tt.want {
			t.Errorf("matchDoubleStar(%q, %q) = %v, want %v", tt.id, tt.pattern, got, tt.want)
		}
	}
}

var _ = pkix.Extension{}
