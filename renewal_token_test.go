// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
	"time"
)

func TestParseRenewalToken_NotFound(t *testing.T) {
	token, err := ParseRenewalToken(nil)
	if err != nil {
		t.Fatalf("unexpected error for nil: %v", err)
	}
	if token != nil {
		t.Fatal("expected nil for empty extensions")
	}

	token, err = ParseRenewalToken([]pkix.Extension{})
	if err != nil {
		t.Fatalf("unexpected error for empty: %v", err)
	}
	if token != nil {
		t.Fatal("expected nil for no matching ext")
	}
}

func TestBuildAndParseRenewalToken(t *testing.T) {
	nonce := make([]byte, 16)
	rt := RenewalTokenExt{
		Version:        1,
		OldCertSerial:  []byte{1, 2, 3, 4},
		NewKeyHash:     make([]byte, 32),
		Timestamp:      time.Now(),
		Nonce:          nonce,
		ValidityPeriod: 300,
	}
	der, err := asn1.Marshal(rt)
	if err != nil {
		t.Fatal(err)
	}

	ext := pkix.Extension{
		Id:    OIDRenewalToken,
		Value: der,
	}

	parsed, err := ParseRenewalToken([]pkix.Extension{ext})
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if parsed == nil {
		t.Fatal("expected non-nil token")
	}
	if string(parsed.OldCertSerial) != string([]byte{1, 2, 3, 4}) {
		t.Fatalf("serial mismatch: got %x", parsed.OldCertSerial)
	}
	if !parsed.VerifyNonce() {
		t.Fatal("expected valid nonce")
	}
}

func TestRenewalToken_IsExpired(t *testing.T) {
	rt := &RenewalTokenExt{
		Timestamp:      time.Now().Add(-1 * time.Hour),
		ValidityPeriod: 300,
	}
	if !rt.IsExpired() {
		t.Fatal("expected expired")
	}

	rt2 := &RenewalTokenExt{
		Timestamp:      time.Now().Add(1 * time.Hour),
		ValidityPeriod: 300,
	}
	if rt2.IsExpired() {
		t.Fatal("expected not expired")
	}

	if (*RenewalTokenExt)(nil).IsExpired() != true {
		t.Fatal("nil token should be expired")
	}
}

func TestRenewalToken_VerifyNonce(t *testing.T) {
	tests := []struct {
		name  string
		nonce []byte
		want  bool
	}{
		{"16 bytes", make([]byte, 16), true},
		{"nil", nil, false},
		{"empty", []byte{}, false},
		{"short", []byte{1, 2, 3}, false},
		{"wrong 32", make([]byte, 32), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := &RenewalTokenExt{Nonce: tt.nonce}
			if got := rt.VerifyNonce(); got != tt.want {
				t.Errorf("VerifyNonce() = %v, want %v", got, tt.want)
			}
		})
	}
	if (*RenewalTokenExt)(nil).VerifyNonce() {
		t.Fatal("nil should return false")
	}
}

func TestRenewalToken_ValidateConstraints(t *testing.T) {
	valid := &RenewalTokenExt{
		Version:        1,
		OldCertSerial:  []byte{1, 2, 3},
		NewKeyHash:     make([]byte, 32),
		Timestamp:      time.Now(),
		Nonce:          make([]byte, 16),
		ValidityPeriod: 300,
	}
	if err := valid.ValidateConstraints(); err != nil {
		t.Fatalf("valid token: %v", err)
	}

	// Exceeded validity
	exceeded := *valid
	exceeded.ValidityPeriod = 600
	if err := exceeded.ValidateConstraints(); err == nil {
		t.Fatal("expected error for validityPeriod 600")
	}

	// Empty serial
	noSerial := *valid
	noSerial.OldCertSerial = nil
	if err := noSerial.ValidateConstraints(); err == nil {
		t.Fatal("expected error for empty serial")
	}

	// Wrong key hash length
	wrongHash := *valid
	wrongHash.NewKeyHash = make([]byte, 16)
	if err := wrongHash.ValidateConstraints(); err == nil {
		t.Fatal("expected error for wrong newKeyHash")
	}

	// Wrong nonce length
	wrongNonce := *valid
	wrongNonce.Nonce = make([]byte, 32)
	if err := wrongNonce.ValidateConstraints(); err == nil {
		t.Fatal("expected error for wrong nonce length")
	}

	// Nil token
	if err := (*RenewalTokenExt)(nil).ValidateConstraints(); err == nil {
		t.Fatal("expected error for nil token")
	}
}
