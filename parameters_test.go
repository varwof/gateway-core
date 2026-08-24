// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"testing"
)

func TestParseMaxRows(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    int64
		wantOK  bool
		wantErr bool
	}{
		{"empty", "", 0, false, false},
		{"valid", `{"max_rows": 1000}`, 1000, true, false},
		{"zero", `{"max_rows": 0}`, 0, true, false},
		{"missing key", `{"other": 5}`, 0, false, false},
		{"invalid json", `not json`, 0, false, true},
		{"negative", `{"max_rows": -3}`, 0, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok, err := parseMaxRows([]byte(tt.raw))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want error, got ok=%v val=%d", ok, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ok != tt.wantOK || got != tt.want {
				t.Fatalf("got (%d, %v), want (%d, %v)", got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestMaxRowsValidator_Validate(t *testing.T) {
	v := maxRowsValidator{}
	granted := Capability{SchemeId: "report", CapabilityId: "list", Parameters: []byte(`{"max_rows": 1000}`)}

	t.Run("declared within boundary", func(t *testing.T) {
		declared := Capability{SchemeId: "report", CapabilityId: "list", Parameters: []byte(`{"max_rows": 100}`)}
		if err := v.Validate(granted, declared); err != nil {
			t.Fatalf("declared 100 within 1000 should pass, got %v", err)
		}
	})

	t.Run("declared equal boundary", func(t *testing.T) {
		declared := Capability{SchemeId: "report", CapabilityId: "list", Parameters: []byte(`{"max_rows": 1000}`)}
		if err := v.Validate(granted, declared); err != nil {
			t.Fatalf("declared 1000 == boundary should pass, got %v", err)
		}
	})

	t.Run("declared exceeds boundary", func(t *testing.T) {
		declared := Capability{SchemeId: "report", CapabilityId: "list", Parameters: []byte(`{"max_rows": 5000}`)}
		if err := v.Validate(granted, declared); err == nil {
			t.Fatal("declared 5000 > 1000 should be rejected")
		}
	})

	t.Run("granted no boundary → unrestricted", func(t *testing.T) {
		open := Capability{SchemeId: "report", CapabilityId: "list"}
		declared := Capability{SchemeId: "report", CapabilityId: "list", Parameters: []byte(`{"max_rows": 50000}`)}
		if err := v.Validate(open, declared); err != nil {
			t.Fatalf("no granted boundary should be unrestricted, got %v", err)
		}
	})

	t.Run("declared no params → pass", func(t *testing.T) {
		declared := Capability{SchemeId: "report", CapabilityId: "list"}
		if err := v.Validate(granted, declared); err != nil {
			t.Fatalf("no declared params should pass, got %v", err)
		}
	})

	t.Run("invalid declared params", func(t *testing.T) {
		declared := Capability{SchemeId: "report", CapabilityId: "list", Parameters: []byte(`bad`)}
		if err := v.Validate(granted, declared); err == nil {
			t.Fatal("invalid declared params should error")
		}
	})
}

func TestParameterValidatorRegistry(t *testing.T) {
	reg := NewParameterValidatorRegistry()
	if err := reg.Register(MaxRowsValidator); err != nil {
		t.Fatalf("Register: %v", err)
	}
	// duplicate register → error
	if err := reg.Register(MaxRowsValidator); err == nil {
		t.Fatal("duplicate scheme register should error")
	}
	if reg.Len() != 1 {
		t.Fatalf("Len = %d, want 1", reg.Len())
	}
	if got := reg.Keys(); len(got) != 1 || got[0] != "report" {
		t.Fatalf("Keys = %v, want [report]", got)
	}
	v, err := reg.Find("report")
	if err != nil || v == nil {
		t.Fatalf("Find report: %v", err)
	}
	if _, err := reg.Find("unknown-scheme"); err == nil {
		t.Fatal("Find unknown should error")
	}
	reg.Reset()
	if reg.Len() != 0 {
		t.Fatal("Len after Reset should be 0")
	}
	// nil receiver safety
	var nilReg *ParameterValidatorRegistry
	if err := nilReg.Register(MaxRowsValidator); err == nil {
		t.Fatal("nil Register should error")
	}
	if nilReg.Len() != 0 {
		t.Fatal("nil Len should be 0")
	}
	if nilReg.Keys() != nil {
		t.Fatal("nil Keys should be nil")
	}
	if err := nilReg.ValidateCapability(Capability{}, Capability{}); err != nil {
		t.Fatalf("nil ValidateCapability should pass, got %v", err)
	}
}

func TestValidateCapability_UnregisteredScheme(t *testing.T) {
	// Unregistered scheme → pass through directly (capability-level intersection already done upstream).
	reg := NewParameterValidatorRegistry()
	declared := Capability{SchemeId: "no-such-scheme", CapabilityId: "x", Parameters: []byte(`{"max_rows": 99999}`)}
	if err := reg.ValidateCapability(Capability{}, declared); err != nil {
		t.Fatalf("unregistered scheme should pass, got %v", err)
	}
}

func TestBuiltinParameterValidators(t *testing.T) {
	defer ResetParameterValidators()
	// init() already registered MaxRowsValidator → builtin registry should have 1.
	if BuiltinParameterValidators().Len() != 1 {
		t.Fatal("builtin registry should have 1 validator from init()")
	}
	ResetParameterValidators()
	if BuiltinParameterValidators().Len() != 0 {
		t.Fatal("Reset should empty builtin registry")
	}
	// After reset, can re-register.
	if err := RegisterParameterValidator(MaxRowsValidator); err != nil {
		t.Fatalf("RegisterParameterValidator: %v", err)
	}
	if BuiltinParameterValidators().Len() != 1 {
		t.Fatal("builtin registry should have 1 validator after register")
	}
}
