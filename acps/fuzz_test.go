// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package acps

import (
	"encoding/json"
	"testing"
)

// FuzzParseAIC exercises the AIC grammar with hostile strings.
func FuzzParseAIC(f *testing.F) {
	f.Add("1.2.156.3088.1.2.34C2.478BDF.3GF546.0JU4")
	f.Add("1.2.3.4.5.6.7.8.9.0.1.2")
	f.Add("")
	f.Add("111")
	f.Add("..")
	f.Add("1.2.156.3088.1.2.34C2.478BDF.0000000.0000")
	f.Add("sanitized-suffix#frag")
	f.Fuzz(func(t *testing.T, raw string) {
		a, err := ParseAIC(raw)
		if err != nil {
			return
		}
		// Round-trip: normalized output stays parseable and stable.
		again, err := ParseAIC(a.String())
		if err != nil || again.String() != a.String() {
			t.Fatalf("parse not stable: %q -> %q -> %v", raw, a.String(), err)
		}
	})
}

// FuzzNormalizeAICText must never panic on garbage and must be idempotent.
func FuzzNormalizeAICText(f *testing.F) {
	f.Add("1.2.156.3088.1.2.34C2.478BDF.3GF546.0JU4")
	f.Add(" 1.2.156.3088.1.2.34C2.478BDF.3GF546.0JU4 ")
	f.Add("\x00\x01\xff")
	f.Add("a-B-c-D-1-2-3")
	f.Fuzz(func(t *testing.T, raw string) {
		norm := NormalizeAICText(raw)
		if again := NormalizeAICText(norm); again != norm {
			t.Fatalf("normalize non-idempotent: %q -> %q -> %q", raw, norm, again)
		}
	})
}

// FuzzVerifyChecksum checks the code never panics and never reports a
// structurally-invalid code as valid.
func FuzzVerifyChecksum(f *testing.F) {
	f.Add("1.2.156.3088.1.2.34C2.478BDF.3GF546.0JU4", []byte{0x12, 0x34})
	f.Add("34C2.478BDF.3GF546.0000", []byte{})
	f.Add("", []byte{0x01})
	f.Add("\x00\x01here", []byte{0xde, 0xad})
	f.Fuzz(func(t *testing.T, code string, salt []byte) {
		ok, err := VerifyChecksum(code, salt)
		if err != nil {
			return
		}
		if !ok {
			return
		}
		if _, err := ParseAIC(code); err != nil {
			t.Fatalf("checksum accepts structurally-invalid code %q: %v", code, err)
		}
	})
}

// FuzzFromTokenClaims feeds arbitrary claim payloads to the token binding.
func FuzzFromTokenClaims(f *testing.F) {
	f.Add([]byte(`{"iss":"https://sts.example.com","sub":"https://idp.example.com/realm#u","exp":4102444800,"act":"agent:1.2.156.3088.1.2.34C2.478BDF.3GF546.0JU4"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var claims map[string]any
		if err := json.Unmarshal(data, &claims); err != nil {
			return
		}
		tok := FromTokenClaims(claims)
		if claims == nil && tok != nil || claims != nil && tok == nil {
			t.Fatalf("null claims must yield nil token (claims=%v, tok=%p)", claims, tok)
		}
		if tok == nil {
			return
		}
		// Required-claims validation must never panic on adversarial input.
		_ = tok.ValidateRequiredClaims()
	})
}
