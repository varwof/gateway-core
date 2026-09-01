// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"testing"
)

func TestMaskString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		visible int
		want    string
	}{
		{"empty", "", 4, ""},
		{"short string", "abc", 4, "abc"},
		{"exact length", "abcd", 4, "abcd"},
		{"typical", "abcdefgh", 4, "****efgh"},
		{"zero visible", "hello", 0, "*****"},
		{"negative visible", "hello", -1, "hello"},
		{"single char visible", "abcdef", 1, "*****f"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MaskString(tt.input, tt.visible)
			if got != tt.want {
				t.Errorf("MaskString(%q, %d) = %q, want %q", tt.input, tt.visible, got, tt.want)
			}
		})
	}
}

func TestMaskCertSerial(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty", "", ""},
		{"typical hex", "A1B2C3D4E5F6", "**:**:**:**:E5:F6"},
		{"with colons", "A1:B2:C3:D4:E5:F6", "**:**:**:**:E5:F6"},
		{"short serial", "AB", "AB"},
		{"odd length", "ABC123", "**:C1:23"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MaskCertSerial(tt.input)
			if got != tt.want {
				t.Errorf("MaskCertSerial(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestMaskFilePath(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty", "", ""},
		{"bare filename", "secret.pem", "s****t.pem"},
		{"full path", "/etc/pki/certs/secret.pem", "/etc/pki/certs/s****t.pem"},
		{"no extension", "/etc/pki/secretkey", "/etc/pki/*********"},
		{"windows path", `C:\pki\secret.pem`, `C:\pki\s****t.pem`},
		{"short base", "ab.pem", "**.pem"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MaskFilePath(tt.input)
			if got != tt.want {
				t.Errorf("MaskFilePath(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestMaskToken(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty", "", ""},
		{"short token", "abcdef", "******"},
		{"typical API key", "sk-abc123def456ghi789", "sk-a*************i789"},
		{"exact 8 chars", "12345678", "********"},
		{"9 chars masks half", "abcdefghi", "ab*****hi"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MaskToken(tt.input)
			if got != tt.want {
				t.Errorf("MaskToken(%q) = %q, want %q", tt.input, got, tt.want)
			}
			// Finding 21: never reveal more than half of a short token.
			revealed := 0
			for i := 0; i < len(got); i++ {
				if got[i] != DefaultMaskRune {
					revealed++
				}
			}
			if revealed > len(tt.input)/2 && len(tt.input) > 8 {
				t.Errorf("MaskToken(%q) reveals %d of %d chars (finding 21)", tt.input, revealed, len(tt.input))
			}
		})
	}
}

func TestMaskEmail(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty", "", ""},
		{"no domain", "alice", "*lice"},
		{"typical", "alice@example.com", "a***e@example.com"},
		{"short local", "ab@test.com", "**@test.com"},
		{"single char", "a@b.co", "*@b.co"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MaskEmail(tt.input)
			if got != tt.want {
				t.Errorf("MaskEmail(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSanitizeString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty", "", ""},
		{"normal", "hello world", "hello world"},
		{"with control chars", "he\x00llo", "hello"},
		{"with newline", "line1\nline2", "line1\nline2"},
		{"with tab", "col1\tcol2", "col1\tcol2"},
		{"trimmed", "  spaced  ", "spaced"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeString(tt.input)
			if got != tt.want {
				t.Errorf("SanitizeString(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestMaskBasename(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"with extension", "secret.pem", "s****t.pem"},
		{"no extension", "secretkey", "*********"},
		{"short name", "ab.pem", "**.pem"},
		{"two char base", "a.pem", "*.pem"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := maskBasename(tt.input)
			if got != tt.want {
				t.Errorf("maskBasename(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
