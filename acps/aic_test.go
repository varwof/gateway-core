// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package acps

import (
	"errors"
	"strings"
	"testing"
)

func TestParseAIC_Valid(t *testing.T) {
	aic, err := ParseAIC(aicSpecExample)
	if err != nil {
		t.Fatalf("ParseAIC(%q): %v", aicSpecExample, err)
	}
	if aic.Code != aicSpecExample {
		t.Fatalf("code = %q, want %q", aic.Code, aicSpecExample)
	}
	if aic.Prefix != AICPrefix {
		t.Fatalf("prefix = %q", aic.Prefix)
	}
	if aic.Version != "1" {
		t.Fatalf("version = %q, want 1", aic.Version)
	}
	if aic.Checksum != "0JU4" {
		t.Fatalf("checksum = %q, want 0JU4", aic.Checksum)
	}
	if aic.IsBody() {
		t.Fatal("IsBody() = true, want false (level-9 is an entity sequence)")
	}
}

func TestParseAIC_LowercaseNormalized(t *testing.T) {
	raw := "1.2.156.3088.1.1.34c2.478bdf.3gf546.0ju4"
	aic, err := ParseAIC(raw)
	if err != nil {
		t.Fatalf("ParseAIC(lowercase): %v", err)
	}
	if aic.Code != aicSpecExample {
		t.Fatalf("normalized code = %q, want %q", aic.Code, aicSpecExample)
	}
}

func TestParseAIC_BodyEntity(t *testing.T) {
	aic, err := ParseAIC("1.2.156.3088.1.1.34C2.478BDF.0.0JU4")
	if err != nil {
		t.Fatal(err)
	}
	if !aic.IsBody() {
		t.Fatal("level-9 '0' should mark the agent body")
	}
}

func TestParseAIC_Invalid(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"empty", ""},
		{"bad level count", "1.2.156.3088.1.1.34C2.478BDF.3GF546"},
		{"wrong prefix", "1.2.3.4.1.1.34C2.478BDF.3GF546.0JU4"},
		{"illegal char dash", "1.2.156.3088.1.1.34-C2.478BDF.3GF546.0JU4"},
		{"illegal char bang", "1.2.156.3088.1.1.34C2.478BDF.3GF54!.0JU4"},
		{"version zero", "1.2.156.3088.0.1.34C2.478BDF.3GF546.0JU4"},
		{"version multi", "1.2.156.3088.12.1.34C2.478BDF.3GF546.0JU4"},
		{"arsp seq zero", "1.2.156.3088.1.0.34C2.478BDF.3GF546.0JU4"},
		{"arsp seq too long", "1.2.156.3088.1.1234567.34C2.478BDF.3GF546.0JU4"},
		{"entity seq too long", "1.2.156.3088.1.1.34C2.478BDF.1234567890.0JU4"},
		{"checksum short", "1.2.156.3088.1.1.34C2.478BDF.3GF546.0JU"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseAIC(tc.raw); err == nil {
				t.Fatalf("ParseAIC(%q) succeeded, want error", tc.raw)
			} else if !errors.Is(err, ErrInvalidAIC) {
				t.Fatalf("ParseAIC(%q) err = %v, want ErrInvalidAIC", tc.raw, err)
			}
		})
	}
}

func TestNormalizeAICText(t *testing.T) {
	if got := NormalizeAICText(" 1.2.156.3088.1.1.34c2.478bdf.3gf546.0ju4 "); got != aicSpecExample {
		t.Fatalf("NormalizeAICText = %q, want %q", got, aicSpecExample)
	}
}

func TestCRC16CCITTFALSE_SpecVector(t *testing.T) {
	// AIC §4.1 worked example: data = ASCII upper-cased 1..9 levels, salt
	// 0x12,0x34 (2 bytes), result 0x646C → "0JU4".
	data := []byte("1.2.156.3088.1.1.34C2.478BDF.3GF546")
	data = append(data, 0x12, 0x34)
	got := CRC16CCITTFALSE(data)
	if got != 0x646C {
		t.Fatalf("CRC16CCITTFALSE = 0x%04X, want 0x646C", got)
	}
	if enc := Base36Encode(got); enc != "0JU4" {
		t.Fatalf("Base36Encode = %q, want 0JU4", enc)
	}
}

func TestVerifyChecksum(t *testing.T) {
	// The spec example's implied salt is 0x12 0x34 (data 1..9 levels). We test
	// against the vector to prove the full verifier path works when a salt is
	// configured (AIC §4.2).
	salt := []byte{0x12, 0x34}
	aic, err := Verify(aicSpecExample, salt)
	if err != nil {
		t.Fatalf("Verify with salt: %v", err)
	}
	if !aic.ChecksumValidated {
		t.Fatal("ChecksumValidated = false, want true")
	}
	ok, err := VerifyChecksum(aicSpecExample, salt)
	if err != nil || !ok {
		t.Fatalf("VerifyChecksum = (%v,%v), want (true,nil)", ok, err)
	}
}

func TestVerifyChecksum_WrongSaltRejected(t *testing.T) {
	if _, err := Verify(aicSpecExample, []byte{0x00, 0x01}); !errors.Is(err, ErrAICChecksum) {
		t.Fatalf("Verify(wrong salt) err = %v, want ErrAICChecksum", err)
	}
}

func TestVerifyChecksum_NoSaltStructuralOnly(t *testing.T) {
	// Only structural validation runs without a salt; VerifyChecksum signals
	// "not verifiable" instead of failing (fail-open on checksum is
	// intentional and documented — the salt is per-ARSP internal).
	aic, err := Verify(aicSpecExample, nil)
	if err != nil {
		t.Fatalf("Verify(nil salt): %v", err)
	}
	if aic.ChecksumValidated {
		t.Fatal("ChecksumValidated should stay false without salt")
	}
	ok, err := VerifyChecksum(aicSpecExample, nil)
	if ok || err != nil {
		t.Fatalf("VerifyChecksum(nil salt) = (%v,%v), want (false,nil)", ok, err)
	}
}

func TestVerifyChecksum_ShortSaltRejected(t *testing.T) {
	if _, err := Verify(aicSpecExample, []byte{0x12}); err == nil {
		t.Fatal("Verify with 1-byte salt should error (AIC §4.1 salt ≥2 bytes)")
	}
}

func TestSubjectID(t *testing.T) {
	if got := SubjectID(aicSpecExample); got != "agent:"+aicSpecExample {
		t.Fatalf("SubjectID = %q", got)
	}
}

func TestExtractPeerAIC_CNOnly(t *testing.T) {
	cert := testPeerCert(t, aicSpecExample, nil)
	got, err := ExtractPeerAIC(cert, false)
	if err != nil {
		t.Fatal(err)
	}
	if got != aicSpecExample {
		t.Fatalf("peer AIC = %q", got)
	}
}

func TestExtractPeerAIC_CNAndSANMatch(t *testing.T) {
	cert := testPeerCert(t, strings.ToLower(aicSpecExample), []string{"acps://" + aicSpecExample})
	got, err := ExtractPeerAIC(cert, false)
	if err != nil {
		t.Fatal(err)
	}
	if got != aicSpecExample {
		t.Fatalf("peer AIC = %q, want normalized %q", got, aicSpecExample)
	}
}

func TestExtractPeerAIC_CNAndSANMismatch(t *testing.T) {
	cert := testPeerCert(t, aicSpecExample, []string{"acps://" + partnerAIC})
	if _, err := ExtractPeerAIC(cert, false); !errors.Is(err, ErrPeerIdentityMismatch) {
		t.Fatalf("err = %v, want ErrPeerIdentityMismatch", err)
	}
}

func TestExtractPeerAIC_MissingIdentity(t *testing.T) {
	cert := testPeerCert(t, "", nil)
	if _, err := ExtractPeerAIC(cert, false); !errors.Is(err, ErrMissingPeerIdentity) {
		t.Fatalf("err = %v, want ErrMissingPeerIdentity", err)
	}
}

func TestExtractPeerAIC_InvalidCN(t *testing.T) {
	cert := testPeerCert(t, "not-an-aic/with/slashes/0", []string{"acps://" + aicSpecExample})
	if _, err := ExtractPeerAIC(cert, false); !errors.Is(err, ErrMissingPeerIdentity) {
		// CN present but invalid → certificate identity invalid (AIP §6.0 rule 4).
		t.Fatalf("err = %v, want ErrMissingPeerIdentity", err)
	}
}

func TestExtractPeerAIC_RequireSAN(t *testing.T) {
	without := testPeerCert(t, aicSpecExample, nil)
	if _, err := ExtractPeerAIC(without, true); !errors.Is(err, ErrMissingPeerIdentity) {
		t.Fatalf("requireSAN without SAN: err = %v", err)
	}
	with := testPeerCert(t, aicSpecExample, []string{"acps://" + aicSpecExample})
	if _, err := ExtractPeerAIC(with, true); err != nil {
		t.Fatalf("requireSAN with SAN: %v", err)
	}
}

func TestMatchPeerAIC(t *testing.T) {
	if err := MatchPeerAIC(aicSpecExample, strings.ToLower(aicSpecExample)); err != nil {
		t.Fatalf("match (case-insensitive) failed: %v", err)
	}
	if err := MatchPeerAIC(aicSpecExample, partnerAIC); err == nil {
		t.Fatal("mismatch should error")
	}
}

func TestParseAIC_RejectsForwardCompatFieldChecksumRange(t *testing.T) {
	// Any 4-character base36 checksum value is structurally accepted (the
	// 0000..1EKF range equals the full base36 4-char space, max=0xFFFF).
	for _, ck := range []string{"0000", "1EKF", "ZZZZ"} {
		raw := "1.2.156.3088.1.1.34C2.478BDF.3GF546." + ck
		if _, err := ParseAIC(raw); err != nil {
			t.Fatalf("checksum %q: %v", ck, err)
		}
	}
}
