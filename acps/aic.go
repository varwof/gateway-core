// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// AIC — Agent Identity Code (ACPs-spec-AIC-v02.02).
//
// An AIC is a dotted hierarchy of base36 (0-9, A-Z) levels. Levels 1-4 are the
// fixed ISO/CC-member/national OID prefix 1.2.156.3088; levels 5-10 form the
// content: 5=version (1..Z), 6=registration-service sequence, 7=vendor
// sequence, 8=body sequence, 9=entity sequence (0 marks the body itself),
// 10=checksum (AUTOSAR CRC-16/CCITT-FALSE over the upper-cased levels 1-9 plus
// the ARSP salt, base36-encoded into 4 characters).
//
// The digest salt is held internally by each registration service, so when the
//
//	slice is given no salt it performs structural validation only (AIC §4.2);
//
// when a salt (>=2 bytes) is configured, it requires the full CRC match.
package acps

import (
	"crypto/x509"
	"fmt"
	"strings"
)

// AIC structural constants (AIC spec §3).
const (
	// AICPrefix is the fixed 4-level identity-code prefix (ISO → CC-member
	// 156 → national ACPs node 3088).
	AICPrefix = "1.2.156.3088"
	// AICPrefixLevels is the number of levels in the fixed prefix.
	AICPrefixLevels = 4
	// AICTotLevels is the total number of identity-code levels (4+6).
	AICTotLevels = 10
	// AICDataLevels is the number of checksum-input levels (1..9).
	AICDataLevels = 9
	// MinSaltLen is the minimum ARSP salt length (AIC §4.1, "不少于 2 字节").
	MinSaltLen = 2
	// The level-5 version is single character in 1..Z.
	minVersionLevel, maxVersionLevel = "1", "Z"
	// Max content retained per level: level 6/7 up to 6 chars, level 8/9 up
	// to 9 chars, checksum exactly 4 chars.
	maxARSPSeq, maxEntitySeq, checksumLen = 6, 9, 4
	// ChecksumPerLevelUpper is the inclusive upper bound expressed in base36
	// text for levels 6-9 (ZZZZZZ / ZZZZZZZZZ); level 9 additionally allows 0.
	maxVendorSeqText, maxBodySeqText = "ZZZZZZ", "ZZZZZZZZZ"
	maxARSPSeqText                   = "ZZZZZZ"
	maxEntitySeqText                 = "ZZZZZZZZZ"
)

// checksumCharset is the base36 alphabet (AIC §4.1 step 7).
const checksumCharset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

// AIC is a parsed, normalized Agent Identity Code.
type AIC struct {
	// Code is the normalized (upper-cased) full identity code.
	Code string
	// Prefix is the fixed prefix (levels 1-4).
	Prefix string
	// Content is levels 5..10 (normalized uppercase).
	Content string
	// Version is the level-5 version field.
	Version string
	// Checksum is the level-10 checksum field.
	Checksum string
	// ChecksumValidated is true when a salt was configured and the CRC
	// compared equal (checksum fully verified).
	ChecksumValidated bool
}

// String returns the normalized identity code.
func (a AIC) String() string { return a.Code }

// IsBody reports whether the entity-level field (level 9) equals "0", i.e. the
// registered object is the agent body rather than a derived entity (AIC §3(9)).
func (a AIC) IsBody() bool {
	levels := strings.Split(a.Content, ".")
	return len(levels) == 6 && levels[4] == "0"
}

// validCharset reports whether every level-5..10 character is in [0-9A-Z].
func validCharset(level string) bool {
	for i := 0; i < len(level); i++ {
		c := level[i]
		if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

// inRange reports whether v (base36 text) is within [lo, hi] lexicographically
// (all equal width in the restriction below, so lexicographic order is
// numerically correct).
func inRange(v, lo, hi string) bool { return v >= lo && v <= hi }

// ParseAIC normalizes and structurally validates a raw identity code. It
// returns the parsed AIC; ChecksumValidated stays false unless VerifyChecksum
// has run with the ARSP salt. Any structural violation is an error (AIC §3).
func ParseAIC(raw string) (*AIC, error) {
	norm := NormalizeAICText(raw)
	if norm == "" {
		return nil, ErrInvalidAIC
	}
	levels := strings.Split(norm, ".")
	if len(levels) != AICTotLevels {
		return nil, aicErr("want %d levels, got %d", AICTotLevels, len(levels))
	}
	prefix := strings.Join(levels[:AICPrefixLevels], ".")
	if prefix != AICPrefix {
		return nil, aicErr("prefix %q != %q", prefix, AICPrefix)
	}
	content := strings.Join(levels[AICPrefixLevels:], ".")

	// Level charset: each content level must be digits or upper-case letters
	// (0-9, A-Z), case-normalized (AIC §3).
	for i, lv := range levels[AICPrefixLevels:] {
		if !validCharset(lv) {
			return nil, aicErr("invalid character in level %d", AICPrefixLevels+i+1)
		}
	}
	// Level 5: version 1..Z (single character, never 0).
	version := levels[4]
	if len(version) != 1 || !inRange(version, minVersionLevel, maxVersionLevel) {
		return nil, aicErr("version level %q not in 1..Z", version)
	}
	// Level 6/7: 1..ZZZZZZ; level 8: 1..ZZZZZZZZZ; level 9: 0..ZZZZZZZZZ.
	if len(levels[5]) > maxARSPSeq || len(levels[6]) > maxARSPSeq || len(levels[7]) > maxEntitySeq || len(levels[8]) > maxEntitySeq {
		return nil, aicErr("level length exceeds maximum")
	}
	if !inRange(levels[5], "1", maxARSPSeqText) {
		return nil, aicErr("arsp sequence %q not in 1..%s", levels[5], maxARSPSeqText)
	}
	if !inRange(levels[6], "1", maxVendorSeqText) {
		return nil, aicErr("vendor sequence %q not in 1..%s", levels[6], maxVendorSeqText)
	}
	if !inRange(levels[7], "1", maxBodySeqText) {
		return nil, aicErr("body sequence %q not in 1..%s", levels[7], maxBodySeqText)
	}
	if !inRange(levels[8], "0", maxEntitySeqText) {
		return nil, aicErr("entity sequence %q not in 0..%s", levels[8], maxEntitySeqText)
	}
	checksum := levels[9]
	if len(checksum) != checksumLen || !validCharset(checksum) {
		return nil, aicErr("checksum %q not a 4-character base36 value", checksum)
	}
	return &AIC{Code: norm, Prefix: prefix, Content: content, Version: version, Checksum: checksum}, nil
}

// aicErr formats a structural-error message wrapping the ErrInvalidAIC
// sentinel so failures are testable with errors.Is.
func aicErr(format string, args ...any) error {
	return fmt.Errorf(format+": %w", append(args, ErrInvalidAIC)...)
}

// NormalizeAICText upper-cases the raw input, which is the canonical form the
// specification recommends for storage and comparison (AIC §3).
func NormalizeAICText(raw string) string {
	if raw == "" {
		return ""
	}
	return strings.ToUpper(strings.TrimSpace(raw))
}

// SubjectID builds the AAC agent subject `agent:{aic}` (AAC §6.1).
func SubjectID(code string) string { return "agent:" + NormalizeAICText(code) }

// CRC16CCITTFALSE computes the AUTOSAR CRC-16/CCITT-FALSE value: poly 0x1021,
// init 0xFFFF, no input/output reflection, xorout 0x0000 (AIC §4.1 steps 3-6).
func CRC16CCITTFALSE(data []byte) uint16 {
	crc := uint16(0xFFFF)
	for _, b := range data {
		crc ^= uint16(b) << 8
		for i := 0; i < 8; i++ {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
			crc &= 0xFFFF
		}
	}
	return crc
}

// Base36Encode encodes v into the fixed 4-character base36 string, left-padded
// with '0' (AIC §4.1 step 7).
func Base36Encode(v uint16) string {
	var out [checksumLen]byte
	for i := checksumLen - 1; i >= 0; i-- {
		out[i] = checksumCharset[v%36]
		v /= 36
	}
	return string(out[:])
}

// VerifyChecksum recomputes the level-10 checksum over upper-cased levels 1-9
// with the ARSP salt appended (AIC §4.2). The salt must be at least MinSaltLen
// bytes; when it is empty the function returns (false, nil) to signal "not
// verifiable without salt" and the caller performs structural validation only.
func VerifyChecksum(code string, salt []byte) (bool, error) {
	aic, err := ParseAIC(code)
	if err != nil {
		return false, err
	}
	if len(salt) == 0 {
		return false, nil
	}
	if len(salt) < MinSaltLen {
		return false, fmt.Errorf("AIC: ARSP salt must be at least %d bytes", MinSaltLen)
	}
	levels := strings.Split(aic.Code, ".")
	data := []byte(strings.Join(levels[:AICDataLevels], "."))
	data = append(data, salt...)
	computed := Base36Encode(CRC16CCITTFALSE(data))
	if computed != aic.Checksum {
		return false, ErrAICChecksum
	}
	return true, nil
}

// Verify parses raw, runs structural validation and, when a non-empty salt is
// supplied, full checksum verification (AIC §4.2). Marks ChecksumValidated.
func Verify(raw string, salt []byte) (*AIC, error) {
	aic, err := ParseAIC(raw)
	if err != nil {
		return nil, err
	}
	if len(salt) == 0 {
		// No ARSP salt available: structural validation only. Documented in
		// the requirements baseline (§9.1) and conformance matrix.
		return aic, nil
	}
	ok, err := VerifyChecksum(raw, salt)
	if err != nil {
		return nil, err
	}
	if ok {
		aic.ChecksumValidated = true
	}
	return aic, nil
}

// ExtractPeerAIC implements the direct-mode peer identity extraction
// (ACPs-spec-AIP-v02.02 §6.0 via conceptual summary; AAC §9.2):
//
//   - Subject CN is the primary AIC source;
//   - a SAN URI acps://{AIC} is supplementary identity;
//   - CN and SAN, when both present, must agree (else identity invalid);
//   - CN missing or not a valid AIC makes the certificate identity invalid.
//
// requireSAN additionally demands that the SAN URI be present and equal (used
// in the strictest deployments). A missing certificate identity maps to the
// -32008 AuthenticationRequiredError family in the enforcement layer.
func ExtractPeerAIC(cert *x509.Certificate, requireSAN bool) (string, error) {
	if cert == nil {
		return "", ErrMissingPeerIdentity
	}
	cn := strings.TrimSpace(cert.Subject.CommonName)
	san := ""
	for _, u := range cert.URIs {
		if u.Scheme == "acps" && u.Host != "" {
			san = u.Host
			break
		}
	}
	cnOK := cn != "" && isStructurallyValid(cn)
	if !cnOK {
		return "", fmt.Errorf("%w: cn %q not a valid AIC", ErrMissingPeerIdentity, maskCN(cn))
	}
	if requireSAN && san == "" {
		return "", fmt.Errorf("%w: SAN acps:// URI required", ErrMissingPeerIdentity)
	}
	if san != "" && !strings.EqualFold(cn, san) {
		return "", ErrPeerIdentityMismatch
	}
	return NormalizeAICText(cn), nil
}

// isStructurallyValid is a lightweight pre-check used before normalization
// joins (avoids materializing the normalized form twice).
func isStructurallyValid(raw string) bool {
	_, err := ParseAIC(raw)
	return err == nil
}

// maskCN never exposes the full CN in error text when it is not a valid AIC
// (it is user-controlled); it only says whether a CN is present.
func maskCN(cn string) string {
	if cn == "" {
		return "(empty)"
	}
	return "(present)"
}

// MatchPeerAIC checks business-message senderId against the certificate peer
// AIC (AIP §6.0): values must agree after normalization. Mismatch is a
// -32009 AuthorizationFailedError at the enforcement layer.
func MatchPeerAIC(peerAIC, senderID string) error {
	if peerAIC == "" || senderID == "" {
		return ErrMissingPeerIdentity
	}
	if NormalizeAICText(peerAIC) != NormalizeAICText(strings.TrimSpace(senderID)) {
		return fmt.Errorf("%w: senderId != peer AIC", ErrPeerIdentityMismatch)
	}
	return nil
}
