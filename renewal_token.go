package gw

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"time"
)

// OIDRenewalToken is the OID for the RenewalToken extension (1.3.6.1.4.1.66257.1.6).
var OIDRenewalToken = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 6}

// RenewalTokenExt is the ASN.1 serialization structure for RenewalToken (I-D §6).
// The spec defines 7 fields: version, principalUid, oldCertSerial, newKeyHash, timestamp, nonce, validityPeriod.
type RenewalTokenExt struct {
	Version        int          `asn1:"default:1"`
	PrincipalUid   PrincipalUid `asn1:"optional,contextspecific,tag:0"`
	OldCertSerial  []byte       `asn1:"octet"`
	NewKeyHash     []byte       `asn1:"octet"`
	Timestamp      time.Time    `asn1:"generalized"`
	Nonce          []byte       `asn1:"octet"` // SIZE(16)
	ValidityPeriod int          `asn1:"default:300"`
}

// ParseRenewalToken parses a RenewalToken from certificate extensions.
func ParseRenewalToken(exts []pkix.Extension) (*RenewalTokenExt, error) {
	for _, ext := range exts {
		if ext.Id.Equal(OIDRenewalToken) {
			var token RenewalTokenExt
			if _, err := asn1.Unmarshal(ext.Value, &token); err != nil {
				return nil, fmt.Errorf("renewal_token: unmarshal failed: %w", err)
			}
			return &token, nil
		}
	}
	return nil, nil
}

// IsExpired checks whether the RenewalToken has expired.
func (r *RenewalTokenExt) IsExpired() bool {
	if r == nil {
		return true
	}
	return time.Now().After(r.Timestamp.Add(time.Duration(r.ValidityPeriod) * time.Second))
}

// VerifyNonce verifies that the nonce is 16 bytes long (spec §6: SIZE(16)).
func (r *RenewalTokenExt) VerifyNonce() bool {
	if r == nil {
		return false
	}
	return len(r.Nonce) == 16
}

// ValidateConstraints validates the RenewalToken constraints (spec §6).
func (r *RenewalTokenExt) ValidateConstraints() error {
	if r == nil {
		return fmt.Errorf("renewal_token: nil token")
	}
	if r.ValidityPeriod > 300 {
		return fmt.Errorf("renewal_token: validityPeriod %d exceeds max 300 seconds", r.ValidityPeriod)
	}
	if len(r.OldCertSerial) == 0 {
		return fmt.Errorf("renewal_token: oldCertSerial required")
	}
	if len(r.NewKeyHash) != 32 {
		return fmt.Errorf("renewal_token: newKeyHash length %d: must be 32", len(r.NewKeyHash))
	}
	if !r.VerifyNonce() {
		return fmt.Errorf("renewal_token: nonce length %d: must be 16", len(r.Nonce))
	}
	return nil
}
