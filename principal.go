package gw

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
)

// PrincipalProfile describes the identity and authorization summary of a principal.
type PrincipalProfile struct {
	PrincipalUID       string
	CommonName         string
	OrganizationalUnit []string
	CertHash           string
	UserPermission     *UserPermission
	Roles              []string
}

// ParsePrincipalProfile constructs a PrincipalProfile from a principal certificate, AIC, and
// UserPermission. up may be nil; uid prefers aic.PrincipalUid then falls back to cert CN.
func ParsePrincipalProfile(cert *x509.Certificate, aic *AIC, up *UserPermission) (*PrincipalProfile, error) {
	if cert == nil {
		return nil, fmt.Errorf("principal profile: nil cert")
	}
	h := sha256.Sum256(cert.Raw)
	p := &PrincipalProfile{
		CommonName:         cert.Subject.CommonName,
		OrganizationalUnit: cert.Subject.OrganizationalUnit,
		CertHash:           hex.EncodeToString(h[:]),
		Roles:              ExtractRoles(cert),
	}
	if aic != nil && aic.PrincipalUid.String() != ":" {
		p.PrincipalUID = aic.PrincipalUid.String()
	} else {
		p.PrincipalUID = cert.Subject.CommonName
	}
	p.UserPermission = up
	return p, nil
}

// HasRole checks whether the profile contains the specified role (convenience method).
func (p *PrincipalProfile) HasRole(role string) bool {
	for _, r := range p.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// AllowsDelegationMode checks whether the specified delegation mode is allowed.
func (p *PrincipalProfile) AllowsDelegationMode(mode int) bool {
	if p.UserPermission == nil {
		return false
	}
	return p.UserPermission.AgentDelegation.AllowedMode >= mode
}

// PrincipalProfileAttribute is a single attribute in the PrincipalProfile extension.
type PrincipalProfileAttribute struct {
	Type  string `asn1:"utf8"`
	Value string `asn1:"utf8"`
}

// PrincipalProfileExtension is the ASN.1 structure for the PrincipalProfile X.509 v3 extension.
type PrincipalProfileExtension struct {
	Version    int `asn1:"default:1"`
	Attributes []PrincipalProfileAttribute
}

// OIDPrincipalProfile is the Principal Profile extension OID.
var OIDPrincipalProfile = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 4}

// ParsePrincipalProfileExtension parses the PrincipalProfile extension from a certificate.
// Returns nil if the extension is not present.
func ParsePrincipalProfileExtension(cert *x509.Certificate) *PrincipalProfileExtension {
	if cert == nil {
		return nil
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDPrincipalProfile) {
			var pp PrincipalProfileExtension
			if _, err := asn1.Unmarshal(ext.Value, &pp); err == nil {
				return &pp
			}
		}
	}
	return nil
}
