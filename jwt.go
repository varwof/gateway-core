// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package gw

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"crypto/sha256"
	pki "github.com/varwof/types"
	"github.com/varwof/types/aicjwt"
)

// JWTVerifier verifies AIC-JWT bearer tokens against a trust root built
// from CA certificates (same kid convention as the X.509 carrier:
// base64url SHA-256 of the certificate SPKI). On success it returns a
// synthesized X.509 certificate carrying the token's AIC extension, so
// the existing pipeline (RunAccessPipeline / CheckAdmission) admits a
// bearer request exactly like a certificate-authenticated one.
type JWTVerifier struct {
	roots map[string]crypto.PublicKey // kid -> issuer public key
}

// NewJWTVerifier builds a verifier from CA certificates. kid for each CA
// is base64url(SHA-256(SubjectPublicKeyInfo)) — the same binding core
// publishes on /.well-known/jwks.json.
func NewJWTVerifier(cas []*x509.Certificate) *JWTVerifier {
	roots := make(map[string]crypto.PublicKey, len(cas))
	for _, c := range cas {
		if c == nil {
			continue
		}
		if kid, err := aicjwt.SPKIHash(c, "sha-256"); err == nil {
			roots[kid] = c.PublicKey
		}
	}
	return &JWTVerifier{roots: roots}
}

// LoadJWTVerifier reads one or more PEM CA certificate files (comma or
// space separated paths) and builds a JWT verifier from them. An empty
// spec returns a nil verifier (bearer auth disabled).
func LoadJWTVerifier(caFiles ...string) (*JWTVerifier, error) {
	var certs []*x509.Certificate
	for _, spec := range caFiles {
		for _, f := range strings.FieldsFunc(spec, func(r rune) bool { return r == ',' || r == ' ' }) {
			if f == "" {
				continue
			}
			pemData, err := os.ReadFile(f)
			if err != nil {
				return nil, fmt.Errorf("jwt: read CA %q: %w", f, err)
			}
			parsed, err := parsePEMCerts(pemData)
			if err != nil {
				return nil, fmt.Errorf("jwt: parse CA %q: %w", f, err)
			}
			certs = append(certs, parsed...)
		}
	}
	if len(certs) == 0 {
		return nil, nil
	}
	return NewJWTVerifier(certs), nil
}

// VerifyBearer validates a Bearer AIC-JWT and returns a synthesized
// certificate carrying the AIC claims, plus the raw outer claims.
func (v *JWTVerifier) VerifyBearer(token string, now time.Time) (*x509.Certificate, *aicjwt.OuterClaims, error) {
	if len(v.roots) == 0 {
		return nil, nil, fmt.Errorf("jwt: no trust root configured")
	}
	if _, err := aicjwt.Validate(token, aicjwt.VerifyOptions{
		Now:        now,
		IssuerKeys: v.roots,
	}); err != nil {
		return nil, nil, fmt.Errorf("jwt: validate: %w", err)
	}

	// Re-parse payload for the claims we synthesize into the certificate.
	_, pb, _, err := aicjwt.ParseCompact(token)
	if err != nil {
		return nil, nil, fmt.Errorf("jwt: parse: %w", err)
	}
	var outer aicjwt.OuterClaims
	if err := json.Unmarshal(pb, &outer); err != nil {
		return nil, nil, fmt.Errorf("jwt: payload: %w", err)
	}

	cert, err := SynthesizeCertFromJWT(&outer)
	if err != nil {
		return nil, nil, err
	}
	return cert, &outer, nil
}

// SynthesizeCertFromJWT builds an X.509 certificate carrying the AIC
// claims of an AIC-JWT, so downstream certificate-based pipeline stages
// (CheckAdmission, capability matching, audit) work unchanged.
func SynthesizeCertFromJWT(outer *aicjwt.OuterClaims) (*x509.Certificate, error) {
	if outer == nil || outer.Aic == nil {
		return nil, fmt.Errorf("jwt: missing aic claims")
	}
	aic := jwtToAIC(outer)

	// ASN.1-serialize the AIC so ParseAIC on the synthesized certificate
	// recovers the exact claims.
	extVal, err := asn1.Marshal(*aic)
	if err != nil {
		return nil, fmt.Errorf("jwt: marshal AIC extension: %w", err)
	}

	agentID := outer.Sub
	if agentID == "" {
		agentID = outer.Aic.Principal.ID
	}

	notBefore := time.Unix(outer.Iat, 0)
	notAfter := time.Unix(outer.Exp, 0)

	return &x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject:      pkix.Name{CommonName: agentID},
		Issuer:       pkix.Name{CommonName: outer.Iss},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		Extensions: []pkix.Extension{
			{Id: pki.OIDAIC, Critical: false, Value: extVal},
		},
	}, nil
}

// jwtToAIC maps AIC-JWT claims onto the X.509 AIC structure.
func jwtToAIC(outer *aicjwt.OuterClaims) *pki.AIC {
	aic := &pki.AIC{
		Version:        1,
		AgentId:        outer.Sub,
		DelegationMode: pki.DelegationMode(modeToInt(outer.Aic.DelegationMode)),
	}
	if aic.AgentId == "" {
		aic.AgentId = outer.Aic.Principal.ID
	}
	kh, _ := base64.RawURLEncoding.DecodeString(outer.Aic.Principal.KeyHash)
	aic.PrincipalUid = pki.PrincipalUid{
		Version:    1,
		Realm:      outer.Aic.Principal.Realm,
		Identifier: outer.Aic.Principal.ID,
		KeyHash:    kh,
	}
	for _, c := range outer.Aic.Capabilities {
		aic.Capabilities = append(aic.Capabilities, pki.Capability{
			SchemeId:     c.Scheme,
			CapabilityId: c.ID,
			Parameters:   []byte(c.Params),
		})
	}
	for _, c := range outer.Aic.Constraints {
		aic.AuthorizationConstraints = append(aic.AuthorizationConstraints, pki.Capability{
			SchemeId:     c.Scheme,
			CapabilityId: c.ID,
			Parameters:   []byte(c.Params),
		})
	}
	// pki.ParseAIC requires a present DelegationAuthorization. For an
	// AIC-JWT the delegation authorization is represented by the outer.da
	// claim (JWT form); authorize-mode tokens carry none. Synthesize a
	// present-but-neutral placeholder so the certificate pipeline admits
	// the bearer; its signature/replay checks only run when explicitly
	// configured (RequireUserAuth / NonceCache), which a JWT carrier does
	// not satisfy. The nonce is derived deterministically from the JTI so
	// the same token always synthesizes the same carrier.
	aic.DelegationAuthorization = pki.DelegationAuthorization{
		RequestedLifetime:  requestedLifetimeOf(outer),
		Reason:             pki.Reason{ReasonCode: "JWT_BEARER", Description: "aic-jwt bearer authentication"},
		Nonce:              nonceFromJTI(outer.Jti),
		SignatureAlgorithm: pki.AlgorithmIdentifier{Algorithm: pki.OIDSHA256},
	}
	return aic
}

// nonceFromJTI derives a fixed-length nonce from the token JTI (SHA-256),
// so the synthesized DA passes ValidateAIC while remaining deterministic.
func nonceFromJTI(jti string) []byte {
	h := sha256.Sum256([]byte(jti))
	return h[:]
}

// requestedLifetimeOf derives a non-zero requestedLifetime from the token's
// exp-iat so the synthesized DA placeholder is present (IsPresent()).
func requestedLifetimeOf(outer *aicjwt.OuterClaims) int {
	if outer.Exp > outer.Iat {
		if lt := int(outer.Exp - outer.Iat); lt > 0 {
			return lt
		}
	}
	return 3600
}

// parsePEMCerts extracts all certificates from PEM data.
func parsePEMCerts(pemData []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		certs = append(certs, c)
	}
	return certs, nil
}

// modeToInt maps the JWT delegation_mode string to the X.509 enum.
func modeToInt(mode string) int {
	switch mode {
	case aicjwt.ModeRepresentative:
		return 1
	default:
		return 0
	}
}
