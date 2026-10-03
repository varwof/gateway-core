// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// makeCertWithExt mints a self-signed certificate carrying one extra extension.
//
// When the extension is an AIC whose DelegationAuthorization carries no
// signature, the AIC is turned into a *verifiable* self-authorized delegation:
// PrincipalUid.KeyHash becomes the leaf SPKI hash and the DA is signed over its
// DelegationAuthTBS with the leaf key.  DA verification is unconditional in the
// agent-certificate verification procedure (draft Section 12 step 4), so the
// old placeholder fixtures (zero KeyHash, no signature) are correctly refused
// now.  Fixtures that carry a deliberate signature or a non-zero KeyHash are
// left untouched so the DA-specific negative tests still exercise real inputs.
func makeCertWithExt(t *testing.T, oid asn1.ObjectIdentifier, extVal []byte) *x509.Certificate {
	t.Helper()
	cert, _ := makeCertWithExtRole(t, nil, oid, extVal)
	return cert
}

func makeCertWithRoleExt(t *testing.T, ous []string, oid asn1.ObjectIdentifier, extVal []byte) *x509.Certificate {
	t.Helper()
	cert, _ := makeCertWithExtRole(t, ous, oid, extVal)
	return cert
}

func makeCertWithExtRole(t *testing.T, ous []string, oid asn1.ObjectIdentifier, extVal []byte) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	extVal = selfAuthorizePlaceholderAIC(t, key, oid, extVal)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test", OrganizationalUnit: ous},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: oid, Value: extVal},
		},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	return cert, key
}

// selfAuthorizePlaceholderAIC returns extVal unchanged unless it is an AIC with
// a zero KeyHash and no DA signature, in which case it returns a re-marshalled
// AIC that the certificate pipeline can actually verify.
func selfAuthorizePlaceholderAIC(t *testing.T, key *ecdsa.PrivateKey, oid asn1.ObjectIdentifier, extVal []byte) []byte {
	t.Helper()
	if !oid.Equal(oidAIC) {
		return extVal
	}
	var aic AIC
	if _, err := asn1.Unmarshal(extVal, &aic); err != nil {
		return extVal
	}
	if len(aic.DelegationAuthorization.SignatureValue) != 0 {
		return extVal
	}
	if !isZeroKeyHash(aic.PrincipalUid.KeyHash) {
		return extVal
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyHash := sha256.Sum256(spki)
	aic.PrincipalUid.KeyHash = keyHash[:]
	if len(aic.PrincipalUid.HashAlgo.Algorithm) == 0 {
		aic.PrincipalUid.HashAlgo = AlgorithmIdentifier{Algorithm: OIDSHA256}
	}
	if aic.Version == 0 {
		aic.Version = 1
	}
	da := &aic.DelegationAuthorization
	if da.RequestedLifetime < 7200 {
		da.RequestedLifetime = 86400
	}
	if da.Timestamp.IsZero() {
		da.Timestamp = time.Now().UTC()
	}
	if len(da.Nonce) == 0 {
		da.Nonce = make([]byte, 32)
	}
	if len(da.SignatureAlgorithm.Algorithm) == 0 {
		da.SignatureAlgorithm = AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256}
	}
	tbs := DelegationAuthTBS{
		Version:                  aic.Version,
		AgentId:                  aic.AgentId,
		PrincipalUid:             aic.PrincipalUid,
		Reason:                   da.Reason,
		Capabilities:             aic.Capabilities,
		DelegationMode:           aic.DelegationMode,
		AuthorizationConstraints: aic.AuthorizationConstraints,
		RequestedLifetime:        da.RequestedLifetime,
		Timestamp:                da.Timestamp,
		Nonce:                    da.Nonce,
	}
	der, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(der)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	da.SignatureValue = sig
	out, err := asn1.Marshal(aic)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func isZeroKeyHash(h []byte) bool {
	for _, b := range h {
		if b != 0 {
			return false
		}
	}
	return true
}
