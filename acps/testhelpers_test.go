// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package acps

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"
)

// testPeerCert builds a self-signed certificate whose Subject CN and SAN
// acps:// URI carry the given AIC (AIP §6.0 shape).
func testPeerCert(t *testing.T, cn string, uris []string) *x509.Certificate {
	t.Helper()
	return testPeerCertWithOU(t, cn, uris, nil)
}

func testPeerCertWithOU(t *testing.T, cn string, uris []string, ous []string) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:         cn,
			OrganizationalUnit: ous,
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
	}
	for _, u := range uris {
		parsed, err := url.Parse(u)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.URIs = append(tmpl.URIs, parsed)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	cert.PublicKey = &key.PublicKey
	return cert
}

// aicSpecExample is the AIC example from ACPs-spec-AIC §3.
const aicSpecExample = "1.2.156.3088.1.1.34C2.478BDF.3GF546.0JU4"

// partnerAIC is a second structurally-valid AIC used in delegation tests.
const partnerAIC = "1.2.156.3088.1.2.34C2.478BDF.3GF546.0JU4"
