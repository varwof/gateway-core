package gw

import (
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// pkixName constructs a simple Subject name.
func pkixName(cn string) pkix.Name {
	return pkix.Name{CommonName: cn}
}

// embedAIC serializes an AIC as an X.509 v3 extension and embeds it in a copy of the cert.
func embedAIC(t *testing.T, cert *x509.Certificate, aic *AIC) *x509.Certificate {
	t.Helper()
	val, err := asn1.Marshal(*aic)
	if err != nil {
		t.Fatal(err)
	}
	cp := *cert
	cp.Extensions = append(cp.Extensions, pkix.Extension{
		Id:    oidAIC,
		Value: val,
	})
	return &cp
}

// reSignWithAIC re-issues a certificate with the AIC extension (using the same key).
func reSignWithAIC(t *testing.T, template *x509.Certificate, aic *AIC, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	val, err := asn1.Marshal(*aic)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := *template
	tmpl.Extensions = append(tmpl.Extensions, pkix.Extension{Id: oidAIC, Value: val})
	der, err := x509.CreateCertificate(nil, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	out, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

var _ = big.NewInt
var _ = time.Now
