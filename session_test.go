// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func makeCertWithExt(t *testing.T, oid asn1.ObjectIdentifier, extVal []byte) *x509.Certificate {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: oid, Value: extVal},
		},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	return cert
}

func makeCertWithRoleExt(t *testing.T, ous []string, oid asn1.ObjectIdentifier, extVal []byte) *x509.Certificate {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
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
	return cert
}

func TestParseGatewaySessionExtension_NilCert(t *testing.T) {
	gs, err := ParseGatewaySessionExtension(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gs != nil {
		t.Fatal("expected nil result")
	}
}

func TestParseGatewaySessionExtension_NoExt(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	gs, err := ParseGatewaySessionExtension(cert)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gs != nil {
		t.Fatal("expected nil result for cert without gateway session extension")
	}
}

func TestParseGatewaySessionExtension_Valid(t *testing.T) {
	gs := GatewaySessionExtension{
		Version:       1,
		MaxConcurrent: 10,
		HardTimeout:   3600,
		MaxRetries:    3,
	}
	val, err := asn1.Marshal(gs)
	if err != nil {
		t.Fatal(err)
	}

	cert := makeCertWithExt(t, oidGateway, val)
	parsed, err := ParseGatewaySessionExtension(cert)
	if err != nil {
		t.Fatalf("ParseGatewaySessionExtension: %v", err)
	}
	if parsed == nil {
		t.Fatal("expected non-nil result")
	}
	if parsed.MaxConcurrent != 10 {
		t.Fatalf("MaxConcurrent: expected 10, got %d", parsed.MaxConcurrent)
	}
	if parsed.HardTimeout != 3600 {
		t.Fatalf("HardTimeout: expected 3600, got %d", parsed.HardTimeout)
	}
	if len(parsed.AllowedCIDRs) != 0 {
		t.Fatalf("AllowedCIDRs: expected empty, got %v", parsed.AllowedCIDRs)
	}
	if parsed.MaxRetries != 3 {
		t.Fatalf("MaxRetries: expected 3, got %d", parsed.MaxRetries)
	}
}

func TestParseGatewaySessionExtension_Malformed(t *testing.T) {
	_, err := ParseGatewaySessionExtension(makeCertWithExt(t, oidGateway, []byte{0xff, 0xff}))
	if err == nil {
		t.Fatal("expected error for malformed extension")
	}
}

func TestGatewaySession_NilReceiverMethods(t *testing.T) {
	var nilGS *GatewaySessionExtension

	if got := nilGS.MaxConcurrentLimit(); got != 0 {
		t.Fatalf("MaxConcurrentLimit on nil: expected 0, got %d", got)
	}
	if got := nilGS.HardTimeoutLimit(); got != 0 {
		t.Fatalf("HardTimeoutLimit on nil: expected 0, got %d", got)
	}
	if got := nilGS.MaxRetriesLimit(); got != 0 {
		t.Fatalf("MaxRetriesLimit on nil: expected 0, got %d", got)
	}
	if got := nilGS.CIDRAllowed("10.0.0.1"); !got {
		t.Fatal("CIDRAllowed on nil: expected true (no restriction)")
	}
}

func TestGatewaySession_CIDRAllowed(t *testing.T) {
	gs := &GatewaySessionExtension{
		AllowedCIDRs: []string{"10.0.0.0/8", "192.168.1.0/24"},
	}
	if !gs.CIDRAllowed("10.0.0.1") {
		t.Fatal("expected true for 10.0.0.1 in 10.0.0.0/8")
	}
	if !gs.CIDRAllowed("192.168.1.100") {
		t.Fatal("expected true for 192.168.1.100 in 192.168.1.0/24")
	}
	if gs.CIDRAllowed("8.8.8.8") {
		t.Fatal("expected false for non-matching IP")
	}
	if gs.CIDRAllowed("192.168.0.1") {
		t.Fatal("expected false for 192.168.0.1 not in 192.168.1.0/24")
	}
}

func TestGatewaySession_EmptyCIDRs(t *testing.T) {
	gs := &GatewaySessionExtension{AllowedCIDRs: []string{}}
	if !gs.CIDRAllowed("any.ip.is.fine") {
		t.Fatal("expected true when AllowedCIDRs is empty")
	}

	gs2 := &GatewaySessionExtension{AllowedCIDRs: nil}
	if !gs2.CIDRAllowed("also.fine") {
		t.Fatal("expected true when AllowedCIDRs is nil")
	}
}

var _ = pem.Block{}
