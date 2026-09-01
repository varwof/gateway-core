// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"bytes"
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

func TestNewTSAClient_EmptyURL(t *testing.T) {
	if c := NewTSAClient(""); c != nil {
		t.Fatal("expected nil for empty URL")
	}
}

func TestNewTSAClient_ValidURL(t *testing.T) {
	c := NewTSAClient("http://tsa.example.com")
	if c == nil {
		t.Fatal("expected non-nil client")
	}
	if c.URL != "http://tsa.example.com" {
		t.Fatalf("url: expected http://tsa.example.com, got %s", c.URL)
	}
}

func TestTSASign_SignFunc(t *testing.T) {
	c := NewTSAClient("http://tsa.example.com")
	c.SignFunc = func(data []byte) ([]byte, error) {
		h := sha256.Sum256(data)
		return h[:], nil
	}
	result, err := c.Sign([]byte("hello"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	expected := sha256.Sum256([]byte("hello"))
	if string(result) != string(expected[:]) {
		t.Fatal("SignFunc result mismatch")
	}
}

func TestTSASign_NilClient(t *testing.T) {
	var c *TSAClient
	_, err := c.Sign(nil)
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestTSAVerify_NilClient(t *testing.T) {
	var c *TSAClient
	err := c.Verify(nil, nil)
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestTSAClient_SetCACert_Nil(t *testing.T) {
	var c *TSAClient
	if err := c.SetCACert(""); err != nil {
		t.Fatalf("SetCACert on nil client: %v", err)
	}
}

func TestTSAClient_SetCACert_EmptyFile(t *testing.T) {
	c := NewTSAClient("http://tsa.example.com")
	if err := c.SetCACert(""); err != nil {
		t.Fatalf("SetCACert with empty file: %v", err)
	}
}

func TestMarshalTSARequest(t *testing.T) {
	req := TimeStampReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{Algorithm: oidSha256},
			HashedMessage: []byte("hash"),
		},
	}
	data, err := MarshalTSARequest(req)
	if err != nil {
		t.Fatalf("MarshalTSARequest: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("empty marshalled data")
	}

	var parsed TimeStampReq
	if _, err := asn1.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal roundtrip: %v", err)
	}
	if parsed.Version != 1 {
		t.Fatalf("version: expected 1, got %d", parsed.Version)
	}
}

func TestEncodeDecodeBase64(t *testing.T) {
	original := []byte("test data for base64 encoding")
	encoded := EncodeBase64(original)
	decoded, err := DecodeBase64(encoded)
	if err != nil {
		t.Fatalf("DecodeBase64: %v", err)
	}
	if string(decoded) != string(original) {
		t.Fatal("base64 roundtrip mismatch")
	}
}

func TestDecodeBase64_Invalid(t *testing.T) {
	_, err := DecodeBase64("not-valid-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestUnmarshalTimestampToken_Invalid(t *testing.T) {
	_, err := UnmarshalTimestampToken([]byte{0xff, 0xff})
	if err == nil {
		t.Fatal("expected error for invalid CMS data")
	}
}

func TestFindTSACert(t *testing.T) {
	if c := findTSACert(nil); c != nil {
		t.Fatal("expected nil for empty cert list")
	}
	if c := findTSACert([]*x509.Certificate{}); c != nil {
		t.Fatal("expected nil for empty cert slice")
	}
}

func TestExtractTSTInfoFromCMS_Invalid(t *testing.T) {
	_, _, _, _, err := extractTSTInfoFromCMS([]byte{0xff})
	if err == nil {
		t.Fatal("expected error for invalid data")
	}
}

// TestTSAClient_SetMaxTSTAge verifies L7: the accepted TST age window is
// configurable and defaults to 1h (tightened from the previous 24h).
func TestTSAClient_SetMaxTSTAge(t *testing.T) {
	c := NewTSAClient("http://tsa.example.com")
	if c.maxTSTAge != time.Hour {
		t.Fatalf("default maxTSTAge = %v, want 1h", c.maxTSTAge)
	}
	c.SetMaxTSTAge(30 * time.Minute)
	if c.maxTSTAge != 30*time.Minute {
		t.Fatalf("maxTSTAge after Set = %v, want 30m", c.maxTSTAge)
	}
	var nilC *TSAClient
	nilC.SetMaxTSTAge(time.Minute) // must not panic
}

// TestVerifyCMSSignatureSignedAttrs (finding 9): the CMS signature is computed
// over the RFC 5652 §5.4 SET OF (0x31) encoding of SignedAttributes, not the
// [0] IMPLICIT (0xA0) wrapper, and the signed message-digest must equal the
// digest of the eContent.
func TestVerifyCMSSignatureSignedAttrs(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tsa"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	eContent := []byte("the TSTInfo eContent")
	eDigest := sha256.Sum256(eContent)

	// Build signedAttrs: contentType = id-ct-TSTInfo, message-digest = sha256(eContent).
	contentTypeVal, _ := asn1.Marshal(oidTSTInfo)
	mdVal, _ := asn1.Marshal(eDigest[:])
	attrs := []cmsAttribute{
		{Type: oidContentType, Values: []asn1.RawValue{{FullBytes: contentTypeVal}}},
		{Type: oidMessageDigest, Values: []asn1.RawValue{{FullBytes: mdVal}}},
	}
	setOf, err := asn1.MarshalWithParams(attrs, "set")
	if err != nil {
		t.Fatal(err)
	}

	// Signature computed over the SET OF (0x31) form per RFC 5652 §5.4.
	sig, err := ecdsa.SignASN1(rand.Reader, key, digestForCMS(setOf))
	if err != nil {
		t.Fatal(err)
	}

	si := &cmsSignerInfo{
		DigestAlgorithm: oidSha256,
		SignatureAlgo:   asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}, // ecdsa-with-SHA256
		SignedAttrsSet:  setOf,
		MessageDigest:   eDigest[:],
		ContentType:     oidTSTInfo,
		SignatureValue:  sig,
	}
	if err := verifyCMSSignature(si, []*x509.Certificate{cert}, eContent); err != nil {
		t.Fatalf("correct token must verify: %v", err)
	}

	// Tampered message-digest must be rejected.
	bad := *si
	bad.MessageDigest = []byte("tampered-digest")
	if err := verifyCMSSignature(&bad, []*x509.Certificate{cert}, eContent); err == nil {
		t.Fatal("tampered message-digest must be rejected")
	}

	// Wrong contentType must be rejected.
	bad2 := *si
	bad2.ContentType = oidSignedData
	if err := verifyCMSSignature(&bad2, []*x509.Certificate{cert}, eContent); err == nil {
		t.Fatal("wrong contentType must be rejected")
	}

	// Signature computed over the [0] IMPLICIT (0xA0) wrapper must be rejected:
	// this was the pre-fix behavior (finding 9).
	rawAttr := asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: setOf}
	a0Form, err := asn1.Marshal(rawAttr)
	if err != nil {
		t.Fatal(err)
	}
	sigOverA0, err := ecdsa.SignASN1(rand.Reader, key, digestForCMS(a0Form))
	if err != nil {
		t.Fatal(err)
	}
	bad3 := *si
	bad3.SignatureValue = sigOverA0
	if err := verifyCMSSignature(&bad3, []*x509.Certificate{cert}, eContent); err == nil {
		t.Fatal("signature over [0] wrapper must be rejected (finding 9)")
	}
}

// TestParseSignerInfoExtractsAttrs (finding 9): parseSignerInfo must recover
// the SET OF encoding and the message-digest/contentType attributes.
func TestParseSignerInfoExtractsAttrs(t *testing.T) {
	eDigest := sha256.Sum256([]byte("payload"))
	contentTypeVal, _ := asn1.Marshal(oidTSTInfo)
	mdVal, _ := asn1.Marshal(eDigest[:])
	attrs := []cmsAttribute{
		{Type: oidContentType, Values: []asn1.RawValue{{FullBytes: contentTypeVal}}},
		{Type: oidMessageDigest, Values: []asn1.RawValue{{FullBytes: mdVal}}},
	}
	setOf, err := asn1.MarshalWithParams(attrs, "set")
	if err != nil {
		t.Fatal(err)
	}

	// SignerInfo: version, sid, digestAlgorithm, signedAttrs [0] IMPLICIT, sigAlgo, sig.
	si, err := asn1.Marshal(struct {
		Version     int
		SID         asn1.RawValue
		DigestAlgo  asn1.ObjectIdentifier
		SignedAttrs asn1.RawValue `asn1:"optional,tag:0,class:2,implicit"`
		SigAlgo     asn1.ObjectIdentifier
		Signature   []byte
	}{
		Version:     1,
		SID:         asn1.RawValue{FullBytes: mustOID(t, asn1.ObjectIdentifier{1, 2, 3})},
		DigestAlgo:  oidSha256,
		SignedAttrs: asn1.RawValue{FullBytes: a0Implicit(setOf)},
		SigAlgo:     asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2},
		Signature:   []byte{0x00},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Strip the outer SEQUENCE header: parseSignerInfo expects the inner content.
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(si, &outer); err != nil {
		t.Fatal(err)
	}
	if outer.Tag != asn1.TagSequence {
		t.Fatalf("expected SEQUENCE, got tag %d", outer.Tag)
	}

	parsed := parseSignerInfo(outer.Bytes)
	if parsed == nil {
		t.Fatal("parseSignerInfo returned nil")
	}
	if parsed.SignedAttrsSet == nil {
		t.Fatal("SignedAttrsSet not recovered (finding 9)")
	}
	if !bytes.Equal(parsed.MessageDigest, eDigest[:]) {
		t.Fatal("message-digest attribute not recovered")
	}
	if !parsed.ContentType.Equal(oidTSTInfo) {
		t.Fatal("contentType attribute not recovered")
	}
}

func mustOID(t *testing.T, oid asn1.ObjectIdentifier) []byte {
	t.Helper()
	b, err := asn1.Marshal(oid)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// a0Implicit wraps raw bytes in a [0] IMPLICIT (context, tag 0) tag.
func a0Implicit(inner []byte) []byte {
	b, _ := asn1.Marshal(asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: inner})
	return b
}

func digestForCMS(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
