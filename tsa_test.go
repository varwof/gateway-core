// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
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
	_, _, _, err := extractTSTInfoFromCMS([]byte{0xff})
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
