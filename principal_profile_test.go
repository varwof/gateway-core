// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"encoding/asn1"
	"testing"
)

func TestParsePrincipalProfileExtension_NilCert(t *testing.T) {
	if got := ParsePrincipalProfileExtension(nil); got != nil {
		t.Fatal("expected nil for nil cert")
	}
}

func TestParsePrincipalProfileExtension_NoExt(t *testing.T) {
	cert := testCertWithExtension(t, []int{1, 2, 3}, []byte("dummy"))
	if got := ParsePrincipalProfileExtension(cert); got != nil {
		t.Fatal("expected nil for cert without principal_profile ext")
	}
}

func TestBuildAndParsePrincipalProfileExtension(t *testing.T) {
	ext := makePrincipalProfileExt(t, map[string]string{
		"department": "Engineering",
		"level":      "Senior",
	})
	cert := testCertWithExtension(t, OIDPrincipalProfile, ext)
	parsed := ParsePrincipalProfileExtension(cert)
	if parsed == nil {
		t.Fatal("expected non-nil")
	}
	if parsed.Version != 1 {
		t.Fatalf("Version: expected 1, got %d", parsed.Version)
	}
	attrMap := make(map[string]string)
	for _, a := range parsed.Attributes {
		attrMap[a.Type] = a.Value
	}
	if attrMap["department"] != "Engineering" {
		t.Fatalf("department: expected Engineering, got %s", attrMap["department"])
	}
	if attrMap["level"] != "Senior" {
		t.Fatalf("level: expected Senior, got %s", attrMap["level"])
	}
}

func TestParsePrincipalProfileExtension_SingleAttr(t *testing.T) {
	ext := makePrincipalProfileExt(t, map[string]string{
		"locale": "zh-CN",
	})
	cert := testCertWithExtension(t, OIDPrincipalProfile, ext)
	parsed := ParsePrincipalProfileExtension(cert)
	if parsed == nil {
		t.Fatal("expected non-nil")
	}
	if len(parsed.Attributes) != 1 {
		t.Fatalf("expected 1 attr, got %d", len(parsed.Attributes))
	}
	if parsed.Attributes[0].Type != "locale" || parsed.Attributes[0].Value != "zh-CN" {
		t.Fatalf("expected locale=zh-CN, got %s=%s", parsed.Attributes[0].Type, parsed.Attributes[0].Value)
	}
}

func makePrincipalProfileExt(t *testing.T, attrs map[string]string) []byte {
	t.Helper()
	var ppAttrs []PrincipalProfileAttribute
	for k, v := range attrs {
		ppAttrs = append(ppAttrs, PrincipalProfileAttribute{Type: k, Value: v})
	}
	pp := PrincipalProfileExtension{
		Version:    1,
		Attributes: ppAttrs,
	}
	der, err := asn1.Marshal(pp)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
