// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"encoding/asn1"
	"testing"
)

func TestParseUserPermissionExtension_NilCert(t *testing.T) {
	up, err := ParseUserPermissionExtension(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if up != nil {
		t.Fatal("expected nil for nil cert")
	}
}

func TestParseUserPermissionExtension_NoExt(t *testing.T) {
	cert := makeCertWithExt(t, asn1.ObjectIdentifier{1, 2, 3, 4}, []byte{0x05, 0x00})
	up, err := ParseUserPermissionExtension(cert)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if up != nil {
		t.Fatal("expected nil for cert without UserPermission extension")
	}
}

func TestParseUserPermissionExtension_Valid(t *testing.T) {
	pa := PrincipalAuthorization{
		Grants: []Capability{{CapabilityId: "gateway:read"}},
	}
	val, err := asn1.Marshal(pa)
	if err != nil {
		t.Fatal(err)
	}
	cert := makeCertWithExt(t, oidUserPermission, val)
	parsed, err := ParseUserPermissionExtension(cert)
	if err != nil {
		t.Fatalf("ParseUserPermissionExtension: %v", err)
	}
	if parsed == nil {
		t.Fatal("expected non-nil")
	}
	if len(parsed.Grants) != 1 {
		t.Fatalf("Grants len: expected 1, got %d", len(parsed.Grants))
	}
	if parsed.Grants[0].CapabilityId != "gateway:read" {
		t.Fatalf("CapabilityId: got %s", parsed.Grants[0].CapabilityId)
	}
}

func TestParseUserPermissionExtension_Malformed(t *testing.T) {
	_, err := ParseUserPermissionExtension(makeCertWithExt(t, oidUserPermission, []byte{0xff}))
	if err == nil {
		t.Fatal("expected error for malformed UserPermission extension")
	}
}

func TestUserPermission_PermIds(t *testing.T) {
	up := &UserPermission{
		Roles: []RoleDef{
			{RoleId: "admin", Permissions: []PermissionDef{{PermId: "gateway:admin"}, {PermId: "gateway:ops"}}},
		},
	}
	ids := up.PermIds()
	if len(ids) != 2 {
		t.Fatalf("expected 2 perm ids, got %d: %v", len(ids), ids)
	}
	if ids[0] != "gateway:admin" || ids[1] != "gateway:ops" {
		t.Fatalf("unexpected ids: %v", ids)
	}
}

func TestUserPermission_NilPermIds(t *testing.T) {
	var nilUP *UserPermission
	if ids := nilUP.PermIds(); ids != nil {
		t.Fatal("expected nil PermIds for nil receiver")
	}
}
