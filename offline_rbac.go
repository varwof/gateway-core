// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"time"
)

// OfflineRbacExt is the ASN.1 structure for the OfflineRBAC X.509 v3 extension
// (tech spec v1.4 definition, including Version).
// Fully consistent with the varwof-core/ca package.
type OfflineRbacExt struct {
	Version          int    `asn1:"default:1"` // Tech spec includes this field; not listed in I-D base ASN.1
	RoleId           string `asn1:"utf8"`
	PermissionBitmap asn1.BitString
	ResourceScope    []string  // SEQUENCE OF UTF8String (tech spec v1.4 overrides I-D single-value)
	NotBefore        time.Time `asn1:"generalized,optional"`
	NotAfter         time.Time `asn1:"generalized,optional"`
	TrustAnchorHash  []byte    `asn1:"octet"`
}

// ParseOfflineRBAC parses OfflineRBAC from a certificate extension.
func ParseOfflineRBAC(cert *x509.Certificate) *OfflineRbacExt {
	if cert == nil {
		return nil
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDOfflineRBAC) {
			var rbac OfflineRbacExt
			if _, err := asn1.Unmarshal(ext.Value, &rbac); err == nil {
				return &rbac
			}
		}
	}
	return nil
}

// OfflineRBACDecision is the result of an offline RBAC decision.
type OfflineRBACDecision struct {
	Allowed bool
	Reason  string
}

// OfflineRBACCheck performs a three-stage offline RBAC decision:
//
//  1. trustAnchorHash verification: ensures the certificate's issuing CA matches
//     the CA recorded in the extension. Skipped if issuer is nil.
//  2. ResourceScope check: the target resource must be in the extension's resource
//     scope list. Skipped if resourceScope is empty.
//  3. PermissionBitmap check: the operation type must be present in the bitmap.
//     Skipped if the permission bitmap is empty.
//  4. ValidityPolicy check: the current time must be within the validity period.
//     Skipped if ValidityPolicy is nil.
func OfflineRBACCheck(ext *OfflineRbacExt, opts OfflineRBACCheckOptions) OfflineRBACDecision {
	if ext == nil {
		return OfflineRBACDecision{Allowed: false, Reason: "offline_rbac: extension not found"}
	}

	if opts.Issuer != nil && len(ext.TrustAnchorHash) > 0 {
		h := sha256.Sum256(opts.Issuer.Raw)
		if !bytes.Equal(ext.TrustAnchorHash, h[:]) {
			return OfflineRBACDecision{
				Allowed: false,
				Reason:  fmt.Sprintf("offline_rbac: trust anchor hash mismatch"),
			}
		}
	}

	if opts.TargetResource != "" && len(ext.ResourceScope) > 0 {
		found := false
		for _, scope := range ext.ResourceScope {
			if scope == opts.TargetResource || matchGlob(scope, opts.TargetResource) {
				found = true
				break
			}
		}
		if !found {
			return OfflineRBACDecision{
				Allowed: false,
				Reason:  fmt.Sprintf("offline_rbac: resource %q not in scope %v", opts.TargetResource, ext.ResourceScope),
			}
		}
	}

	if opts.RequiredPerm >= 0 && len(ext.PermissionBitmap.Bytes) >= 4 {
		bitmap := uint32(ext.PermissionBitmap.Bytes[0]) |
			uint32(ext.PermissionBitmap.Bytes[1])<<8 |
			uint32(ext.PermissionBitmap.Bytes[2])<<16 |
			uint32(ext.PermissionBitmap.Bytes[3])<<24
		if bitmap&(1<<uint(opts.RequiredPerm)) == 0 {
			return OfflineRBACDecision{
				Allowed: false,
				Reason:  fmt.Sprintf("offline_rbac: permission bit %d not set in bitmap", opts.RequiredPerm),
			}
		}
	}

	if !ext.NotBefore.IsZero() || !ext.NotAfter.IsZero() {
		now := time.Now()
		if !ext.NotBefore.IsZero() && now.Before(ext.NotBefore) {
			return OfflineRBACDecision{
				Allowed: false,
				Reason:  fmt.Sprintf("offline_rbac: not yet valid until %v", ext.NotBefore),
			}
		}
		if !ext.NotAfter.IsZero() && now.After(ext.NotAfter) {
			return OfflineRBACDecision{
				Allowed: false,
				Reason:  fmt.Sprintf("offline_rbac: expired at %v", ext.NotAfter),
			}
		}
	}

	return OfflineRBACDecision{Allowed: true}
}

// OfflineRBACCheckOptions are the options for offline RBAC checks.
type OfflineRBACCheckOptions struct {
	Issuer         *x509.Certificate
	TargetResource string
	RequiredPerm   int
}

// RBACPermRead/Write/Delete/Exec are offline RBAC permission bit constants.
const (
	RBACPermRead   = 0
	RBACPermWrite  = 1
	RBACPermDelete = 2
	RBACPermExec   = 3
)

// OIDOfflineRBAC is the Offline RBAC extension OID.
var OIDOfflineRBAC = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 3}

func matchGlob(pattern, s string) bool {
	if pattern == s {
		return true
	}
	patternLen := len(pattern)
	strLen := len(s)
	pi, si := 0, 0
	var starIdx, matchIdx int = -1, 0

	for si < strLen {
		if pi < patternLen && (pattern[pi] == '?' || pattern[pi] == s[si]) {
			pi++
			si++
		} else if pi < patternLen && pattern[pi] == '*' {
			starIdx = pi
			matchIdx = si
			pi++
		} else if starIdx != -1 {
			pi = starIdx + 1
			matchIdx++
			si = matchIdx
		} else {
			return false
		}
	}

	for pi < patternLen && pattern[pi] == '*' {
		pi++
	}
	return pi == patternLen
}
