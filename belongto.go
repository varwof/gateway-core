// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// G4 dual-certificate belong-to strong binding (SPKI strong binding).
//
// Dual-certificate deployment (08-dual-cert.md): the handshake certificate is presented
// at the TLS layer (small size, agentId + principalUid + DA, capabilities/constraints
// can be left empty), and the authorization certificate is presented at the application
// layer (full AIC). Both must be strongly bound to the same entity, otherwise an attacker
// could use someone else's agentId to issue their own authorization certificate to forge
// identity ("same agentId" branch is UTF8String, not a cryptographic binding).
//
// Strong binding assertions (all must pass for G4):
//   - Same key pair: handshake.RawSubjectPublicKeyInfo == auth.RawSubjectPublicKeyInfo
//     (SPKI byte-equal, cryptographic binding — replacing either certificate fails);
//   - Same CA: handshake.RawIssuer == auth.RawIssuer (same issuer);
//   - Same trust chain: auth must be verifiable by the same roots pool that verified the
//     handshake certificate chain (KeyUsages=ClientAuth).
//
// Identifier fields like agentId do not participate in binding (cannot be used as identity
// basis, only for logging/audit).

package gw

import (
	"bytes"
	"crypto/x509"
	"fmt"
)

// VerifyBelongTo verifies that the handshake certificate and authorization certificate
// are strongly bound to the same Agent (G4).
//
// Parameters:
//   - handshake: the handshake certificate presented at the TLS layer (its chain has already
//     been verified by the gateway trust roots during the handshake);
//   - auth: the authorization certificate presented at the application layer (full AIC);
//   - roots: the gateway trust root pool (same as used for verifying the handshake certificate
//     chain); when nil, chain verification is skipped, but SPKI and same-CA checks are still enforced.
//
// Returns an error if any assertion fails (Fail-Close). AgentId extraction is only used for
// logging and does not participate in the decision.
func VerifyBelongTo(handshake, auth *x509.Certificate, roots *x509.CertPool) error {
	if handshake == nil {
		return fmt.Errorf("belong_to: nil handshake cert")
	}
	if auth == nil {
		return fmt.Errorf("belong_to: nil auth cert")
	}

	// Same key pair (cryptographic binding, G4 core).
	if !bytes.Equal(handshake.RawSubjectPublicKeyInfo, auth.RawSubjectPublicKeyInfo) {
		return fmt.Errorf("belong_to: SPKI mismatch (handshake and auth certs are not the same keypair)")
	}

	// Same CA.
	if !bytes.Equal(handshake.RawIssuer, auth.RawIssuer) {
		return fmt.Errorf("belong_to: issuer mismatch (handshake issuer != auth issuer)")
	}

	// Same trust chain: auth must be verifiable by the same trust root pool used to
	// verify the handshake certificate chain.
	if roots != nil {
		if _, err := auth.Verify(x509.VerifyOptions{
			Roots:     roots,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}); err != nil {
			return fmt.Errorf("belong_to: auth cert chain: %w", err)
		}
	}
	return nil
}
