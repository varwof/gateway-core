// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// AAC/AIP error mapping — AIP JSON-RPC server-error codes (§12 of AAC,
// error table of AIP). AAC §12 requires that outward-facing error messages
// never leak concrete policy, lists, roles, relationship chains or token
// claims; the detailed reason only enters the audit log. This file therefore
// separates the public message from the internal reason/chain.
package acps

import (
	"errors"
	"fmt"
)

// AIP JSON-RPC server-error codes (AIP error table; AAC §12 reuses them).
const (
	CodeAuthenticationRequired = -32008
	CodeAuthorizationFailed    = -32009
	CodeAccessTokenInvalid     = -32010
)

// ErrCode describes the public error contract of an AAC failure.
type ErrCode struct {
	Code    int    // AIP JSON-RPC code (-32008..-32010)
	Message string // public message, never leaks internals
}

// Public messages (AIP table message column).
const (
	msgAuthenticationRequired = "Authentication required"
	msgAuthorizationFailed    = "Authorization failed"
	msgInvalidAccessToken     = "Invalid access token"
)

// Internal reason codes (audit detail; never exposed outward).
const (
	ReasonMissingCredentials  = "missing_credentials"
	ReasonInvalidPeerIdentity = "invalid_peer_identity"
	ReasonBadToken            = "invalid_access_token"
	ReasonActorMismatch       = "actor_binding_mismatch"
	ReasonPolicyDenied        = "policy_denied"
	ReasonUnsignedDelegate    = "unsigned_delegation_record"
	ReasonUnboundDelegate     = "unbound_delegation_record"
	ReasonSelfClaimed         = "self_claimed_payload_field"
	ReasonChainTailMismatch   = "actor_chain_tail_mismatch"
	ReasonBoundaryViolation   = "delegation_boundary_violation"
	ReasonDepthExceeded       = "chain_depth_exceeded"
	ReasonImpersonation       = "impersonation_denied"
	ReasonObligationFailed    = "obligation_unsatisfied"
	ReasonContextInvalid      = "untrusted_authorization_context"
	ReasonPDPUnavailable      = "pdp_unavailable_or_no_policy"
	ReasonReplayDetected      = "token_replay_detected"
)

// AACError carries a public code/message plus an internal reason for audit.
type AACError struct {
	Code       int    // AIP JSON-RPC code
	Message    string // outward-safe message
	ReasonCode string // internal reason (audit only)
	Err        error  // underlying detail (audit/verbose only)
}

func (e *AACError) Error() string { return e.Message }
func (e *AACError) Unwrap() error { return e.Err }

// Is reports whether e matches a target error (supports errors.Is on sentinels).
func (e *AACError) Is(target error) bool {
	if t, ok := target.(*AACError); ok {
		return t.Code == e.Code && (t.ReasonCode == "" || t.ReasonCode == e.ReasonCode)
	}
	return false
}

// NewAACError builds an error carrying both the public contract and the
// internal reason. The underlying err (detail) is kept out of Error() so the
// public message never leaks the chain.
func NewAACError(code int, message, reason string, err error) *AACError {
	return &AACError{Code: code, Message: message, ReasonCode: reason, Err: err}
}

// AuthenticationRequiredError: missing or invalid required authentication
// credentials / peer certificate / unparsable AIC (AAC §12).
func AuthenticationRequiredError(reason string, err error) *AACError {
	return NewAACError(CodeAuthenticationRequired, msgAuthenticationRequired, reason, err)
}

// AuthorizationFailedError: senderId != peer AIC, act/cnf binding mismatch,
// trusted-context policy denial, missing resource, PDP unavailable (AAC §12).
func AuthorizationFailedError(reason string, err error) *AACError {
	return NewAACError(CodeAuthorizationFailed, msgAuthorizationFailed, reason, err)
}

// AccessTokenInvalidError: badly formed, signed, timed, revoked, untrusted,
// wrong-audience or replayed token (AAC §12).
func AccessTokenInvalidError(reason string, err error) *AACError {
	return NewAACError(CodeAccessTokenInvalid, msgInvalidAccessToken, reason, err)
}

// Typed sentinels used by package logic; tests assert on these with
// errors.Is while the public contract stays stable.
var (
	// ErrUnsignedDelegation: delegation record carries no verifiable signature
	// (AAC §14.5(6)).
	ErrUnsignedDelegation = errors.New("acps: unsigned delegation record")
	// ErrUnboundDelegation: delegation record is not bound to the presenting
	// identity (AAC §14.2/§14.5(6)).
	ErrUnboundDelegation = errors.New("acps: unbound delegation record")
	// ErrSelfClaimed: identity/delegation data self-asserted in unprotected
	// payload (AAC §14.5(1)(2)(6)).
	ErrSelfClaimed = errors.New("acps: self-claimed payload field")
	// ErrMissingTokenClaims: a required delegation-token field is absent
	// (AAC §10.2).
	ErrMissingTokenClaims = errors.New("acps: delegation token missing required claims")
	// ErrChainTailMismatch: actor_chain last element != immediate actor
	// (AAC §6.4(3)).
	ErrChainTailMismatch = errors.New("acps: actor chain tail mismatch")
	// ErrBoundaryViolation: dynamic/fixed boundary violated (AAC §10.6/§10.7).
	ErrBoundaryViolation = errors.New("acps: delegation boundary violation")
	// ErrDepthExceeded: chain depth exceeds the authorized maximum
	// (AAC §9.4(5) / §10.7).
	ErrDepthExceeded = errors.New("acps: delegation chain depth exceeded")
	// ErrImpersonation: impersonation attempted without explicit policy
	// (AAC §14.4).
	ErrImpersonation = errors.New("acps: impersonation denied")
	// ErrObligationsUnsatisfied: PEP could not satisfy mandatory obligations
	// (AAC §6.6).
	ErrObligationsUnsatisfied = errors.New("acps: obligation unsatisfied")
	// ErrContextInvalid: a context provider or resolver failed closed
	// (AAC §7.6(2)).
	ErrContextInvalid = errors.New("acps: untrusted authorization context")
	// ErrPDPUnavailable: no policy and no explicit degradation (AAC §5(6)).
	ErrPDPUnavailable = errors.New("acps: pdp unavailable or no policy")
	// ErrNotExplicitAllow: decision is not an explicit allow (AAC §5(7)).
	ErrNotExplicitAllow = errors.New("acps: decision is not explicit allow")
	// ErrInvalidAIC: malformed AIC code (AIC spec §3/§4).
	ErrInvalidAIC = errors.New("acps: invalid agent identity code")
	// ErrAICChecksum: AIC checksum verification failed (AIC spec §4.2).
	ErrAICChecksum = errors.New("acps: agent identity code checksum mismatch")
	// ErrPeerIdentityMismatch: CN and SAN acps:// disagree (AIP §6.0).
	ErrPeerIdentityMismatch = errors.New("acps: certificate identity mismatch (cn vs san)")
	// ErrMissingPeerIdentity: certificate carries no usable peer AIC (AIP §6.0).
	ErrMissingPeerIdentity = errors.New("acps: missing peer identity in certificate")
	// ErrReplay: jti / one-time token reuse detected (AAC §14.3(2)).
	ErrReplay = errors.New("acps: token replay detected")
)

// acpsErrorf wraps an internal error with a reason tag for audit coherence.
func acpsErrorf(reason string, err error) *AACError {
	return NewAACError(CodeAuthorizationFailed, msgAuthorizationFailed, reason, fmt.Errorf("%w", err))
}
