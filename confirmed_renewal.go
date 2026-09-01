// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// confirmed_renewal.go — Confirmed renewal flow (patent spec P2-A-12/17, P1-B-12)
//
// Renewal is no longer automatically re-signed by the gateway; instead it enters a
// "awaiting responsible party confirmation" state machine:
//   - Gateway renewal trigger (NeedRenewPct) → RequestRenewal() registers and enters AwaitingConfirmation;
//   - The responsible party (client holding the user private key / management API) calls
//     SignRenewalDA to re-sign DelegationAuthorization with its private key
//     (new nonce/timestamp/requestedLifetime);
//   - Gateway Confirm() verifies the responsible party certificate + DA signature + permission
//     recheck (new capabilities ⊆ responsible party PA grants) → issues new cert to CA with
//     sessionID → marks old cert for transition (ConnExpiryRegistry UpdateCert sets
//     renewed=true → connection close skips revocation);
//   - Reject() explicitly rejects (permissions reduced or responsible party refuses).

package gw

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// RenewalState is the state of the confirmed renewal state machine.
type RenewalState int

// RenewalState values.
const (
	// RenewalIdle indicates no in-progress renewal request.
	RenewalIdle RenewalState = iota
	// RenewalAwaitingConfirmation means renewal was triggered and awaits responsible party confirmation (P2-A-12).
	RenewalAwaitingConfirmation
	// RenewalConfirmed means the responsible party confirmed, new cert issued successfully, old cert marked for transition.
	RenewalConfirmed
	// RenewalRejected means the renewal was rejected (permissions reduced or responsible party refused).
	RenewalRejected
)

// String returns the human-readable name of the state.
func (s RenewalState) String() string {
	switch s {
	case RenewalIdle:
		return "idle"
	case RenewalAwaitingConfirmation:
		return "awaiting_confirmation"
	case RenewalConfirmed:
		return "confirmed"
	case RenewalRejected:
		return "rejected"
	default:
		return "unknown"
	}
}

// DefaultRenewalConfirmTimeout is the default timeout for confirmed renewal awaiting responsible
// party confirmation (24 hours). After timeout, the request automatically transitions to
// Rejected, preventing state machine deadlock.
const DefaultRenewalConfirmTimeout = 24 * time.Hour

// RenewalRequest is the registration information for a renewal request (input for entering
// the awaiting confirmation state).
type RenewalRequest struct {
	// SessionID is the original session identifier carried by the renewal request (P2-A-12, not written to cert).
	SessionID string `json:"session_id"`
	// CA is the target issuing CA name.
	CA string `json:"ca,omitempty"`
	// CN is the certificate common name.
	CN string `json:"cn"`
	// SAN is the certificate SAN (optional).
	SAN string `json:"san,omitempty"`
	// AgentId is the retained agentId.
	AgentId string `json:"agent_id,omitempty"`
	// PrincipalUid is the responsible party UID.
	PrincipalUid string `json:"principal_uid,omitempty"`
	// Capabilities are the capabilities to retain in the new cert (for new ⊆ responsible party PA grants check).
	Capabilities []Capability `json:"capabilities,omitempty"`
	// OldSerial is the old certificate serial number (for transition marking).
	OldSerial string `json:"old_serial,omitempty"`
	// OldCert is the old certificate (for transition marking, contains NotAfter).
	OldCert *x509.Certificate `json:"-"`
	// RequesterKeyHash is the SPKI SHA-256 hash of the authenticated entity that
	// triggered the renewal request (captured server-side from the management
	// mTLS peer, not decoded from JSON). Confirm rejects when the confirming
	// responsible party is the same entity (two-party control, finding 2).
	RequesterKeyHash string `json:"-"`
	// Validity is the new certificate validity (days).
	Validity int `json:"validity,omitempty"`
	// Profile is the issuance profile.
	Profile string `json:"profile,omitempty"`
}

// RenewalConfirmation is the information after responsible party confirmation (Confirm input).
type RenewalConfirmation struct {
	// SessionID matches RenewalRequest.SessionID.
	SessionID string
	// DA is the DelegationAuthorization re-signed by the responsible party (output of SignRenewalDA).
	DA DelegationAuthorization
	// PrincipalCert is the responsible party certificate (basis for signature verification + permission recheck).
	PrincipalCert *x509.Certificate
	// KeyHash is the responsible party SPKI hash (for cross-validation with AIC PrincipalUid.KeyHash, optional).
	KeyHash []byte
}

// confirmedRenewal is the runtime state for a single renewal request.
type confirmedRenewal struct {
	req     *RenewalRequest
	state   RenewalState
	reason  string
	created time.Time
	issued  *IssueResult
}

// ConfirmedRenewalManager manages the confirmed renewal state machine.
// Thread-safe; only one in-progress renewal request is allowed at a time
// (single certificate rotation semantics).
type ConfirmedRenewalManager struct {
	mu       sync.Mutex
	current  *confirmedRenewal
	issueCfg *IssueConfig
	registry *ConnExpiryRegistry
	timeout  time.Duration
	now      func() time.Time
	onIssued func(newCert *x509.Certificate) // Callback: gateway atomic certificate switch

	// verifyPrincipal, when non-nil, cryptographically validates the responsible
	// party certificate presented in Confirm (trust-anchor chain, revocation,
	// custom policy) before the DA signature is accepted. Confirm requires a
	// verifier when actual issuance is configured (issueCfg != nil) and fails
	// closed otherwise, so an attacker-supplied self-signed certificate can never
	// authorize a renewal that produces a new credential.
	verifyPrincipal func(*x509.Certificate) error

	// verifyOldCert, when non-nil, verifies that the old certificate being
	// renewed is still valid and not revoked before a renewal is issued
	// (finding 4). Confirm requires it when issuance is configured and the
	// request carries an old serial, failing closed otherwise so a just-revoked
	// credential cannot be renewed into a fresh valid certificate.
	verifyOldCert func(serial string, oldCert *x509.Certificate) error

	// maxRenewalDAAge is the maximum acceptable age of the responsible party's
	// re-signed DA timestamp (default 5 minutes, finding 10).
	maxRenewalDAAge time.Duration
	// maxRequestedLifetime is the maximum acceptable RequestedLifetime in
	// seconds for a renewal DA (default 24h, finding 10).
	maxRequestedLifetime int
	// renewalNonces, when non-nil, provides one-time-use replay protection for
	// the renewal DA nonce (finding 10).
	renewalNonces *memReplayStore
}

// NewConfirmedRenewalManager creates a confirmed renewal manager.
//   - issueCfg is used to issue new certificates from CA (may be nil: registration/confirmation
//     semantics only, no actual issuance, for testing);
//   - registry, when non-nil, calls UpdateCert on the old certificate after successful issuance
//     to mark the transition;
//   - onIssued, when non-nil, is called after successful issuance (gateway atomic certificate
//     switch entry point).
func NewConfirmedRenewalManager(issueCfg *IssueConfig, registry *ConnExpiryRegistry, onIssued func(newCert *x509.Certificate)) *ConfirmedRenewalManager {
	return &ConfirmedRenewalManager{
		issueCfg:             issueCfg,
		registry:             registry,
		timeout:              DefaultRenewalConfirmTimeout,
		now:                  time.Now,
		onIssued:             onIssued,
		maxRenewalDAAge:      5 * time.Minute,
		maxRequestedLifetime: int((24 * time.Hour) / time.Second),
		renewalNonces:        NewReplayNonceStore(24*time.Hour, 4096),
	}
}

// SetRenewalDAFreshness overrides the maximum acceptable age of the renewal DA
// timestamp (finding 10). Ages older than this are rejected.
func (m *ConfirmedRenewalManager) SetRenewalDAFreshness(maxAge time.Duration) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.maxRenewalDAAge = maxAge
}

// SetRenewalNonceStore replaces the renewal DA replay store (finding 10).
// Pass nil to disable replay protection (not recommended).
func (m *ConfirmedRenewalManager) SetRenewalNonceStore(s *memReplayStore) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.renewalNonces = s
}

// validateRenewalDAFreshness checks the responsible party's re-signed DA for
// timestamp freshness, bounded requested_lifetime, and one-time-use nonce
// replay (finding 10).
func (m *ConfirmedRenewalManager) validateRenewalDAFreshness(conf *RenewalConfirmation) error {
	da := conf.DA
	if da.Timestamp.IsZero() {
		return errors.New("renewal DA timestamp is missing")
	}
	age := m.now().Sub(da.Timestamp)
	if age < 0 || age > m.maxRenewalDAAge {
		return fmt.Errorf("renewal DA timestamp %s is not within the acceptable freshness window (%s)",
			da.Timestamp.Format(time.RFC3339), m.maxRenewalDAAge)
	}
	if da.RequestedLifetime <= 0 {
		return errors.New("renewal DA requested_lifetime must be positive")
	}
	if da.RequestedLifetime > m.maxRequestedLifetime {
		return fmt.Errorf("renewal DA requested_lifetime %d exceeds the maximum %d seconds",
			da.RequestedLifetime, m.maxRequestedLifetime)
	}
	if m.renewalNonces != nil {
		if err := m.renewalNonces.CheckAndAdd(hex.EncodeToString(da.Nonce)); err != nil {
			return fmt.Errorf("renewal DA nonce replay: %w", err)
		}
	}
	return nil
}

// SetTimeout overrides the confirmation timeout (for testing).
func (m *ConfirmedRenewalManager) SetTimeout(d time.Duration) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.timeout = d
}

// SetPrincipalCertVerifier installs the responsible-party certificate verifier.
// The verifier must chain the presented certificate to a trusted identity anchor
// (and may additionally check revocation/OU policy). It is invoked by Confirm
// before the renewal DA is accepted. Deployments that issue new certificates
// must configure one; Confirm fails closed otherwise (finding 1).
func (m *ConfirmedRenewalManager) SetPrincipalCertVerifier(fn func(*x509.Certificate) error) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.verifyPrincipal = fn
}

// SetOldCertVerifier installs the old-certificate revocation verifier invoked by
// Confirm before a renewal is issued. It must confirm the old certificate is
// still valid/unrevoked; Confirm fails closed when issuance is configured but no
// verifier is installed (finding 4).
func (m *ConfirmedRenewalManager) SetOldCertVerifier(fn func(serial string, oldCert *x509.Certificate) error) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.verifyOldCert = fn
}

// validatePrincipalCert runs the responsible-party certificate checks that the
// renewal security depends on (finding 1):
//   - the certificate must be within its validity window (self-contained, always);
//   - when a verifier is installed, it must accept the certificate;
//   - when issuance is configured but no verifier is installed, Confirm fails
//     closed: without a trust anchor the presented certificate is attacker-
//     controllable, so no new credential may be produced from it.
func (m *ConfirmedRenewalManager) validatePrincipalCert(cert *x509.Certificate) error {
	if cert == nil {
		return errors.New("responsible party certificate is required")
	}
	now := m.now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return fmt.Errorf("responsible party certificate not currently valid (notBefore=%s, notAfter=%s)",
			cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
	}
	if m.verifyPrincipal != nil {
		if err := m.verifyPrincipal(cert); err != nil {
			return fmt.Errorf("responsible party certificate verification failed: %w", err)
		}
		return nil
	}
	if m.issueCfg != nil {
		return errors.New("responsible party certificate verification is not configured; refusing to issue a renewal certificate on an unverified responsible party certificate")
	}
	return nil
}

// State returns the current renewal state.
func (m *ConfirmedRenewalManager) State() RenewalState {
	if m == nil || m.current == nil {
		return RenewalIdle
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expireIfTimeout()
	return m.current.state
}

// CurrentSessionID returns the sessionID of the in-progress renewal request.
func (m *ConfirmedRenewalManager) CurrentSessionID() string {
	if m == nil || m.current == nil {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.current.req.SessionID
}

// RequestRenewal initiates a renewal request and enters the AwaitingConfirmation state.
// Returns an error if a request is already in progress and has not timed out.
func (m *ConfirmedRenewalManager) RequestRenewal(req *RenewalRequest) error {
	if m == nil {
		return errors.New("confirmed_renewal: nil manager")
	}
	if req == nil {
		return errors.New("confirmed_renewal: nil request")
	}
	if req.SessionID == "" {
		return errors.New("confirmed_renewal: session_id required")
	}
	if req.CN == "" {
		return errors.New("confirmed_renewal: cn required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.expireIfTimeout()
	if m.current != nil && m.current.state == RenewalAwaitingConfirmation {
		return fmt.Errorf("confirmed_renewal: renewal for session %q already awaiting confirmation", m.current.req.SessionID)
	}
	m.current = &confirmedRenewal{
		req:     req,
		state:   RenewalAwaitingConfirmation,
		created: m.now(),
	}
	return nil
}

// Confirm confirms the renewal by the responsible party (P2-A-12/17):
//  1. Verifies sessionID match and AwaitingConfirmation state;
//  2. Verifies responsible party certificate is non-empty + DA signature (signed by responsible party's private key);
//  3. Permission recheck: new capabilities ⊆ responsible party PA grants (capabilitySubset),
//     out of bounds → Rejected (permissions reduced, P2-A-17);
//  4. Issues new certificate to CA (when issueCfg is non-nil);
//  5. Marks old certificate for transition: registry.UpdateCert(oldSerial, newCert);
//  6. onIssued callback (gateway atomic switch).
func (m *ConfirmedRenewalManager) Confirm(conf *RenewalConfirmation) (*IssueResult, error) {
	if m == nil {
		return nil, errors.New("confirmed_renewal: nil manager")
	}
	if conf == nil {
		return nil, errors.New("confirmed_renewal: nil confirmation")
	}
	if conf.PrincipalCert == nil {
		return nil, errors.New("confirmed_renewal: principal cert required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.expireIfTimeout()
	if m.current == nil {
		return nil, errors.New("confirmed_renewal: no pending renewal request")
	}
	if m.current.req.SessionID != conf.SessionID {
		return nil, fmt.Errorf("confirmed_renewal: session_id mismatch (want %q, got %q)", m.current.req.SessionID, conf.SessionID)
	}
	if m.current.state != RenewalAwaitingConfirmation {
		return nil, fmt.Errorf("confirmed_renewal: renewal not awaiting confirmation (state %s)", m.current.state)
	}

	// 0. Validate the responsible party certificate (trust anchor, expiry) before
	//    accepting the DA signature or permission grants parsed from it.
	if err := m.validatePrincipalCert(conf.PrincipalCert); err != nil {
		m.current.state = RenewalRejected
		m.current.reason = err.Error()
		return nil, errors.New(m.current.reason)
	}

	// 0a. Two-party control (finding 2): the entity that requested the renewal
	//     must not be the same entity that confirms it. When the requester
	//     identity was captured, an identical responsible-party key fails closed.
	if req := m.current.req; req.RequesterKeyHash != "" {
		if strings.EqualFold(req.RequesterKeyHash, KeyHashHex(conf.PrincipalCert)) {
			m.current.state = RenewalRejected
			m.current.reason = "two-party control: the renewal requester cannot confirm its own renewal"
			return nil, errors.New(m.current.reason)
		}
	}

	// 1. Verify DA signature (signed by responsible party's private key, DelegationAuthTBS recomputed)
	if err := verifyRenewalDA(m.current.req, conf.PrincipalCert, conf.DA); err != nil {
		m.current.state = RenewalRejected
		m.current.reason = fmt.Sprintf("da verification failed: %v", err)
		return nil, errors.New(m.current.reason)
	}

	// 1a. DA freshness/lifetime/replay (finding 10): a replayed or stale DA, or
	//     one requesting an unbounded lifetime, must not confirm a renewal.
	if err := m.validateRenewalDAFreshness(conf); err != nil {
		m.current.state = RenewalRejected
		m.current.reason = err.Error()
		return nil, errors.New(m.current.reason)
	}

	// 2. Permission recheck: new capabilities ⊆ responsible party PA grants (permissions reduced → reject renewal)
	if err := m.checkPermissions(conf); err != nil {
		m.current.state = RenewalRejected
		m.current.reason = err.Error()
		return nil, errors.New(m.current.reason)
	}

	// 2a. Old-certificate revocation (finding 4): a just-revoked credential must
	//     not be "renewed" into a fresh valid certificate. When issuance is
	//     configured and the request names an old serial, the old certificate
	//     must be verified unrevoked or the renewal fails closed.
	if m.issueCfg != nil && m.current.req.OldSerial != "" {
		if m.verifyOldCert == nil {
			m.current.state = RenewalRejected
			m.current.reason = "old certificate revocation verification is not configured; refusing to issue a renewal for an unverified old certificate"
			return nil, errors.New(m.current.reason)
		}
		var oldCert *x509.Certificate
		if m.registry != nil {
			oldCert = m.registry.Certificate(m.current.req.OldSerial)
		}
		if err := m.verifyOldCert(m.current.req.OldSerial, oldCert); err != nil {
			m.current.state = RenewalRejected
			m.current.reason = fmt.Sprintf("old certificate revocation check failed: %v", err)
			return nil, errors.New(m.current.reason)
		}
	}

	// 3. Issue new certificate
	var issued *IssueResult
	if m.issueCfg != nil {
		client, err := NewIssueClient(*m.issueCfg)
		if err != nil {
			m.current.state = RenewalRejected
			m.current.reason = fmt.Sprintf("issue client init: %v", err)
			return nil, errors.New(m.current.reason)
		}
		req := m.current.req
		issued, err = client.Issue(&IssueRequest{
			CA:        req.CA,
			CN:        req.CN,
			SAN:       req.SAN,
			Profile:   req.Profile,
			Validity:  req.Validity,
			OldSerial: req.OldSerial,
		})
		if err != nil {
			m.current.state = RenewalRejected
			m.current.reason = fmt.Sprintf("issue new cert: %v", err)
			return nil, errors.New(m.current.reason)
		}
	}

	m.current.state = RenewalConfirmed
	m.current.issued = issued

	// 4. Mark old certificate for transition (new cert inherits concurrency count; connection close skips revocation)
	if m.registry != nil && m.current.req.OldSerial != "" {
		var newCert *x509.Certificate
		if issued != nil {
			newCert, _ = issued.Certificate()
		}
		m.registry.UpdateCert(m.current.req.OldSerial, newCert)
	}

	// 5. Gateway atomic switch callback
	if m.onIssued != nil && issued != nil {
		if newCert, err := issued.Certificate(); err == nil {
			m.onIssued(newCert)
		}
	}

	return issued, nil
}

// Reject explicitly rejects the renewal (responsible party refused or gateway found permissions reduced).
func (m *ConfirmedRenewalManager) Reject(reason string) {
	if m == nil || m.current == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current.state == RenewalAwaitingConfirmation {
		m.current.state = RenewalRejected
		m.current.reason = reason
	}
}

// Reason returns the rejection/reason information for the current renewal request.
func (m *ConfirmedRenewalManager) Reason() string {
	if m == nil || m.current == nil {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.current.reason
}

// Issued returns the certificate result issued for the current renewal request (available after Confirmed).
func (m *ConfirmedRenewalManager) Issued() *IssueResult {
	if m == nil || m.current == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.current.issued
}

// Reset clears the current renewal request (reverts to Idle, for testing/reuse).
func (m *ConfirmedRenewalManager) Reset() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.current = nil
}

// expireIfTimeout automatically transitions to Rejected on timeout (must be called with lock held).
func (m *ConfirmedRenewalManager) expireIfTimeout() {
	if m.current == nil || m.current.state != RenewalAwaitingConfirmation {
		return
	}
	if m.timeout <= 0 {
		return
	}
	if m.now().Sub(m.current.created) > m.timeout {
		m.current.state = RenewalRejected
		m.current.reason = fmt.Sprintf("renewal confirmation timed out after %s", m.timeout)
	}
}

// checkPermissions performs permission recheck (P2-A-17): new capabilities ⊆ responsible party PA grants.
// When no PA grants are present, checks new capabilities ⊆ old certificate capabilities
// (preserves existing authorization boundaries). If neither bounds the new
// capabilities and the manager is configured to issue, the recheck fails closed
// so an attacker cannot mint a renewal certificate with unbounded capabilities
// (finding 1: the old-certificate fallback is unreachable via the API because
// RenewalRequest.OldCert is not decoded from JSON).
func (m *ConfirmedRenewalManager) checkPermissions(conf *RenewalConfirmation) error {
	req := m.current.req
	newCaps := req.Capabilities

	// Prefer responsible party PA grants
	pa, err := ParseUserPermissionExtension(conf.PrincipalCert)
	if err != nil {
		return fmt.Errorf("permission recheck: parse principal authorization: %v", err)
	}
	if pa != nil && len(pa.Grants) > 0 {
		if !capabilitySubset(newCaps, pa.Grants) {
			return fmt.Errorf("permission recheck: renewal capabilities exceed principal authorization grants (privileges reduced)")
		}
		return nil
	}

	// Fall back to old certificate capabilities
	if req.OldCert != nil {
		oldAIC, err := ParseAIC(req.OldCert)
		if err != nil {
			return fmt.Errorf("permission recheck: parse old aic: %v", err)
		}
		if oldAIC != nil && !capabilitySubset(newCaps, oldAIC.Capabilities) {
			return fmt.Errorf("permission recheck: renewal capabilities exceed old certificate capabilities (privileges reduced)")
		}
		if oldAIC != nil {
			return nil
		}
	}

	// No bounding authorization available: when the manager actually issues, refuse
	// rather than grant the requested capabilities unconstrained.
	if m.issueCfg != nil {
		return errors.New("permission recheck: renewal capabilities are unconstrained (no principal authorization grants and no old certificate authorization); refusing renewal")
	}
	return nil
}

// SignRenewalDA has the responsible party re-sign DelegationAuthorization with its private key
// (P2-A-12): generates a DA with new nonce/timestamp/requestedLifetime, signing the
// DelegationAuthTBS DER content.
// The responsible party client calls this and passes the result + responsible party certificate
// to the gateway's Confirm().
func SignRenewalDA(req *RenewalRequest, key crypto.Signer, nonce []byte, ts time.Time, lifetime int, reasonCode, reasonDesc string) (DelegationAuthorization, error) {
	if req == nil {
		return DelegationAuthorization{}, errors.New("sign_renewal_da: nil request")
	}
	if len(nonce) != 32 {
		return DelegationAuthorization{}, fmt.Errorf("sign_renewal_da: nonce must be exactly 32 bytes, got %d", len(nonce))
	}
	if lifetime <= 0 {
		return DelegationAuthorization{}, fmt.Errorf("sign_renewal_da: lifetime must be positive")
	}
	if ts.IsZero() {
		ts = time.Now()
	}

	var principalUid PrincipalUid
	if req.PrincipalUid != "" {
		pu, err := ParsePrincipalUid(req.PrincipalUid)
		if err != nil {
			return DelegationAuthorization{}, fmt.Errorf("sign_renewal_da: parse principal uid: %v", err)
		}
		principalUid = pu
	}

	tbs := DelegationAuthTBS{
		Version:           1,
		AgentId:           req.AgentId,
		PrincipalUid:      principalUid,
		Reason:            Reason{ReasonCode: reasonCode, Description: reasonDesc},
		Capabilities:      req.Capabilities,
		DelegationMode:    DelegationAuthorized,
		RequestedLifetime: lifetime,
		Timestamp:         ts,
		Nonce:             nonce,
	}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return DelegationAuthorization{}, fmt.Errorf("sign_renewal_da: marshal tbs: %w", err)
	}
	digest := sha256.Sum256(tbsDER)

	sigAlgo := AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256}
	var sig []byte
	switch key.Public().(type) {
	case *ecdsa.PublicKey:
		sig, err = ecdsa.SignASN1(rand.Reader, key.(*ecdsa.PrivateKey), digest[:])
		if err != nil {
			return DelegationAuthorization{}, fmt.Errorf("sign_renewal_da: ecdsa sign: %w", err)
		}
	case *rsa.PublicKey:
		sigAlgo = AlgorithmIdentifier{Algorithm: OIDSigRSAWithSHA256}
		sig, err = rsa.SignPKCS1v15(rand.Reader, key.(*rsa.PrivateKey), crypto.SHA256, digest[:])
		if err != nil {
			return DelegationAuthorization{}, fmt.Errorf("sign_renewal_da: rsa sign: %w", err)
		}
	default:
		return DelegationAuthorization{}, fmt.Errorf("sign_renewal_da: unsupported key type %T", key.Public())
	}

	return DelegationAuthorization{
		Reason:             Reason{ReasonCode: reasonCode, Description: reasonDesc},
		RequestedLifetime:  lifetime,
		Timestamp:          ts,
		Nonce:              nonce,
		SignatureAlgorithm: sigAlgo,
		SignatureValue:     sig,
	}, nil
}

// verifyRenewalDA verifies the renewal DA signature using the responsible party's certificate
// (DelegationAuthTBS recomputed).
func verifyRenewalDA(req *RenewalRequest, principalCert *x509.Certificate, da DelegationAuthorization) error {
	if principalCert == nil {
		return errors.New("principal cert is nil")
	}
	if len(da.SignatureValue) == 0 {
		return errors.New("empty signature")
	}
	if len(da.Nonce) != 32 {
		return fmt.Errorf("nonce length %d: must be exactly 32 bytes", len(da.Nonce))
	}

	principalUid := PrincipalUid{}
	if req.PrincipalUid != "" {
		pu, err := ParsePrincipalUid(req.PrincipalUid)
		if err != nil {
			return fmt.Errorf("parse principal uid: %v", err)
		}
		principalUid = pu
	}

	tbs := DelegationAuthTBS{
		Version:           1,
		AgentId:           req.AgentId,
		PrincipalUid:      principalUid,
		Reason:            da.Reason,
		Capabilities:      req.Capabilities,
		DelegationMode:    DelegationAuthorized,
		RequestedLifetime: da.RequestedLifetime,
		Timestamp:         da.Timestamp,
		Nonce:             da.Nonce,
	}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return fmt.Errorf("marshal tbs: %w", err)
	}
	digest := sha256.Sum256(tbsDER)

	switch pub := principalCert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if !da.SignatureAlgorithm.Algorithm.Equal(OIDSigECDSAWithSHA256) {
			return fmt.Errorf("unsupported ECDSA algorithm OID %s", da.SignatureAlgorithm.Algorithm)
		}
		if !ecdsa.VerifyASN1(pub, digest[:], da.SignatureValue) {
			return errors.New("ecdsa signature verification failed")
		}
	case *rsa.PublicKey:
		switch {
		case da.SignatureAlgorithm.Algorithm.Equal(OIDSigRSAWithSHA256):
			if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], da.SignatureValue); err != nil {
				return fmt.Errorf("rsa-sha256 verification: %w", err)
			}
		case da.SignatureAlgorithm.Algorithm.Equal(OIDSigRSAPSSWithSHA256):
			if err := rsa.VerifyPSS(pub, crypto.SHA256, digest[:], da.SignatureValue, nil); err != nil {
				return fmt.Errorf("rsa-pss-sha256 verification: %w", err)
			}
		default:
			return fmt.Errorf("unsupported RSA algorithm OID %s", da.SignatureAlgorithm.Algorithm)
		}
	default:
		return fmt.Errorf("unsupported key type %T", principalCert.PublicKey)
	}
	return nil
}

// KeyHashHex returns the certificate SPKI SHA-256 hash (hex), used for AIC PrincipalUid.KeyHash cross-validation.
func KeyHashHex(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return strings.ToUpper(fmt.Sprintf("%X", sum[:]))
}

// DAToPayload serializes the DelegationAuthorization re-signed by the responsible party into
// a management API JSON payload.
// The responsible party client obtains the DA via SignRenewalDA, calls this function to pack
// it, and POSTs to /api/v1/gateway/renewal/confirm.
func DAToPayload(da DelegationAuthorization) RenewalDAPayload {
	return RenewalDAPayload{
		ReasonCode:         da.Reason.ReasonCode,
		ReasonDesc:         da.Reason.Description,
		RequestedLifetime:  da.RequestedLifetime,
		Timestamp:          da.Timestamp.Format(time.RFC3339Nano),
		Nonce:              da.Nonce,
		SignatureAlgorithm: da.SignatureAlgorithm.Algorithm.String(),
		SignatureValue:     da.SignatureValue,
	}
}
