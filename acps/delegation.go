// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Delegation semantics (AAC §10) and the "do not trust self-claimed fields"
// rule (AAC §14.5).
//
// A DelegationRecord is the unit of cross-hop authorization. To be accepted it
// must be:
//
//   - signed by a trusted issuer (§14.5(6), §10.2);
//   - bound to the presenting identity (§14.2 — cnf/act vs presenter key);
//   - carrying all required claims (iss/sub/aud/exp/iat/jti/scope/act, §10.2);
//   - within the delegation boundary (fixed route / dynamic partner set /
//     chain depth, §10.1/§10.6-§10.7).
//
// Anything that arrives only as an unverifiable payload assertion — an
// unsigned "delegation record", an unbound record, or a record whose fields
// are merely self-declared in the request body — is rejected here, before any
// policy evaluation (§14.5). The crypto envelope below uses Ed25519 + EdDSA
// signed payloads so the "unsigned vs signed" and "unbound vs bound" cases can
// be demonstrated and tested locally; the same record may be carried inside a
// JWT whose signature/exp are verified upstream (aicjwt / gateway JWT
// verifier).
package acps

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Delegation modes (AAC §10.1).
const (
	DelegationModeFixed   = "fixed"
	DelegationModeDynamic = "dynamic"
)

// CanonicalAudience renders the canonical Resource Server audience for an
// agent partner (AAC §6.7(1)).
func CanonicalAudience(aic string) string {
	return "acps:agent:" + NormalizeAICText(aic)
}

// DelegationToken is the normalized view of the delegation token claims
// (AAC §10.2 required fields + §10.3 recommended fields). Zero/empty fields
// mean the claim was absent.
type DelegationToken struct {
	Iss   string
	Sub   string
	Aud   string
	Exp   int64
	Iat   int64
	Nbf   int64
	Jti   string
	Scope string
	Act   string
	CNF   string

	SubjectType       string   // acps_subject_type: human | agent | service
	TargetAIC         string   // acps_target_aic
	SkillID           string   // acps_skill_id
	DelegationID      string   // acps_delegation_id
	DelegationMode    string   // acps_delegation_mode: fixed | dynamic
	BoundaryID        string   // acps_boundary_id
	BoundaryHash      string   // acps_boundary_hash
	ChainDepth        int      // acps_chain_depth
	MaxChainDepth     int      // acps_max_chain_depth
	AllowedRoute      []string // acps_allowed_route (fixed mode)
	AllowedPartnerAIC []string // acps_allowed_partner_aics (dynamic mode)
	Impersonation     bool     // acps_impersonation (must be explicit, §14.4)
}

// RequiredClaims reports the set checked by ValidateRequiredClaims (AAC §10.2).
var RequiredClaims = []string{"iss", "sub", "aud", "exp", "iat", "jti", "scope", "act"}

// TokenClaimsFromJSON decodes a JSON object (JWT payload portion) into a claim
// map for FromTokenClaims.
func TokenClaimsFromJSON(data []byte) (map[string]any, error) {
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("acps: decode token claims: %w", err)
	}
	return m, nil
}

// FromTokenClaims lowers a claim map into the normalized token. Only the
// documented claim names are interpreted (AAC §10.2/§10.3 legend).
func FromTokenClaims(claims map[string]any) *DelegationToken {
	if claims == nil {
		return nil
	}
	return &DelegationToken{
		Iss:               claimString(claims, "iss"),
		Sub:               claimString(claims, "sub"),
		Aud:               claimString(claims, "aud"),
		Exp:               claimInt(claims, "exp"),
		Iat:               claimInt(claims, "iat"),
		Nbf:               claimInt(claims, "nbf"),
		Jti:               claimString(claims, "jti"),
		Scope:             claimString(claims, "scope"),
		Act:               claimString(claims, "act"),
		CNF:               claimString(claims, "cnf"),
		SubjectType:       claimString(claims, "acps_subject_type"),
		TargetAIC:         claimString(claims, "acps_target_aic"),
		SkillID:           claimString(claims, "acps_skill_id"),
		DelegationID:      claimString(claims, "acps_delegation_id"),
		DelegationMode:    claimString(claims, "acps_delegation_mode"),
		BoundaryID:        claimString(claims, "acps_boundary_id"),
		BoundaryHash:      claimString(claims, "acps_boundary_hash"),
		ChainDepth:        int(claimInt(claims, "acps_chain_depth")),
		MaxChainDepth:     int(claimInt(claims, "acps_max_chain_depth")),
		AllowedRoute:      claimStringList(claims, "acps_allowed_route"),
		AllowedPartnerAIC: claimStringList(claims, "acps_allowed_partner_aics"),
		Impersonation:     claimBool(claims, "acps_impersonation"),
	}
}

// ValidateRequiredClaims fails closed when any mandatory delegation-token
// claim is absent (AAC §10.2).
func (t *DelegationToken) ValidateRequiredClaims() error {
	if t == nil {
		return ErrMissingTokenClaims
	}
	missing := []string{}
	if t.Iss == "" {
		missing = append(missing, "iss")
	}
	if t.Sub == "" {
		missing = append(missing, "sub")
	}
	if t.Aud == "" {
		missing = append(missing, "aud")
	}
	if t.Exp == 0 {
		missing = append(missing, "exp")
	}
	if t.Iat == 0 {
		missing = append(missing, "iat")
	}
	if t.Jti == "" {
		missing = append(missing, "jti")
	}
	if t.Scope == "" {
		missing = append(missing, "scope")
	}
	if t.Act == "" {
		missing = append(missing, "act")
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: missing %s", ErrMissingTokenClaims, strings.Join(missing, ","))
	}
	return nil
}

// ValidateLifetime enforces iat <= now <= exp (and nbf when present) (AAC
// §10.2 exp/iat semantics; §12 invalid token mapping).
func (t *DelegationToken) ValidateLifetime(now time.Time) error {
	if t.Exp > 0 && now.Unix() > t.Exp {
		return fmt.Errorf("acps: token expired at %d", t.Exp)
	}
	if t.Iat > 0 && now.Unix() < t.Iat {
		return fmt.Errorf("acps: token not yet valid (iat %d)", t.Iat)
	}
	if t.Nbf > 0 && now.Unix() < t.Nbf {
		return fmt.Errorf("acps: token not yet valid (nbf %d)", t.Nbf)
	}
	if t.Exp > 0 && t.Iat > 0 && t.Exp < t.Iat {
		return fmt.Errorf("acps: token exp %d before iat %d", t.Exp, t.Iat)
	}
	return nil
}

// BoundaryState carries the delegation boundary the current hop was issued
// under (AAC §10.7/§10.6 / §14.1 scope narrowing).
type BoundaryState struct {
	BoundaryID        string
	BoundaryHash      string
	DelegationID      string
	Mode              string // fixed | dynamic
	MaxChainDepth     int
	ChainDepth        int
	AllowedRoute      []string
	AllowedPartnerAIC []string
	TargetAIC         string
	MaxScope          []string // authorized scope set (split of token scope)
}

// ScopeTokens splits a whitespace-separated scope string into the set.
func ScopeTokens(scope string) []string {
	return strings.Fields(scope)
}

// ScopeNarrowed reports whether a next-hop scope is no broader than the bound
// scope (AAC §14.1(2) — Token Exchange must not expand scope). v0 does a
// strict string-set subset comparison on the granted scopes.
func ScopeNarrowed(prev, next []string) bool {
	if len(next) == 0 {
		return true
	}
	set := make(map[string]struct{}, len(prev))
	for _, s := range prev {
		set[s] = struct{}{}
	}
	for _, s := range next {
		if _, ok := set[s]; !ok {
			return false
		}
	}
	return true
}

// Boundary returns the boundary state carried by the token (nil when no
// boundary claims present).
func (t *DelegationToken) Boundary() *BoundaryState {
	if t == nil {
		return nil
	}
	if t.DelegationID == "" && t.BoundaryID == "" && t.MaxChainDepth == 0 &&
		len(t.AllowedRoute) == 0 && len(t.AllowedPartnerAIC) == 0 {
		return nil
	}
	return &BoundaryState{
		BoundaryID:        t.BoundaryID,
		BoundaryHash:      t.BoundaryHash,
		DelegationID:      t.DelegationID,
		Mode:              t.DelegationMode,
		MaxChainDepth:     t.MaxChainDepth,
		ChainDepth:        t.ChainDepth,
		AllowedRoute:      append([]string(nil), t.AllowedRoute...),
		AllowedPartnerAIC: append([]string(nil), t.AllowedPartnerAIC...),
		TargetAIC:         t.TargetAIC,
		MaxScope:          ScopeTokens(t.Scope),
	}
}

// ValidateNext enforces the boundary against a next-hop delegation token
// (AAC §10.6 fixed route, §10.7 dynamic partner set + depth, §14.1 narrowing).
func (b *BoundaryState) ValidateNext(next *DelegationToken) error {
	if b == nil || next == nil {
		return ErrBoundaryViolation
	}
	if b.MaxChainDepth > 0 {
		if next.ChainDepth > b.MaxChainDepth {
			return fmt.Errorf("%w: chain depth %d > max %d", ErrDepthExceeded,
				next.ChainDepth, b.MaxChainDepth)
		}
	}
	mode := b.Mode
	if mode == "" {
		mode = next.DelegationMode
	}
	switch mode {
	case DelegationModeFixed:
		// Current hop must stay on the allowed route (AAC §10.6).
		if len(b.AllowedRoute) > 0 && !containsString(b.AllowedRoute, next.Act) {
			return fmt.Errorf("%w: hop %q not on allowed route", ErrBoundaryViolation, next.Act)
		}
	case DelegationModeDynamic:
		// Next target must be inside the authorized partner set (AAC §10.7).
		if len(b.AllowedPartnerAIC) > 0 && !containsEqualFold(b.AllowedPartnerAIC, next.TargetAIC) {
			return fmt.Errorf("%w: target %q not in allowed partner set", ErrBoundaryViolation, next.TargetAIC)
		}
	case "":
		// No explicit mode: boundary facts are informational; structural
		// checks below still apply.
	}
	// Audience must stay bound to the current Resource Server (canonical
	// audience, §6.7), and next-hop scope must not expand (AAC §14.1(2)).
	if next.Aud != "" && b.TargetAIC != "" && next.Aud != CanonicalAudience(b.TargetAIC) {
		return fmt.Errorf("%w: aud %q out of boundary target %s",
			ErrBoundaryViolation, next.Aud, b.TargetAIC)
	}
	if !ScopeNarrowed(b.MaxScope, ScopeTokens(next.Scope)) {
		return fmt.Errorf("%w: scope %q expands bound scope", ErrBoundaryViolation, next.Scope)
	}
	return nil
}

// DelegationRecord is the envelope that carries a delegation token with proof
// of signature and presenter binding. Only records with Verified && Bound are
// usable for authorization; any other state is rejected (AAC §14.5(6)).
type DelegationRecord struct {
	Token *DelegationToken

	// Payload and Signature are the signed token bytes (Ed25519 in v0; the
	// same envelope can carry a JWT signature verified upstream).
	Payload   []byte
	Signature []byte
	PublicKey ed25519.PublicKey

	// Verified means the signature over Payload checked out with PublicKey.
	Verified bool
	// Bound means the record was bound to the presenter certificate key.
	Bound bool
	// PresenterHash is the SHA-256 of the presenter SPKI (AAC §14.2 cnf).
	PresenterHash []byte
	// Asserted marks records constructed from an unprotected request payload.
	// Such records are always rejected (AAC §14.5(1)(2)(6)).
	Asserted bool
}

// NewSignedDelegation builds a record from a token plus its signed payload.
// Signature verification is deferred: call VerifyDelegation or Verify() before
// using the record (so unsigned construction is distinguishable in tests).
func NewSignedDelegation(tok *DelegationToken, payload, sig []byte, pub ed25519.PublicKey) *DelegationRecord {
	return &DelegationRecord{
		Token:     tok,
		Payload:   append([]byte(nil), payload...),
		Signature: append([]byte(nil), sig...),
		PublicKey: append(ed25519.PublicKey(nil), pub...),
	}
}

// FromSelfClaimedPayload constructs a record whose every claim came from an
// unprotected request payload. It is deliberately marked Asserted so that
// Validate() refuses it unconditionally (AAC §14.5).
func FromSelfClaimedPayload(claims map[string]any) *DelegationRecord {
	return &DelegationRecord{
		Token:    FromTokenClaims(claims),
		Asserted: true,
	}
}

// SignRecord signs the payload with an Ed25519 key (v0 local-issuer envelope).
func SignRecord(payload []byte, priv ed25519.PrivateKey) (ed25519.PublicKey, []byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("acps: sign: invalid private key length %d", len(priv))
	}
	sig := ed25519.Sign(priv, payload)
	return priv.Public().(ed25519.PublicKey), sig, nil
}

// VerifyDelegationSignature checks the Ed25519 signature over the payload.
func VerifyDelegationSignature(payload, sig []byte, pub ed25519.PublicKey) error {
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: invalid signature length", ErrUnsignedDelegation)
	}
	if !ed25519.Verify(pub, payload, sig) {
		return fmt.Errorf("%w: signature mismatch", ErrUnsignedDelegation)
	}
	return nil
}

// BindToPresenter binds the record to the presenter certificate's public key
// (AAC §14.2 certificate-bound token). presenter must be a *x509.Certificate.
func (r *DelegationRecord) BindToPresenter(presenter *x509.Certificate) error {
	if r == nil || presenter == nil || presenter.PublicKey == nil {
		return ErrUnboundDelegation
	}
	spki, err := x509.MarshalPKIXPublicKey(presenter.PublicKey)
	if err != nil {
		return ErrUnboundDelegation
	}
	h := sha256.Sum256(spki)
	r.PresenterHash = h[:]
	r.Bound = true
	return nil
}

// PresenterMatches reports whether the stored presenter hash equals the
// certificate SPKI hash (cnf binding consistency, AAC §14.2).
func (r *DelegationRecord) PresenterMatches(presenter *x509.Certificate) bool {
	if r == nil || presenter == nil || !r.Bound || len(r.PresenterHash) == 0 {
		return false
	}
	spki, err := x509.MarshalPKIXPublicKey(presenter.PublicKey)
	if err != nil {
		return false
	}
	h := sha256.Sum256(spki)
	return bytes.Equal(h[:], r.PresenterHash)
}

// VerifyDelegation performs signature verification; it does not enforce
// binding or policy (those are Validate's job).
func (r *DelegationRecord) VerifyDelegation() error {
	if r == nil || r.Token == nil {
		return ErrMissingTokenClaims
	}
	if r.Asserted {
		return ErrSelfClaimed
	}
	if len(r.Signature) == 0 {
		return ErrUnsignedDelegation
	}
	if err := VerifyDelegationSignature(r.Payload, r.Signature, r.PublicKey); err != nil {
		return err
	}
	r.Verified = true
	return nil
}

// BindSigner is the presenter key type accepted by Validate (certificate).
type BindSigner = *x509.Certificate

// Validate enforces the acceptance gate on a delegation record:
//
//  1. not Asserted (self-claimed payload is never accepted, §14.5);
//  2. signature present and verified (§10.2 / §14.5(6));
//  3. required claims present (§10.2);
//  4. lifetime within now (§12);
//  5. bound to the presenter certificate (§14.2) — bind on demand when
//     presenter is supplied;
//  6. cnf consistency when the token carries a cnf claim.
func (r *DelegationRecord) Validate(presenter *x509.Certificate) error {
	if r == nil || r.Token == nil {
		return ErrMissingTokenClaims
	}
	if r.Asserted {
		return ErrSelfClaimed
	}
	if err := r.VerifyDelegation(); err != nil {
		return err
	}
	if err := r.Token.ValidateRequiredClaims(); err != nil {
		return err
	}
	if err := r.Token.ValidateLifetime(time.Now()); err != nil {
		return err
	}
	if r.Token.CNF != "" {
		// Certificate-bound token (AAC §14.2): a nf token whose cnf does not
		// match the presenter cannot be used.
		if presenter == nil {
			return ErrUnboundDelegation
		}
		if err := r.BindToPresenter(presenter); err != nil {
			return err
		}
		spki, err := x509.MarshalPKIXPublicKey(presenter.PublicKey)
		if err != nil {
			return ErrUnboundDelegation
		}
		h := sha256.Sum256(spki)
		computed := base64.RawURLEncoding.EncodeToString(h[:])
		if !strings.EqualFold(stripCNFPrefix(r.Token.CNF), computed) {
			return fmt.Errorf("%w: cnf does not match presenter key", ErrUnboundDelegation)
		}
	} else if presenter != nil {
		if err := r.BindToPresenter(presenter); err != nil {
			return err
		}
	} else if !r.Bound {
		return fmt.Errorf("%w: record not bound to any presenter", ErrUnboundDelegation)
	}
	return nil
}

// stripCNFPrefix tolerates the x5t#S256: cnf prefix (RFC 7800 style).
func stripCNFPrefix(cnf string) string {
	if i := strings.IndexByte(cnf, ':'); i >= 0 {
		return cnf[i+1:]
	}
	return cnf
}

// EffectiveActorChain derives the verified actor chain for the context
// (AAC §6.4): [primary_subject, ..., act], deduplicated for the single-hop
// case.
func (r *DelegationRecord) EffectiveActorChain() []string {
	if r == nil || r.Token == nil {
		return nil
	}
	primary, err := tokenSubjectID(r.Token)
	if err != nil {
		return nil
	}
	chain := []string{primary}
	if r.Token.Act != "" {
		chain = append(chain, r.Token.Act)
	}
	if len(chain) == 2 && chain[0] == chain[1] {
		chain = chain[:1]
	}
	return chain
}

// Boundary exposes the record's delegation boundary (AAC §10).
func (r *DelegationRecord) Boundary() *BoundaryState {
	if r == nil || r.Token == nil {
		return nil
	}
	return r.Token.Boundary()
}

// JTI returns the token jti for replay tracking (AAC §10.2/§14.3).
func (r *DelegationRecord) JTI() string {
	if r == nil || r.Token == nil {
		return ""
	}
	return r.Token.Jti
}

// ScopeNarrowed reports whether next scope stays inside bound scope.
func tokenSubjectID(tok *DelegationToken) (string, error) {
	switch tok.SubjectType {
	case SubjectTypeHuman:
		iss, sub := splitUnsafe(tok.Sub)
		return ("human:" + iss + "#" + sub), nil
	case SubjectTypeAgent:
		return SubjectID(tok.Sub), nil
	default:
		iss, sub := splitUnsafe(tok.Sub)
		return "service:" + iss + "#" + sub, nil
	}
}

// splitUnsafe splits `{issuer}#{sub}`; when '#' is absent the entire value
// acts as the subject segment (issuer-side may be empty).
func splitUnsafe(s string) (iss, sub string) {
	i := strings.LastIndexByte(s, '#')
	if i < 0 {
		return "", s
	}
	return s[:i], s[i+1:]
}

func claimString(m map[string]any, k string) string {
	if v, ok := m[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func claimInt(m map[string]any, k string) int64 {
	if v, ok := m[k]; ok {
		switch n := v.(type) {
		case float64:
			return int64(n)
		case int64:
			return n
		case int:
			return int64(n)
		case json.Number:
			i, err := n.Int64()
			if err == nil {
				return i
			}
		}
	}
	return 0
}

func claimBool(m map[string]any, k string) bool {
	if v, ok := m[k]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

func claimStringList(m map[string]any, k string) []string {
	v, ok := m[k]
	if !ok {
		return nil
	}
	switch t := v.(type) {
	case []any:
		var out []string
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return append([]string(nil), t...)
	case string:
		return strings.Fields(t)
	}
	return nil
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func containsEqualFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

// SPKIHash is exported for the enforcement layer to bind presenter keys
// (dissonance with the gateway certificate helpers).
func SPKIHash(cert *x509.Certificate) ([]byte, error) {
	if cert == nil || cert.PublicKey == nil {
		return nil, fmt.Errorf("acps: nil presenter certificate")
	}
	spki, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(spki)
	return h[:], nil
}

// Ensure the crypto import is used for future key parsing convenience.
var _ = crypto.SHA256
