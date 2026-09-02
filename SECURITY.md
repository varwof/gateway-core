# Security Policy

## Reporting a Vulnerability

If you find a security vulnerability in `varwof/gateway-core`, please do
not open a public issue. Report it privately to
[pki@varwof.com](mailto:pki@varwof.com).

Please include:

- The affected version(s)
- A description of the vulnerability and its impact
- A minimal reproducer if available

You should receive an acknowledgement within a few business days.
We ask that you give us reasonable time to address the issue before
public disclosure.

## Scope

This project is the security/access-control core library of the
zero-trust gateway (pipeline, AIC/DA decision, AIC-JWT, revocation,
confirmed renewal, management, audit, TSA). Issues of interest include:

- Authentication / authorization bypass (AIC-JWT bearer, confirmed
  renewal, delegated-agent)
- Revocation fail-open (OCSP/CRL) and revocation-defeat via renewal
- Audit/tamper-evidence integrity
- Management-interface RBAC and privilege escalation

## Supported Versions

Security fixes are applied to the latest release. Older releases are
supported on a best-effort basis.

## Funding note: no paid third-party audit

This is an individual / open-source project; no paid third-party
security audit has been conducted. Validation relies on internal
AI-assisted review, automated tests (race-enabled), and independent
cross-implementation exercise where available.

## Security Audit History

Review practice: development includes AI-assisted security review and
RFC compliance cross-checks (PKI (RFC 5280), OCSP (RFC 6960), TSA (RFC 3161), JOSE bearer (RFC 7519/9068)). Consolidated findings are
logged below; each is retained as a historical record after resolution.

### 2026-09-01 -- internal security review (AI-assisted), resolved

Method: internal security/correctness review of the current `main`,
assisted by AI tooling, with RFC cross-checks against PKI (RFC 5280), OCSP (RFC 6960), TSA (RFC 3161), JOSE bearer (RFC 7519/9068).
Status: all findings below were resolved in the 2026-09-01 security
pass (commit 33194ba) and verified by the full test suite. Fixes were verified by the full test suite (race-enabled).

Next scheduled review: quarterly (next: 2026-12-01).
Independent exercise: third-party hostile testing exercised the capability plugins (2026-09).

### Resolved findings (2026-09-01)

### Security (high)

1. **Confirmed-renewal issuance-authorization bypass — the responsible
   party certificate is never validated** (`confirmed_renewal.go:218-300,
   :466-528, :362-389`; `management.go:937-987`).
   `/api/v1/gateway/renewal/confirm` takes `principal_cert_pem` from the
   attacker-controlled request body. `verifyRenewalDA`
   (`confirmed_renewal.go:466`) verifies the DA signature only against
   that caller-supplied cert's public key — it never validates the cert
   against a trust anchor, expiry, or revocation. `checkPermissions`
   (`confirmed_renewal.go:362`) then trusts the `user_permission` PA
   grants parsed (`:367`) from that same self-supplied cert, only
   bounding the new cert's capabilities to the attacker-chosen grants.
   The safe fallback (`req.OldCert` caps, `:379`) is unreachable via the
   API because `RenewalRequest.OldCert` is `json:"-"` (always nil). A
   caller can mint a self-signed principal cert granting arbitrary
   capabilities, confirm a renewal with escalated capabilities, and
   receive the new cert **and private key** (`key_pem`,
   `management.go:983`). The whole responsible-party permission recheck
   is effectively a no-op.

2. **Renewal two-party control is not enforced — the same role requests
   and confirms** (`management.go:199-209`). `/renewal/request` and
   `/renewal/confirm` are both `RoleOps, RoleAdmin`; only `/renewal/reject`
   is `RoleAdmin`. The required "responsible party ≠ requester"
   separation is not enforced, so an Ops user self-approves, amplifying
   item 1.

3. **OCSP `fallback=crl` is a silent fail-open that never consults the
   CRL** (`ocsp.go:216-235`; `pipeline.go`). `fallbackErr` returns `nil`
   (valid/allow) for both `OCSPFallbackAllow` and **`OCSPFallbackCRL`** —
   the "crl" branch never performs a CRL check. This path is reached on
   any OCSP network/parse failure and on the single-leaf (nil-issuer)
   case (`ocsp.go:171-173`). An operator choosing "crl" believes
   revocation is fail-closed but it is fully fail-open. `deny` (default)
   is the only fail-closed option.

4. **Revocation defeated by renewal — renewed cert has no link to the
   original, and a revoked identity can re-enroll**
   (`confirmed_renewal.go:265-297`; `connexpiry.go:130-132`). `Confirm`
   issues a fresh cert without checking that the old serial
   (attacker-supplied) is unrevoked, and with no serial linkage back to
   the original. `registry.UpdateCert(OldSerial, newCert)` then marks the
   old serial `renewed` so its revocation is skipped on connection close.
   A just-revoked credential can be "renewed" into a fresh valid cert.

5. **AIC-JWT bearer has no replay protection, no proof-of-possession, and
   no issuer/audience binding** (`jwt.go:80-106`). `VerifyBearer` calls
   `aicjwt.Validate` with only `Now` and `IssuerKeys`. It never sets
   `NonceStore` (outer `jti` is never replay-checked), `PresenterKey`
   (the `cnf` binding is never verified), `ExpectedIssuer`, or
   `ExpectedAudience`. The code comment (`jwt.go:176-182`) explicitly
   states the replay checks "only run when explicitly configured
   (RequireUserAuth / NonceCache), which a JWT carrier does not satisfy."
   A stolen/sniffed bearer token is therefore reusable until `exp` by any
   bearer, with no key possession required and no revocation path (see
   item 6). (The underlying `aicjwt.Validate` semantics live in
   `types/aicjwt`, already reviewed in the `types` report.)

### Security (medium)

6. **Synthesized bearer cert cannot be revoked — serial 0, issuer from
   `iss`** (`jwt.go:133-135`). Every token synthesizes a cert with
   `SerialNumber: 0` and `Issuer: outer.Iss`, so the CRL/OCSP lookup
   (`pipeline.go`) can never match a real CA. Bearer identities are not
   revocable. Additionally, `nonceFromJTI` (`jwt.go:194`) derives a
   deterministic nonce from `jti`, and the constant serial collapses all
   bearer tokens into one per-cert accounting slot.

7. **OCSP requests carry no nonce and responses are never checked for
   freshness** (`ocsp.go:175,196-204`). `ocsp.CreateRequest(cert, issuer,
   nil)` sends no nonce, and the result is cached with no
   `ThisUpdate`/`NextUpdate`/`ProducedAt` validation. A captured or stale
   "Good" response can be replayed/cached for the full TTL.

8. **Audit tamper-evidence is never enforced on read; chain continuity
   not verified** (`audit.go` read path, `merkle.go:145-163`). The audit
   read path parses entries without TSA verification and without Merkle
   membership checks; `AuditChain.Seal` takes `previousRoot` as a
   caller-supplied string with no continuity enforcement. An actor who
   can edit the audit file can delete/reorder/insert entries without
   detection by the audit endpoint.

9. **TSA CMS signature verification is incorrect — tamper evidence
   unverifiable** (`tsa.go` `verifyCMSSignature`). The verifier passes
   the 32-byte message imprint as the encapContent and hashes `SignedAttrs`
   including the `0xA0` tag instead of the RFC 5652 §5.4 SET OF (`0x31`)
   encoding, and never validates the message-digest attribute. Real
   RFC 3161 tokens fail verification (availability) and the check gives
   no trustworthy tamper evidence.

10. **Renewal DA nonce/timestamp/lifetime are not validated for
    freshness or replay** (`confirmed_renewal.go:466-528`).
    `verifyRenewalDA` checks only nonce length and signature; `Timestamp`
    is not compared to "now", `RequestedLifetime` is unbounded, and the
    nonce is never passed through a nonce cache. Reply DAs can be played
    back and arbitrarily long lifetimes requested.

11. **OCSP fail-open cap only applies to `allow`, not `crl`**
    (`pipeline.go`). The short-lifetime mitigation (`OfflineLifetimeFor`)
    applies a 1h cap only for exactly `OCSPFallbackAllow`; `crl`/`deny`
    return no cap, yet `crl` is fail-open (item 3) — yielding uncapped
    fail-open under the mislabeled "crl" setting.

12. **Management RBAC trusts unverified presented client cert; the server
    does not enforce mTLS itself** (`rbac.go` `RequireRoles`/`PeerCertRoles`,
    `management.go` `Start`). Role OUs are read from
    `r.TLS.PeerCertificates[0]` with no cryptographic verification, and
    `Start` uses the provided `TLSConfig` as-is. If that config lacks
    `ClientAuth=RequireAndVerifyClientCert`, role authorization is
    bypassable by any peer presenting a self-issued cert with a
    `gateway:*` OU. Enforcement is by configuration only.

13. **CRL lookup keyed by `Issuer.String()` equality can silently miss
    revocations** (`crl.go:118,176`; `pipeline.go`). Entries are stored
    under `caCert.Subject.String()` but looked up by
    `clientCert.Issuer.String()`; any RDN ordering/formatting difference
    makes a revoked serial miss and be treated as valid (fail-open).

14. **`MuxStream` receive buffer is unbounded** (`streammux.go`) — a peer
    sending frames faster than the consumer reads grows memory without
    limit (memory DoS).

15. **Audit suppression via buffer-full drop + rotation** (`audit.go`).
    `Log` drops entries when the channel is full (counter only), and
    rotation lets old entries disappear after a backup cap — an attacker
    flooding privileged operations can evict legitimate entries.

### Low / robustness

16. **Self-authorization fallback lets an agent fill its own
    `RequireUserAuth`** (`decision.go:563-566`): when no user cert/keyhash
    is available, `userCert = cert` and the DA is verified against the
    agent's own key, relaxing "user authorization required" to
    agent==user wherever the AIC lacks a `PrincipalUid.KeyHash`.

17. **`CheckDelegatedAgentCert` is a no-op that always accepts**
    (`decision.go:869-874`) — every path returns `""` (success); any
    caller gating delegated-agent certs on it always admits.
    `DelegatedAgentServerIdentity` always returns a zero `expiry`.

18. **CIDR / geo-fence constraints fail open when `ClientIP` is empty**
    (`constraints.go`). Both return allow when `ctx.ClientIP == ""`; a
    gateway not populating client IP (behind a LB / TCP without source
    capture) silently bypasses source-address/geo restrictions.

19. **Unbounded `io.ReadAll` on issue/OCSP/CRL responses**
    (`shortlived.go`, `ocsp.go:186`, `crl.go:147`) — no `LimitReader`.

20. **`VerifyBundle` trusts client-supplied CA certs as roots when the
    caller passes nil** (`credential_bundle.go`) — a self-signed chain can
    self-anchor. Callers must supply trusted roots.

21. **Masking leaks for short inputs** (`mask.go`) — `MaskToken` reveals
    8 chars for ~9-12 char tokens; metrics/tracker expose raw serial
    prefixes (`tracker.go`).

22. **Merkle uniformity / single-leaf root promotion** (`merkle.go`) —
    un-prefixed `sha256(left||right)`, lone leaf promoted to root, and
    no proof-length-vs-height bound.

23. **Audit index/FTS postings grow unbounded** (`audit_index.go`,
    `audit_fts.go`) — by_cn/by_serial/by_word buckets append per entry
    with no eviction.

### Verified-clean / non-issues (checked)

- No algorithm confusion in `aicjwt.Validate`: `alg=none` rejected,
  allowlist enforced, key type-checked against algorithm (RS256 requires
  RSA, ES256 requires P-256); unknown algs fail closed.
- DA signature verification (`VerifyDelegationAuth`) restricts to
  SHA-256 OIDs and cross-checks SPKI; `VerifyDelegationChain` checks
  depth/cycles.
- No `InsecureSkipVerify` in non-test code; TLS min 1.2 with
  GCM/CHACHA suites.

### Environment (not a code bug)

24. `go.mod` declares `go 1.26` while the available toolchain is 1.25.10;
    some analysis tooling fails in this environment.
