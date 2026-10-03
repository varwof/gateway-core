# Protocol-layer parity report with aic-verifier

Last verified: 2026-09-26

## 1. Purpose and scope

`varwof/gateway` depends on this module at build time (`gateway/go.mod` pins
`github.com/varwof/gateway-core v0.4.7`), so this module is the gateway's
actual decision implementation. `varwof/aic-verifier` is an **independent
extraction** of the same admission engine, for plain API services that do not run
a gateway.

The two modules **share no code**: `aic-verifier` does not depend on
`gateway-core`, and parity is maintained by manual copy. This report records the
current parity state, the divergences that are allowed, and how to re-verify
after every change.

Out of scope: CLC semantics themselves, certificate minting, the policy authoring
tool, and the protocol definitions in `varwof/core`.

The counterpart on the `aic-verifier` side is
[`varwof/aic-verifier/docs/parity-gateway-core.md`](https://github.com/varwof/aic-verifier/blob/main/docs/parity-gateway-core.md).
The two carry the same content; on conflict this file wins, since the gateway
depends on this module at build time.

## 2. Snapshot

| Repository | Branch | HEAD |
|---|---|---|
| `gateway-core` | `feat/acps-aac` | `b112ee4` |
| `aic-verifier` | `main` | `df24fc0` |

The parity changes described here are **not yet committed**; both working trees
are dirty.

## 3. File-level parity

### 3.1 Line-for-line identical (comments differ only)

These 18 files are **identical line for line** once the package clause and
comments are normalised:

| File | File | File |
|---|---|---|
| `aic.go` | `capregistry.go` | `constraints.go` |
| `credential_bundle.go` | `delegation_chain.go` | `parameters.go` |
| `crl.go` | `jwt.go` | `plugin.go` |
| `mask.go` | `merkle.go` | `riskmonitor.go` |
| `nonce_cache.go` | `ocsp.go` | `spiffe.go` |
| `tsa.go` | `user_permission.go` | |

The only remaining textual delta is **comments**: this module annotates patent
claim ids in comments (`P1-B-27`, `P2-A-01`, …); `aic-verifier`, as a clean
open-source extraction, deliberately omits them. `nonce_cache.go` additionally
carries a cross-reference comment naming its mirror, correctly pointing in
opposite directions on each side.

### 3.2 Still divergent (config surface only — see §4)

| File | Nature of the divergence |
|---|---|
| `policy.go` | different injection point for the role-extraction policy |
| `constraints.go` | 41 lines of CLC constraint glue present only in `aic-verifier` (the registry itself is identical) |
| `trust_model.go` | different number of CLC fields passed to `CheckAdmission` |
| `pipeline.go` | CLC field plumbing + `aic-verifier`'s multi-operation aggregation |
| `decision.go` | CLC evaluation layer, constraint-registry routing, `VerifyDelegationAuth` signature |

## 4. Allowlist of permitted divergence

Divergence is permitted only on **config surface that does not exist on the other
side**. Each entry below states why the same input still yields the same verdict,
and under what condition the two would actually diverge.

### 4.1 The CLC operation layer (`pipeline.go` / `decision.go` / `trust_model.go`)

`aic-verifier`'s `AdmissionConfig` carries seven extra fields — `Operations`,
`UnresolvedEvaluator`, `DischargeObligations`, `ObligationsUnderstood`,
`RequireFreshDecisionContext`, `DecisionContext`, `ConstraintRegistry` —
`AdmissionResult` carries `OperationDecisions` and `Sources`, and
`PipelineConfig` / `PipelineResult` carry a matching set. These are **exported
API fields** and must stay as they are on both sides; this module deliberately
does not gain inert counterparts (`DecisionContext` would also pull
`register/semantics` into the gateway, which is not worth it).

All of the CLC **implementation** now lives in `aic-verifier`'s own `clc.go`,
out of the shared files:

| Moved | Now in |
|---|---|
| the 56-line per-operation authorization loop | `clc.go` `evaluateCLCOperations` |
| `checkDecisionContext` | `clc.go` |
| `ConstraintToCapability`, `ConnectionConstraintEvaluator` | `clc.go` |
| `aggregateCLCDecisions` | `clc.go` |
| the 6 lines that carry `OperationDecisions` into a refusal | `clc.go` `denyWithAdmission` |
| assembly of the 7 CLC fields | `clc.go` `applyCLCAdmissionConfig` |

Only two one-line seams are left in the shared files:

```go
applyCLCAdmissionConfig(&ac, cfg)   // assembles the 7 CLC fields
if denied := evaluateCLCOperations(aic, &result, &cfg); denied != nil { return *denied }
```

- Same input, same verdict: the CLC fields do not exist on the gateway side, so
  nothing can trigger them, and `applyCLCAdmissionConfig` has no counterpart here.
- Divergence condition: only when `aic-verifier` is used as a CLC decision point.

### 4.2 The constraint evaluation path (`constraints.go` / `decision.go`)

**The constraint registry itself is identical on both sides**:
`globalConstraintRegistry`, `NewConstraintRegistry`, the
`Register` / `Replace` / `Remove` / `Reset` / `Find` / `Len` / `Keys` methods, the
`RegisterConstraint` / `ReplaceConstraint` / `ResetConstraints` extension points,
the 8 built-in evaluators registered in `init()` (`cidr`, `time_window`,
`max_concurrent`, `hard_timeout`, `idle_timeout`, `read_only`, `audit_required`,
`geo_fence`), and the semantics of `isKnownConstraintType` are all line-for-line
the same. The 41-line `constraints.go` delta **does not involve the registry**.

So that the call sites read identically on both sides, this module **also** grew
the three registry-parameterised forms `checkConstraintsReg` /
`firstUnknownConstraintReg` / `isKnownConstraintTypeReg` plus an
`admissionConstraintRegistry` indirection that always returns
`globalConstraintRegistry`, and the five call sites in `CheckAdmission` now use
the parameterised form. The cost is roughly 20 lines of indirection that does not
do anything here yet; the benefit is that this stretch of constraint evaluation is
**line-for-line identical** across the two modules, which is also what made
`constraints.go` a zero-difference file.

The only real delta left: `aic-verifier`'s `admissionConstraintRegistry` prefers
`cfg.ConstraintRegistry`; this module's always returns the global one.

- Same input, same verdict: when `cfg.ConstraintRegistry` is nil (the default)
  and no `RegisterConstraint` / `ReplaceConstraint` call has been made, both sides
  resolve to the very same `globalConstraintRegistry`.
- Divergence condition: only when an `aic-verifier` embedder supplies a custom
  registry via `AdmissionConfig.ConstraintRegistry`. That widens the "known
  constraint type" set, changing the `unknown constraint type %q` denial under
  `StrictConstraints` and the `ActionUnknownConstraint` audit entry. This module
  has no per-admission registry override: the gateway's constraint vocabulary is
  fixed.

### 4.3 Policy injection point (`policy.go`)

`aic-verifier`'s `extractPolicyRoles(cert, policy)` takes the policy as a
parameter; `gateway-core`'s `ExtractPolicyRoles(cert)` reads the global
`GetAuthorizationPolicy()`. The resulting role set is the same; only where the
policy is fetched differs.

### 4.4 `VerifyDelegationAuth` signature (`decision.go`)

`gateway-core` has the 3-argument
`VerifyDelegationAuth(aic, userCert, agentCert)`. `aic-verifier` keeps the
original 2-argument `VerifyDelegationAuth(aic, userCert)` as a wrapper and puts
the v2 verification in a new `VerifyDelegationAuthWithAgent(aic, userCert,
agentCert)`. The internal implementation and every denial reason are identical —
this is deliberate, to avoid breaking `aic-verifier`'s published API-stability
contract (see its README), not an oversight. `aic-verifier`'s admission path and
delegation chain both call the 3-argument form.

### 4.5 Capabilities that exist only in this module

`gmsm.go`, `pipeline_aac.go`, `shortlived` / `confirmed_renewal`, `selfverify`.
`aic-verifier` has no counterpart; this is feature-scope difference and does not
affect verdicts on shared input.

## 5. Divergences closed in this pass

### 5.1 aic-verifier → gateway-core

| File | Problem | Fix |
|---|---|---|
| `constraints.go` | `RegisterGeoResolver` writes `geoResolvers` while `checkGeoFence` reads it unsynchronised — a data race under `-race` (can panic) | added `sync.RWMutex` and `lookupGeoResolver` |
| `tsa.go` | 4 ASN.1 defects: misused `FullBytes`, un-unwrapped nested OCTET STRING, `rest` not advanced past `certs`, and `parseSignerInfo` silently swallowing Unmarshal errors and yielding an empty signer (downstream then reports "signature verification failed", losing the real cause) | propagate every error; `parseSignerInfo` now returns `error`; `tsa_test.go` updated |
| `jwt.go` | `memReplayStore` capacity 4096; at saturation it evicted the oldest entry — effectively a replay window | capacity raised to 65536; fail-closed when saturated with only live markers (availability traded for safety, documented in the comment) |
| `crl.go` | HTTP client had no dial/TLS-handshake timeout, so one slow CRL endpoint could stall the decision | added 5s dial, 30s keepalive, 5s handshake timeout |
| `nonce_cache.go` | `Stop()` was not idempotent | made idempotent and nil-safe |
| `ocsp.go` | `fallback_allow` is the only fail-open path yet recorded nothing about which certificate it admitted | added one untranslatable `[ERROR] ... ALLOWING certificate <CN> without revocation proof` line |
| `merkle.go` | `string(hash) == string(root)` | changed to `bytes.Equal` |
| `decision_test.go` | `TestVerifyDelegationAuth_SPKIHashMismatch`'s fixture never produced a valid TBS (it omitted `RequestedLifetime`) yet only asserted `err != nil` — a long-standing false green | rewrote the fixture: one shared timestamp, a complete `DelegationAuthTBS`, plus a stronger assertion |

### 5.2 gateway-core → aic-verifier

| File | Problem | Fix |
|---|---|---|
| `spiffe.go`, `pipeline.go` | trust domain was not case-normalised per RFC 7555 §2.1; the allowlist compared un-normalised strings | added `canonicalSPIFFEID`, trust-domain lowercasing + character-set validation; allowlist compares canonicalised values |
| `decision.go` | `DefaultDAAgeMax = 30s`, contradicting the `varwof/core` constant | changed to `time.Minute` |
| `decision.go` | no support for DA v2 `agentKeyBinding` | added `VerifyDelegationAuthWithAgent` (see §4.4) |
| `nonce_cache.go` | `maxScopeUse = 3` cap | **removed** (see §6.2) |

### 5.3 Divergence compression (second pass)

Behaviour unchanged, shared-file divergence down from 290 lines to 60, and
18/22 mirror files now at zero difference:

| Action | Effect |
|---|---|
| `aic-verifier`: moved the whole CLC implementation into its own `clc.go` | the 56-line authorization loop, `aggregateCLCDecisions` and the constraint glue left the shared files |
| `aic-verifier`: `applyCLCAdmissionConfig` assembles the 7 CLC fields | the 19-field `AdmissionConfig` literal in `pipeline.go` / `trust_model.go` is now identical on both sides |
| `aic-verifier`: `denyWithAdmission` extracted from the refusal path | `pipeline.go` loses 6 lines |
| this module: added the `*Reg` parameterised forms + the `admissionConstraintRegistry` indirection | the constraint-evaluation stretch is line-for-line identical; costs this module ~20 lines of indirection that does not yet do anything |
| `aic-verifier`: ported 6 SPIFFE case-insensitivity tests from this module | see §5.4 |

`policy.go`'s 3-line delta was **not** compressed: `aic-verifier`'s
`extractPolicyRoles(cert, policy)` supports per-request policy isolation
(`Config.AuthorizationPolicy`) while this module reads a process-wide global.
Compressing it would mean deleting a security feature, so it stays.

### 5.4 A regression this process caught

During the compression pass a `git checkout -- pipeline.go` also wiped the SPIFFE
canonicalisation ported in the previous round (`canonicalSPIFFEID` + lowercased
trust-domain comparison), and `go test -race ./...` stayed green — because
`aic-verifier` had **no** test covering it, which is exactly the gap recorded in
§8. Fixed by porting `TestParseSPIFFEID_TrustDomainLowercase`,
`TestValidTrustDomainCharset`, `TestCanonicalSPIFFEID`,
`TestVerifySPIFFESAN_CaseInsensitiveTrustDomain`,
`TestPipelineSPIFFETrustDomainCaseVariant` and
`TestPipelineSPIFFEAllowedListCaseInsensitive` from this module's
`spiffe_test.go` into the new `aic-verifier/spiffe_case_test.go`, and verified
that all six do fail when the canonicalisation is removed.

Lesson: **port the tests alongside the implementation** — a clean diff does not
mean matching behaviour.

### 5.5 Fixed on both sides

The v1 → legacy-v0 fallback in `verifyDelegationAuthTBS` could **mask the real
error**: after the `PrincipalUid.KeyHash` cross-check failed it kept trying the v0
encoding and returned v0's "signature verification failed", even though the
original token's signature was valid. Both modules now define an
`errDASignatureMismatch` sentinel, and the fallback happens only when the
signature genuinely does not match.

## 6. Two "alignments" that were rejected

Recorded here so they are not reintroduced.

### 6.1 The DA 30s in core's docs

`varwof/core`'s `docs/openapi.yaml:1147` states `da_max_timestamp_skew`
defaults to 30s, and `docs/bench/{zh,en}/benchmark-report-2026-08-27.md` sizes
nonce capacity from "skew 30s" — but `core/internal/config.go:208` sets
`DefaultDATimestampSkew = time.Minute`. **The docs are stale; the constant wins.**
`gateway-core` was already correct, and `aic-verifier` was aligned to it.

### 6.2 aic-verifier's per-scope nonce cap

`aic-verifier` used to cap same-scope nonce reuse at `maxScopeUse = 3`, which
looks stricter and more "fail-closed" — but it **must not be ported**:

- the DA nonce is a static value inside an X.509 extension; it does not rotate
  per request;
- `aic-verifier`'s `Config.NonceCache` defaults to nil, so the cap never fired;
- `gateway` unconditionally creates a nonce cache at `http/gateway.go:82`, so
  porting it would make a gateway proxying a long-lived certificate **reject
  everything from the 4th request onward**.

Conclusion: neither side caps same-scope reuse; only cross-scope replay is
refused. The rationale is recorded in the `nonce_cache.go` comments on both sides.

## 7. Authoritative values

Confirm the source before changing any of these.

| Value | Source of truth |
|---|---|
| `DefaultDAAgeMax = 1m` | `varwof/core` `internal.DefaultDATimestampSkew` (core's docs say 30s — stale) |
| replay store default capacity 65536, fail-closed at saturation | `jwt.go`, `NewReplayNonceStore` comment |
| same-scope nonce reuse is uncapped | `nonce_cache.go`, `CheckAndAdd` comment |
| SPIFFE trust domain is case-insensitive | RFC 7555 §2.1; implementation in `spiffe.go` |
| 8 built-in constraint types | `aic-verifier/constraints.go` `init()`; hard-coded in this module's `constraints.go` |

## 8. Regression tests

| Test | Covers |
|---|---|
| `TestNonceCacheScopeSeparation` (both) | 64 consecutive same-scope reuses admitted; cross-scope refused |
| `TestCheckDAFreshness` (aic-verifier) | 30s passes / 61s refused (the 1m boundary) |
| `TestVerifyDelegationAuth_SPKIHashMismatch` (this module) | with a valid signature and a wrong keyHash, the denial reason must be the keyHash cross-check failure, not the v0 fallback's |
| `TestVerifyDelegationAuth_ECDSA_Expired` (both) | DA expiry |
| `TestParseSPIFFEID_TrustDomainLowercase`, `TestCanonicalSPIFFEID`, `TestVerifySPIFFESAN_CaseInsensitiveTrustDomain`, `TestPipelineSPIFFETrustDomainCaseVariant`, `TestPipelineSPIFFEAllowedListCaseInsensitive` (this module) | trust-domain case insensitivity |
| `TestOCSPFallbackAllowLogsWarning` (aic-verifier) | the fail-open path must leave a trace |

### Known test gaps

Both are "implementation aligned, tests not caught up" — do not cite "verified on
both sides" as grounds for editing these lines until they are closed:

1. **This module** took the fail-open trace code in `ocsp.go` but has **no**
   `fallback_allow` test of its own (the test exists only in `aic-verifier`'s
   `security_fixes_test.go`).
2. ~~**`aic-verifier`** took `spiffe.go`'s canonicalisation but **not** the
   case-insensitivity tests~~ — **closed in §5.4**, see
   `aic-verifier/spiffe_case_test.go`.

The general rule still stands: test files such as `spiffe_test.go` /
`decision_test.go` are **not** among the 22 mirror files, so it is easy to port
an implementation and leave its test behind. When changing shared logic, port the
test with it.

## 9. How to re-verify

### 9.1 Code parity

```sh
cd /path/to/gateway-core
for f in aic.go capregistry.go constraints.go credential_bundle.go crl.go \
         delegation_chain.go jwt.go mask.go merkle.go nonce_cache.go ocsp.go \
         parameters.go plugin.go rbac.go riskmonitor.go spiffe.go tsa.go \
         user_permission.go; do
  diff <(sed -e 's/^package .*/package X/' ../aic-verifier/$f) \
       <(sed -e 's/^package .*/package X/' "$f")
done
```

Expected: no output at all for the 18 zero-difference files.

The other 4 (`policy.go`, `trust_model.go`, `pipeline.go`, `decision.go`) are
expected to hold only the §4 seams, 60 lines in total; anything beyond that is a
regression.

### 9.2 Build and test

Both modules must pass (`aic-verifier` additionally runs versioncheck and the
showcase):

```sh
gofmt -l .            # expect no output
go vet ./...
go build ./...
go test -race ./...
./hack/versioncheck.sh                      # aic-verifier only
go run ./examples/showcase                  # aic-verifier only, expect exit 0
```

## 10. Maintenance rules

1. When changing any file in §3.1, land it in `aic-verifier` first, then copy it
   into this module, in the same commit. Package `aicverifier` → `gw`, with the
   import paths adjusted.
2. Admission verdicts, denial-reason strings, TTL/time windows and fail-closed
   behaviour must be identical. Denial-reason strings are the de facto
   cross-implementation contract and **must not be changed on one side only**.
3. New divergence may only land inside the §4 allowlist; update this report
   before exceeding it.
4. After each sync, run §9 and update the §2 snapshot and the §5 record.
