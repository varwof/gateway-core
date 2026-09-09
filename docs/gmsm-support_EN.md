# GM/SM2-SM3 Verification Support

> Verification side | Does not touch TLS handshake paths | Zero default-build behavior change | Module: `github.com/varwof/gateway-core`, package alias `gw`

## 1. Scope

This module adds **verification-side** GM (SM2/SM3) capability to the gateway: under
CNC / commercial-crypto (商密) compliance requirements it accepts and verifies SM2
certificate chains and SM2 data signatures issued/signed by registered CAs or gateway
self-hosted CAs:

- SM2 certificate chain verification (SM2-with-SM3, OID `1.2.156.10197.1.501`),
  supporting both `root→leaf` and `root→intermediate→leaf` layouts;
- single data-signature verification (message = SM3(ZA‖msg), same convention as the
  tjfoc signing direction);
- SM2 certificate parsing (via tjfoc/gmsm) reusing the existing AIC extraction
  (`ParseAIC`) on the leaf;
- a minimal public verification entry `VerifySM2Bundle`, fully decoupled from TLS
  handshake / certificate verification configuration.

TLS handshake paths are untouched; the default build (without `-tags gmsm`) behaves
exactly as before.

## 2. Build modes: gmsm build-tag pairing

| File | build tag | Behavior |
| --- | --- | --- |
| `gmsm.go` | `//go:build gmsm` | real implementation, imports `github.com/tjfoc/gmsm` |
| `gmsm_stub.go` | `//go:build !gmsm` | every entry fails closed with `ErrSM2NotSupported` |
| `gmsm_shared.go` | no tag | shared types/OIDs/stable reason codes; no tjfoc import (compiles in the default build) |

Tests pair the same way: `gmsm_test.go` (`gmsm`) + `gmsm_stub_test.go` (`!gmsm`).

```bash
# default (no GM) — behavior unchanged
go build ./... && go test ./...

# enable GM verification
go build -tags gmsm ./... && go test -tags gmsm ./...
```

Dependency: `go.mod` pins `github.com/tjfoc/gmsm v1.4.1` (same library/version as core).
The default build compiles only `gmsm_shared.go` + `gmsm_stub.go` and never imports the
gmsm library.

## 3. Public API

```go
// Parses an SM2 certificate into *x509.Certificate (internally via gmsm; the stdlib
// rejects SM2 SPKI).
func ParseSM2Certificate(der []byte) (*x509.Certificate, error)

// Reports whether DER is an SM2 certificate (checks signatureAlgorithm OID 501 only;
// parse failures report false, fail-closed).
func IsSM2Certificate(der []byte) bool

// Single-signature verification: pub is PKIX SPKI (certificate RawSubjectPublicKeyInfo
// form) or gmsm-native oidSM2 SPKI; digest is the exact message bytes the signer signed
// (the ZA‖digest prefixing is internal).
func VerifySM2Signature(pub, digest, sig []byte) error

// SM2 chain verification: resolves the issuer of the leaf among roots, verifies each
// link with SM2-with-SM3. Returns the leaf (*x509.Certificate).
func VerifySM2CertificateChain(leafDER []byte, intermediates, roots [][]byte) (*x509.Certificate, error)

// Minimal public entry: chain verify → (if RequireAIC) extract AIC → (if Signature
// non-empty) verify Data with the leaf public key. On failure the sink writes an audit
// entry with deny_reason=sm2_verify_*.
func VerifySM2Bundle(in SM2BundleInput) (*SM2BundleResult, error)
```

`SM2BundleInput`: `LeafDER`, `Intermediates`, `Roots`, `Data`, `Signature`,
`RequireAIC`, `AuditLogger`, `SrcIP`, `MappingName`, `Target`.

`SM2BundleResult`: `Cert *x509.Certificate`, `AIC *AIC`.

## 4. OIDs

| Purpose | OID |
| --- | --- |
| SM2-with-SM3 signature algorithm | `1.2.156.10197.1.501` |
| SM3 digest algorithm | `1.2.156.10197.1.401` |
| SM2 curve | `1.2.156.10197.1.301` |
| AIC extension | `1.3.6.1.4.1.66257.1.1` (reuses `ParseAIC`) |

## 5. Stable reason codes (audit deny_reason)

`SM2VerifyError{Code, Detail}`, `Error()` prints `"code: detail"`:

| code | trigger |
| --- | --- |
| `sm2_verify_parse_certificate` | DER parse failure on leaf/chain member (incl. truncated) |
| `sm2_verify_not_sm2_certificate` | leaf signature algorithm is not OID 501 (ECDSA/RSA chain) |
| `sm2_verify_parse_public_key` | public-key SPKI parse failure |
| `sm2_verify_unsupported_public_key` | public key not on the SM2 curve / wrong type |
| `sm2_verify_signature` | data signature verification failure |
| `sm2_verify_chain_not_built` | no chain to any trusted root could be built |
| `sm2_verify_chain_signature` | ASN.1 signature check failed at some level (incl. tampering) |
| `sm2_verify_chain_untrusted` | leaf does not match any trusted root (no subject match) |
| `sm2_verify_mixed_chain` | non-SM2 certificate inside the chain |
| `sm2_verify_chain_validity` | leaf/intermediate validity window violated (roots exempt) |
| `sm2_verify_missing_aic` | `RequireAIC` set but leaf carries no AIC extension |
| `sm2_verify_not_supported` | any GM entry invoked in the default (non-gmsm) build |

## 6. Verification semantics

- **Chain**: from the leaf, match by `RawIssuer==RawSubject` (intermediates first),
  verify each link with the issuer's public key via `CheckSignatureFrom`; every chain
  member except the roots must be SM2-with-SM3; loop/depth protection
  (anti-cert-bomb), depth cap = `len(intermediates)+1`.
- **Math**: for SM2-with-SM3 certificates e = SM3(ZA‖RawTBSCertificate); for a single
  signature the message is the signer's digest (ZA‖msg handled internally) — callers
  must not add another hash layer.
- **Key form**: both standard PKIX SPKI (`id-ecPublicKey` + SM2 curve OID) and
  gmsm-native `oidSM2` SPKI are accepted; the curve must be `sm2.P256Sm2()`.
- **AIC**: `ParseSM2Certificate` yields a stdlib certificate, then `ParseAIC` runs
  unchanged; extraction parity with the standard ECDSA certificate path is guaranteed by
  a parity test.

## 7. Tests

Fixtures are generated at test runtime (tjfoc/gmsm): root self-signed → intermediate →
leaf (with AIC extension; the DA is signed by the principal's SM2 key and tagged
SM2-with-SM3). Manual reproduction steps:

1. `sm2.GenerateKey(rand.Reader)` for root/intermediate/leaf and principal keys;
2. build the AIC extension `asn1.Marshal(*aic)` into the template `ExtraExtensions`;
3. `gmx509.Certificate{}.FromX509Certificate(tmpl)` then `gmx509.CreateCertificate`
   sign each level (parent = previously parsed root/intermediate);
4. AIC DelegationAuthTBS DER signed as `userPriv.Sign(rand, sha256(tbs), nil)`.

Coverage: positive chains (two-level and single-level), unrelated CA, same-subject but
different-key root, non-SM2 chain, truncated DER, empty inputs, RequireAIC missing /
satisfied, tampered chain signature, tampered data signature, single-signature
byte-flip, AIC parity, reason-code format and `ErrSM2NotSupported` text.

```bash
go test -tags gmsm -run SM2 -v ./            # GM cases
go test -tags gmsm -race -count=1 ./         # full GM mode + race
go test -count=1 ./                          # full default mode (baseline unchanged)
```

## 8. Golden vectors (core signs → gateway verifies, byte-level closure)

`testdata/gmsm/` holds a set of **fixed DER** issued through core's production
`-tags gmsm` signing path — proving cross-repo interop does not rely on
"isomorphic generation logic":

| File | Content |
| --- | --- |
| `root.der` | SM2 root CA (pure SM2-with-SM3 OID 1.2.156.10197.1.501, self-signed) |
| `intermediate.der` | SM2 intermediate CA (issued by root, IsCA, pathlen=0) |
| `leaf.der` | SM2 leaf **issued by `ca.Sign` (ProfileAgentProxy + BuildAIC)** carrying the AIC extension |
| `leaf.spki.der` | leaf public key, PKIX SPKI |
| `leaf.data.bin` / `leaf.sig.bin` | fixed data + its SM2 signature by the leaf key |
| `expected.json` | expected-value manifest (CN/serial/AIC fields/sig-algo OID) |

The very same bytes live in `core/internal/ca/testdata/gmsm/`. Core's
`TestSM2GoldenVectorRoundTrip` (`-tags gmsm`) and gateway's `TestSM2GoldenFromCore_*`
each verify the identical bytes: whole-chain pure SM2-with-SM3, per-link signature
check, AIC round-trip field parity, sample signature (including one-byte-tamper
rejection). Both sides agreeing on the same bytes is the byte-level closure.

Regeneration (the tool is not committed; it is removed right after signing; a
regeneration yields new random serials — the tests assert only presence/format of
the serial, never a fixed value):

```bash
cd /home/varwof/src/github.com/core
# temporary tool cmd/sm2golden/main.go (//go:build gmsm): GenerateSubCAKey("sm2") for
# four SM2 keys → gmx509 self-signed root, root signs intermediate → DelegationAuthTBS
# (sha256 digest, signed by the principal SM2 key) → ca.Sign(*SignConfig{AIC: &AICConfig{...},
# Profile: ca.ProfileAgentProxy, SkipDB: true, MaxAgentProxyValidity: 24h, …}) for the
# leaf (AIC extension embedded via BuildAIC) → leaf key signs fixed data → writes
# 7 files.
go run -tags gmsm ./cmd/sm2golden -out /tmp/gmsm_golden
# copy *.der *.bin expected.json into both repos' testdata/gmsm/:
cp /tmp/gmsm_golden/* /home/varwof/src/github.com/gateway-core/testdata/gmsm/
cp /tmp/gmsm_golden/* /home/varwof/src/github.com/core/internal/ca/testdata/gmsm/
```

Verify on both sides:

```bash
go test -tags gmsm -run Golden -v ./                     # gateway
go test -tags gmsm -run Golden -v ./internal/ca/         # core
```

## 9. Invariants (regression guard)

- The default build does not import tjfoc/gmsm (`go list -f '{{.GoFiles}}' .` contains
  only `gmsm_shared.go`/`gmsm_stub.go`);
- in the default build every GM entry returns `ErrSM2NotSupported` (fail-closed),
  matching baseline behavior;
- the chain must be all-SM2 and roots must be SM2-keyed; mixed chains are rejected.