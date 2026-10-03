// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Package acps implements a v0 vertical slice of the ACPs-community v2.2.0
// Intelligent Agent Access Control (AAC) profile on top of gateway-core.
//
// Scope (spec commit 3985c1330209f075c124669cc9d31f0e75448140):
//
//   - AIC (ACPs-spec-AIC-v02.02 §3/§4): hierarchical identity-code syntax and
//     the AUTOSAR CRC-16/CCITT-FALSE checksum with the ARSP salt;
//   - AAC (ACPs-spec-AAC-v02.02 §4-§7, §10, §12-§14): trusted authorization
//     context, context providers, delegation boundary, fail-closed decision,
//     authorization-audit, and "do not trust self-claimed payload fields";
//   - AIP (ACPs-spec-AIP-v02.02 §6.0): peer AIC extraction from the mTLS
//     certificate (Subject CN primary, SAN URI:acps://{AIC} supplementary)
//     and the JSON-RPC error-code mapping (-32008/-32009/-32010).
//
// requirements.md (docs/acps/ACPs-v02.2-requirements.md) records the requirement
// baseline; the conformance matrix (docs/acps/conformance-matrix.md) traces each
// rule to its tests. The package is a faithful re-implementation of the AAC
// rules, not a copy of the specification text.
//
// The package deliberately does NOT import the root gateway-core package: the
// root package wires it in (pipeline_aac.go) without a dependency cycle.
package acps
