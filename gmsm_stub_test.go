// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

//go:build !gmsm

// 默认构建（无 -tags gmsm）下国密入口全部 fail-closed 返回 ErrSM2NotSupported，
// 与 core 仓库 internal/ca/sm2_stubs_test.go 的守卫方式一致（文件级 build tag）。

package gw

import (
	"crypto/x509"
	"errors"
	"testing"
)

func TestParseSM2Certificate_Stub(t *testing.T) {
	if c, err := ParseSM2Certificate([]byte{0x30, 0x00}); !errors.Is(err, ErrSM2NotSupported) || c != nil {
		t.Fatalf("expected ErrSM2NotSupported with nil cert, got cert=%v err=%v", c, err)
	}
}

func TestIsSM2Certificate_Stub(t *testing.T) {
	var zero x509.Certificate
	if IsSM2Certificate(zero.Raw) {
		t.Fatal("default build must report false (fail-closed)")
	}
}

func TestVerifySM2Signature_Stub(t *testing.T) {
	if err := VerifySM2Signature(nil, nil, nil); !errors.Is(err, ErrSM2NotSupported) {
		t.Fatalf("expected ErrSM2NotSupported, got %v", err)
	}
}

func TestVerifySM2CertificateChain_Stub(t *testing.T) {
	if c, err := VerifySM2CertificateChain([]byte{0x30, 0x00}, nil, nil); !errors.Is(err, ErrSM2NotSupported) || c != nil {
		t.Fatalf("expected ErrSM2NotSupported with nil cert, got cert=%v err=%v", c, err)
	}
}

func TestVerifySM2Bundle_Stub(t *testing.T) {
	if r, err := VerifySM2Bundle(SM2BundleInput{}); !errors.Is(err, ErrSM2NotSupported) || r != nil {
		t.Fatalf("expected ErrSM2NotSupported with nil result, got result=%v err=%v", r, err)
	}
}
