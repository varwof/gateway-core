// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

//go:build !gmsm

// 国密（SM2/SM3）验证核心 —— 默认构建（无 -tags gmsm）stub。
//
// 与 gmsm.go（//go:build gmsm）配对：函数签名完全一致，全部 fail-closed 返回
// ErrSM2NotSupported，默认构建不 import tjfoc/gmsm、行为与改动前完全一致。

package gw

import "crypto/x509"
import "time"

// ParseSM2Certificate 默认构建下不可用。
func ParseSM2Certificate(der []byte) (*x509.Certificate, error) {
	return nil, ErrSM2NotSupported
}

// IsSM2Certificate 默认构建下报告 false（无法识别即失败，fail-closed）。
func IsSM2Certificate(der []byte) bool {
	return false
}

// VerifySM2Signature 默认构建下不可用。
func VerifySM2Signature(pub, digest, sig []byte) error {
	return ErrSM2NotSupported
}

// VerifySM2CertificateChain 默认构建下不可用。
func VerifySM2CertificateChain(leafDER []byte, intermediates, roots [][]byte, nows ...time.Time) (*x509.Certificate, error) {
	return nil, ErrSM2NotSupported
}

// VerifySM2Bundle 默认构建下不可用。
func VerifySM2Bundle(in SM2BundleInput) (*SM2BundleResult, error) {
	return nil, ErrSM2NotSupported
}
