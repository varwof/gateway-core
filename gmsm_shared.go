// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// SM2 验证核心的公共类型、OID 与稳定原因码。
//
// 本文件不依赖 tjfoc/gmsm（默认构建即可编译）：实际上层逻辑在 gmsm.go
// （//go:build gmsm）与 gmsm_stub.go（//go:build !gmsm）中按 build tag 配对实现，
// 所有非默认构建才可用的符号保证 fail-closed：无 gmsm tag 时一律返回
// ErrSM2NotSupported。

package gw

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"
)

// 国密对象标识符（GB/T 15629 / GM/T 0003 / SM 系列标准）。
var (
	// OIDSM3 是 SM3 杂凑算法 OID（GM/T 0004）。
	OIDSM3 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 401}
	// OIDSM2Curve 是 SM2 椭圆曲线（推荐参数 sm2p256v1）OID（GM/T 0003）。
	OIDSM2Curve = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}
	// OIDSM2WithSM3 是纯 SM2-with-SM3 签名算法 OID，X.509 证书与 CMS 中为国密
	// 证书链/主体签名标注（GM/T 0003.5 §A.2）。
	OIDSM2WithSM3 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 501}
)

// SM2 验证核心的稳定原因码。原因码是稳定的 snake_case 标识（与网关既有
// 拒绝原因风格一致），可原样写入审计 deny_reason 或 Admin 上报；适配层不得
// 依赖错误文案，只依赖原因码。
const (
	// SM2ReasonParseCert 证书/链 DER 解析失败（含截断、非证书内容）。
	SM2ReasonParseCert = "sm2_verify_parse_certificate"
	// SM2ReasonNotSM2Cert 证书签名算法不是 SM2-with-SM3（OID 501）。
	SM2ReasonNotSM2Cert = "sm2_verify_not_sm2_certificate"
	// SM2ReasonParsePublicKey 公钥 DER 解析失败。
	SM2ReasonParsePublicKey = "sm2_verify_parse_public_key"
	// SM2ReasonPublicKeyType 公钥不是 SM2 曲线（拒绝，不静默放行）。
	SM2ReasonPublicKeyType = "sm2_verify_unsupported_public_key"
	// SM2ReasonSignature 单签名验证失败或入参为空。
	SM2ReasonSignature = "sm2_verify_signature"
	// SM2ReasonChainBuild 链构建失败（超深/成环，防证书风暴）。
	SM2ReasonChainBuild = "sm2_verify_chain_not_built"
	// SM2ReasonChainSignature 链上某级签名验签失败。
	SM2ReasonChainSignature = "sm2_verify_chain_signature"
	// SM2ReasonChainUntrusted 链无法终止于受信根（找不到签发者/不受信）。
	SM2ReasonChainUntrusted = "sm2_verify_chain_untrusted"
	// SM2ReasonMixedChain 链中出现非国密成员（叶子/中间件非 501 签名或根非
	// SM2 密钥）。
	SM2ReasonMixedChain = "sm2_verify_mixed_chain"
	// SM2ReasonChainValidity 证书有效期校验失败（未生效/已过期）。
	SM2ReasonChainValidity = "sm2_verify_chain_validity"
	// SM2ReasonMissingAIC 要求携带 AIC 扩展但缺失。
	SM2ReasonMissingAIC = "sm2_verify_missing_aic"
	// SM2ReasonNotSupported 当前构建未启用 gmsm（stub 专用）。
	SM2ReasonNotSupported = "sm2_verify_not_supported"
)

// SM2VerifyError 是国密验证核心返回的错误，携带稳定原因码。
// 适配层（审计/上报）应读取 Code 而非解析 Error() 文案。
type SM2VerifyError struct {
	// Code 是稳定原因码（见 SM2Reason* 常量）。
	Code string
	// Detail 是供人读的详细描述。
	Detail string
}

func (e *SM2VerifyError) Error() string {
	return e.Code + ": " + e.Detail
}

// newSM2VerifyError 构造带稳定原因码的错误。
func newSM2VerifyError(code, format string, args ...any) *SM2VerifyError {
	return &SM2VerifyError{Code: code, Detail: fmt.Sprintf(format, args...)}
}

// ErrSM2NotSupported 是默认构建（无 -tags gmsm）下所有国密入口返回的哨兵错误，
// 与 core 仓库 gmsm_stub 的文案保持一致，保证 fail-closed。
var ErrSM2NotSupported = errors.New("SM2 not supported: build with -tags gmsm")

// SM2BundleInput 是 SM2 验证核心的最小公共验证入口入参，与具体传输解耦：
// 适配层（自终止 TLS 自定义验证 / 透传证书链头）只需把原始字节填入本结构并
// 调用 VerifySM2Bundle。
type SM2BundleInput struct {
	// LeafDER 是客户端叶子证书 DER（SM2 签发）。
	LeafDER []byte
	// Intermediates 是可选的中间 CA 证书 DER。
	Intermediates [][]byte
	// Roots 是受信根 CA 证书 DER 集合（链必须终止于其中之一）。
	Roots [][]byte
	// Data 是待验签数据（由叶子证书持有者密钥签名的原文）。
	// 仅当 Signature 非空时参与验证。
	Data []byte
	// Signature 是 SM2 签名（ASN.1 DER 编码 r||s），由叶子证书持有者密钥生成。
	// 空值表示本入口只做链验证与 AIC 提取，不要求主体签名。
	Signature []byte
	// RequireAIC 为 true 时，叶子证书必须携带可解析的 AIC 扩展，否则拒绝。
	RequireAIC bool
	// AuditLogger 非空时，验证失败会写一条 denied 审计记录（原因码嵌入
	// deny_reason）。nil 表示不写审计（由适配层自行处理）。
	AuditLogger *AuditLogger
	// SrcIP / MappingName / Target 透传给审计记录（可选）。
	SrcIP       string
	MappingName string
	Target      string
	// Now 是链有效期校验的基准时刻；零值表示使用实时时间（time.Now()）。
	// 供测试注入固定时刻，生产调用保持默认即可。
	Now time.Time
}

// SM2BundleResult 是验证成功后的结果。
type SM2BundleResult struct {
	// Cert 是解析后的叶子证书（stdlib *x509.Certificate，可复用 ParseAIC /
	// ExtractRoles 等既有提取逻辑）。
	Cert *x509.Certificate
	// AIC 是叶子证书携带的 AIC 扩展解析结果；证书无 AIC 扩展时为 nil。
	AIC *AIC
}
