// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

//go:build gmsm

// 国密（SM2/SM3）验证核心 —— gmsm 构建实现。
//
// 与 gmsm_stub.go（//go:build !gmsm）配对：默认构建不 import tjfoc/gmsm，
// 所有国密入口 fail-closed。实现模式对齐 core 仓库 internal/ca/gmsm.go。
//
// 范围：证书链验签、单签名验证、SM2 证书解析（供既有 AIC/身份提取复用）。
// 明确不做：TLS 层国密、SM4、JWT SM2 alg、审计摘要 SM3 化。

package gw

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/tjfoc/gmsm/sm2"
	gmx509 "github.com/tjfoc/gmsm/x509"
)

// ParseSM2Certificate 用 gmsm/x509 解析 SM2 签发的证书 DER，再转换为 stdlib
// *x509.Certificate 供既有提取逻辑复用（stdlib 无法解析 SM2 SPKI：SM2 曲线
// OID 1.2.156.10197.1.301 不在 stdlib x509 已知曲线内）。
func ParseSM2Certificate(der []byte) (*x509.Certificate, error) {
	gcert, err := gmx509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return gcert.ToX509Certificate(), nil
}

// parseSM2GCert 解析 DER 并返回 gmsm 层证书（链验签需要 gmsm 层签名算法
// 与密钥表示）。
func parseSM2GCert(der []byte) (*gmx509.Certificate, error) {
	if len(der) == 0 {
		return nil, fmt.Errorf("empty certificate DER")
	}
	return gmx509.ParseCertificate(der)
}

// IsSM2Certificate 报告 DER 是否为以纯 SM2-with-SM3（OID 1.2.156.10197.1.501）
// 签名的证书。解析失败返回 false（fail-closed）。
func IsSM2Certificate(der []byte) bool {
	gcert, err := parseSM2GCert(der)
	if err != nil {
		return false
	}
	return gcert.SignatureAlgorithm == gmx509.SM2WithSM3
}

// sm2CurveKey 判断公钥是否位于 SM2 推荐曲线（P256Sm2）。gmsm/x509 解析
// SM2 SPKI 返回 *ecdsa.PublicKey{P256Sm2}，*sm2.PublicKey 也接受。
func sm2CurveKey(pub any) bool {
	switch k := pub.(type) {
	case *sm2.PublicKey:
		return k.Curve == sm2.P256Sm2()
	case *ecdsa.PublicKey:
		return k.Curve == sm2.P256Sm2()
	default:
		return false
	}
}

// toSM2PublicKey 将 SM2 曲线公钥转换为 *sm2.PublicKey（不同表示共享
// X/Y 坐标）。
func toSM2PublicKey(pub any) *sm2.PublicKey {
	switch k := pub.(type) {
	case *sm2.PublicKey:
		return k
	case *ecdsa.PublicKey:
		return &sm2.PublicKey{Curve: k.Curve, X: k.X, Y: k.Y}
	default:
		return nil
	}
}

// parseSM2PublicKey 解析 SM2 公钥 DER，兼容两种 SPKI 编码：
//   - 标准 PKIX：算法 id-ecPublicKey(1.2.840.10045.2.1) + SM2 曲线 OID
//     （gmsm/x509 CreateCertificate 产物，本系统证书 RawSubjectPublicKeyInfo 形态）；
//   - gmsm 原生：算法直接为 SM2 OID(1.2.156.10197.1.301)（sm2.MarshalSm2PublicKey
//     产物，外部 gmsm 工具常见）。
func parseSM2PublicKey(pub []byte) (any, error) {
	k, err := gmx509.ParsePKIXPublicKey(pub)
	if err == nil {
		if sm2CurveKey(k) {
			return k, nil
		}
		return k, newSM2VerifyError(SM2ReasonPublicKeyType, "public key is not on the SM2 curve")
	}
	if k2, err2 := gmx509.ParseSm2PublicKey(pub); err2 == nil {
		return k2, nil
	} else {
		return nil, newSM2VerifyError(SM2ReasonParsePublicKey, "parse public key: %v", err)
	}
}

// VerifySM2Signature 验证单个 SM2 签名（OID 501 语义）。
//
//   - pub：SM2 公钥 DER（标准 PKIX SPKI 或 gmsm 原生 SPKI，见 parseSM2PublicKey）；
//   - digest：被签名内容字节（即签名方 sm2 密钥 Sign(random, msg, nil) 收到的
//     msg——按 SM2 标准，tjfoc/gmsm 内部计算 SM3(ZA||digest) 后再验签；调用方
//     必须原样回传签名方所签内容，不得再套一次杂凑）；
//   - sig：ASN.1 DER 编码的 (r,s) 签名（tjfoc/gmsm 产物格式）。
//
// 任何一步失败返回带稳定原因码的错误（fail-closed，不静默放行）。
func VerifySM2Signature(pub, digest, sig []byte) error {
	if len(pub) == 0 || len(digest) == 0 || len(sig) == 0 {
		return newSM2VerifyError(SM2ReasonSignature, "empty public key, signed data or signature")
	}
	raw, err := parseSM2PublicKey(pub)
	if err != nil {
		return err
	}
	key := toSM2PublicKey(raw)
	if key == nil {
		return newSM2VerifyError(SM2ReasonPublicKeyType, "unexpected public key representation %T", raw)
	}
	if !key.Verify(digest, sig) {
		return newSM2VerifyError(SM2ReasonSignature, "SM2 signature verification failed")
	}
	return nil
}

// requireSM2Signed 要求证书以 SM2-with-SM3（OID 501）签名，否则拒绝。
func requireSM2Signed(c *gmx509.Certificate) error {
	if c.SignatureAlgorithm != gmx509.SM2WithSM3 {
		return newSM2VerifyError(SM2ReasonNotSM2Cert,
			"certificate %q signed with %v, want SM2-with-SM3 (OID %v)",
			c.Subject.String(), c.SignatureAlgorithm, OIDSM2WithSM3)
	}
	return nil
}

// checkSM2CertTime 校验证书有效期（含此刻边界）。
func checkSM2CertTime(c *gmx509.Certificate, now time.Time) error {
	if now.Before(c.NotBefore) {
		return fmt.Errorf("certificate %q not yet valid (notBefore=%v)", c.Subject.String(), c.NotBefore.UTC())
	}
	if now.After(c.NotAfter) {
		return fmt.Errorf("certificate %q expired (notAfter=%v)", c.Subject.String(), c.NotAfter.UTC())
	}
	return nil
}

// findVerifiedIssuer 在当前证书的签发者中查找并验签：先中间件后根，按
// RawIssuer==RawSubject 匹配，逐个尝试 CheckSignatureFrom，首个通过者胜出
// （兼容交叉签发/同 Subject 异密钥场景）。返回 (签发者, nil)；匹配不到返回
// chain_untrusted；均验签失败返回 chain_signature。
func findVerifiedIssuer(curr *gmx509.Certificate, intermediates, roots []*gmx509.Certificate) (*gmx509.Certificate, error) {
	candidates := make([]*gmx509.Certificate, 0, len(intermediates)+len(roots))
	candidates = append(candidates, intermediates...)
	candidates = append(candidates, roots...)

	matchedSubject := 0
	for _, cand := range candidates {
		if !bytes.Equal(curr.RawIssuer, cand.RawSubject) {
			continue
		}
		matchedSubject++
		if err := curr.CheckSignatureFrom(cand); err == nil {
			return cand, nil
		}
	}
	if matchedSubject == 0 {
		return nil, newSM2VerifyError(SM2ReasonChainUntrusted,
			"no issuer found for %q (issuer=%q): chain does not terminate at a provided root",
			curr.Subject.String(), curr.Issuer.String())
	}
	return nil, newSM2VerifyError(SM2ReasonChainSignature,
		"issuer candidate(s) for %q all failed signature verification", curr.Subject.String())
}

// isTrustAnchor 报告证书 DER 是否与 roots 中某一受信根完全一致（字节匹配，
// 即"链已于此处终止"）。
func isTrustAnchor(c *gmx509.Certificate, roots []*gmx509.Certificate) bool {
	for _, r := range roots {
		if bytes.Equal(c.Raw, r.Raw) {
			return true
		}
	}
	return false
}

// VerifySM2CertificateChain 验证一条纯 SM2 证书链（根 CA 自签/叶子签发均使用
// OID 501 签名），逐级验签（SM3 摘要 + SM2 签名）：
//
//  1. 叶子与所有中间证书必须以 SM2-with-SM3 签名；根必须是 SM2 曲线密钥
//     （混入非国密成员 → mixed_chain，fail-closed）；
//  2. 链必须逐级终止于 roots 中的受信根，任一级签名验证失败或找不到签发者
//     即拒绝（chain_signature / chain_untrusted）；
//  3. 叶子与中间证书有效期校验（chain_validity）；环/超深拒绝
//     （chain_not_built，防证书风暴）。
//
// 成功返回解析后的叶子证书（stdlib *x509.Certificate，可复用 ParseAIC /
// ExtractRoles 等既有提取逻辑）。
func VerifySM2CertificateChain(leafDER []byte, intermediates, roots [][]byte, nows ...time.Time) (*x509.Certificate, error) {
	now := time.Now()
	if len(nows) > 0 {
		now = nows[0]
	}
	leaf, err := parseSM2GCert(leafDER)
	if err != nil {
		return nil, newSM2VerifyError(SM2ReasonParseCert, "parse leaf certificate: %v", err)
	}
	interm := make([]*gmx509.Certificate, 0, len(intermediates))
	for _, d := range intermediates {
		c, err := parseSM2GCert(d)
		if err != nil {
			return nil, newSM2VerifyError(SM2ReasonParseCert, "parse intermediate certificate: %v", err)
		}
		interm = append(interm, c)
	}
	rootCerts := make([]*gmx509.Certificate, 0, len(roots))
	for _, d := range roots {
		c, err := parseSM2GCert(d)
		if err != nil {
			return nil, newSM2VerifyError(SM2ReasonParseCert, "parse root certificate: %v", err)
		}
		rootCerts = append(rootCerts, c)
	}

	if err := requireSM2Signed(leaf); err != nil {
		return nil, err
	}
	for _, c := range interm {
		if err := requireSM2Signed(c); err != nil {
			return nil, newSM2VerifyError(SM2ReasonMixedChain, "%v", err.Error())
		}
	}

	if err := checkSM2CertTime(leaf, now); err != nil {
		return nil, newSM2VerifyError(SM2ReasonChainValidity, "%v", err)
	}
	if isTrustAnchor(leaf, rootCerts) {
		// 叶子本身就是受信根（自签信任锚）——不做自签验签（信任由调用方
		// 提供跟集合决定）。
		if !sm2CurveKey(leaf.PublicKey) {
			return nil, newSM2VerifyError(SM2ReasonMixedChain,
				"trust anchor %q is not an SM2 key", leaf.Subject.String())
		}
		return leaf.ToX509Certificate(), nil
	}

	visited := make(map[string]bool, len(interm)+1)
	curr := leaf
	for {
		if visited[string(curr.Raw)] {
			return nil, newSM2VerifyError(SM2ReasonChainBuild,
				"certificate chain contains a cycle at %q", curr.Subject.String())
		}
		visited[string(curr.Raw)] = true
		if len(visited) > len(interm)+1 {
			return nil, newSM2VerifyError(SM2ReasonChainBuild,
				"certificate chain exceeds maximum depth %d (anti-certificate-bomb)", len(interm)+1)
		}

		parent, err := findVerifiedIssuer(curr, interm, rootCerts)
		if err != nil {
			return nil, err
		}
		if isTrustAnchor(parent, rootCerts) {
			if !sm2CurveKey(parent.PublicKey) {
				return nil, newSM2VerifyError(SM2ReasonMixedChain,
					"trust anchor %q is not an SM2 key", parent.Subject.String())
			}
			break
		}
		// 中间证书成为链上节点：校验其有效期（根为信任锚不校验时间）。
		if err := checkSM2CertTime(parent, now); err != nil {
			return nil, newSM2VerifyError(SM2ReasonChainValidity, "%v", err)
		}
		curr = parent
	}

	return leaf.ToX509Certificate(), nil
}

// writeSM2AuditDenied 在输入配置了审计记录器时，写一条 denied 审计记录，
// 原因码原样写入 deny_reason（审计适配与网关既有拒绝路径一致）。
func writeSM2AuditDenied(in SM2BundleInput, err error) {
	if in.AuditLogger == nil {
		return
	}
	entry := NewAuditEntryDenied(in.SrcIP, in.MappingName, in.Target, "sm2_verify: "+err.Error(), nil)
	entry.Action = string(ActionDenied)
	in.AuditLogger.Log(entry)
}

// VerifySM2Bundle 是 SM2 验证核心的最小公共入口（与具体传输解耦）。接收
// "原始证书 DER/链 + 待验证签名 + 数据"，依次执行：
//
//  1. 链验证（VerifySM2CertificateChain）；
//  2. AIC 扩展提取（复用既有 ParseAIC，不复制提取逻辑）；RequireAIC 时缺失即拒；
//  3. 主体签名验证（Signature 非空时，用叶子证书 SPKI 验证对 Data 的 SM2
//     签名）。
//
// 任一步失败返回带稳定原因码的错误（fail-closed，"未知即放行"不存在）。返回
// 结果携带解析后的叶子证书与 AIC，供适配层继续走既有接入审计/授权逻辑。
func VerifySM2Bundle(in SM2BundleInput) (*SM2BundleResult, error) {
	var nows []time.Time
	if !in.Now.IsZero() {
		nows = append(nows, in.Now)
	}
	cert, err := VerifySM2CertificateChain(in.LeafDER, in.Intermediates, in.Roots, nows...)
	if err != nil {
		writeSM2AuditDenied(in, err)
		return nil, err
	}

	aic, err := ParseAIC(cert)
	if err != nil {
		e := newSM2VerifyError(SM2ReasonParseCert, "AIC extension parse: %v", err)
		writeSM2AuditDenied(in, e)
		return nil, e
	}
	if in.RequireAIC && aic == nil {
		e := newSM2VerifyError(SM2ReasonMissingAIC, "leaf certificate carries no AIC extension")
		writeSM2AuditDenied(in, e)
		return nil, e
	}

	if len(in.Signature) > 0 {
		if len(in.Data) == 0 {
			e := newSM2VerifyError(SM2ReasonSignature, "signature provided but data empty")
			writeSM2AuditDenied(in, e)
			return nil, e
		}
		if err := VerifySM2Signature(cert.RawSubjectPublicKeyInfo, in.Data, in.Signature); err != nil {
			writeSM2AuditDenied(in, err)
			return nil, err
		}
	}

	return &SM2BundleResult{Cert: cert, AIC: aic}, nil
}
