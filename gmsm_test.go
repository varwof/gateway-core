// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

//go:build gmsm

// 国密验证核心测试（-tags gmsm）：正向 SM2 证书链 + AIC 提取、反向向量
// （篡改/错 CA/非 SM2 OID/截断）、单签名验证。
//
// SM2 证书 fixture 在测试内用 tjfoc/gmsm 实时生成（与 core 仓库
// internal/ca/gmsm.go 的 createSM2Certificate 同构：根 CA 自签、中间件/叶子
// 逐级签发，均使用纯 SM2-with-SM3 OID 501）；生成步骤见 docs/gmsm-support.md。

package gw

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tjfoc/gmsm/sm2"
	gmx509 "github.com/tjfoc/gmsm/x509"
	pki "github.com/varwof/types"
)

// ─── fixture 生成 ──────────────────────────────────────────────────

type sm2Fixture struct {
	rootDER  []byte
	interDER []byte
	leafDER  []byte

	viewDER []byte

	leafPriv *sm2.PrivateKey
	userPriv *sm2.PrivateKey
	badRoot  []byte

	leafNoAICDER []byte
	ecdsaLeafDER []byte

	aicExt   pkix.Extension
	aic      *AIC
	userSPKI []byte
}

// fixtureToSM2PublicKey 归一化 *sm2.PublicKey 表示（对齐 core toSM2PublicKey）。
func fixtureToSM2PublicKey(pub any) (*sm2.PublicKey, error) {
	switch k := pub.(type) {
	case *sm2.PublicKey:
		if k.Curve != sm2.P256Sm2() {
			return nil, fmt.Errorf("not an SM2 curve")
		}
		return k, nil
	case *ecdsa.PublicKey:
		if k.Curve != sm2.P256Sm2() {
			return nil, fmt.Errorf("not the SM2 curve")
		}
		return &sm2.PublicKey{Curve: k.Curve, X: k.X, Y: k.Y}, nil
	default:
		return nil, fmt.Errorf("unsupported fixture key type %T", pub)
	}
}

// createSM2FixtureCert 与 core 的 createSM2Certificate 同构（模板→纯 OID 501 证书）。
func createSM2FixtureCert(tmpl, parent *x509.Certificate, pub any, signer *sm2.PrivateKey) ([]byte, error) {
	sm2Pub, err := fixtureToSM2PublicKey(pub)
	if err != nil {
		return nil, err
	}
	gtmpl := &gmx509.Certificate{}
	gtmpl.FromX509Certificate(tmpl)
	gparent := &gmx509.Certificate{}
	if parent != nil {
		gparent.FromX509Certificate(parent)
	}
	return gmx509.CreateCertificate(gtmpl, gparent, sm2Pub, signer)
}

func fixtureCAKey(t *testing.T) *sm2.PrivateKey {
	t.Helper()
	k, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate sm2 key: %v", err)
	}
	return k
}

// fixtureSignDA 用主体（user）SM2 密钥对 DelegationAuthTBS 签名，签名算法
// 标注 SM2-with-SM3 —— 复用与 VerifyDelegationAuth 相同的内容构造约定：
// digest = SHA-256(DelegationAuthTBS DER)。
func fixtureSignDA(t *testing.T, userPriv *sm2.PrivateKey, userSPKI []byte, aicRef *AIC) []byte {
	t.Helper()
	tbs := DelegationAuthTBS{
		Version:                  aicRef.Version,
		AgentId:                  aicRef.AgentId,
		PrincipalUid:             aicRef.PrincipalUid,
		Reason:                   aicRef.DelegationAuthorization.Reason,
		Capabilities:             aicRef.Capabilities,
		DelegationMode:           aicRef.DelegationMode,
		AuthorizationConstraints: aicRef.AuthorizationConstraints,
		RequestedLifetime:        aicRef.DelegationAuthorization.RequestedLifetime,
		Timestamp:                aicRef.DelegationAuthorization.Timestamp,
		Nonce:                    aicRef.DelegationAuthorization.Nonce,
	}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatalf("marshal DA TBS: %v", err)
	}
	digest := sha256.Sum256(tbsDER)
	sig, err := userPriv.Sign(rand.Reader, digest[:], nil)
	if err != nil {
		t.Fatalf("sign DA with SM2: %v", err)
	}
	aicRef.DelegationAuthorization.SignatureValue = sig
	return sig
}

// newSM2Fixture 生成：
//   - SM2 根 CA（自签）→ SM2 中间 CA → SM2 叶子（含 AIC 扩展），全链 OID 501；
//   - 一个 Subject 与被验链相同、但密钥无关的第二根 CA（错 CA 向量）；
//   - 无 AIC 扩展的叶子（RequireAIC 反向向量）；
//   - 携带同一 AIC 扩展 DER 的 ECDSA 叶子（AIC 提取一致性对照）。
func newSM2Fixture(t *testing.T) *sm2Fixture {
	t.Helper()
	now := time.Now().UTC()
	userPriv := fixtureCAKey(t)
	userSPKI, err := gmx509.MarshalPKIXPublicKey(userPriv.Public())
	if err != nil {
		t.Fatal(err)
	}

	rootKey := fixtureCAKey(t)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1001),
		Subject:               pkix.Name{CommonName: "SM2 Root CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := createSM2FixtureCert(rootTmpl, rootTmpl, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatalf("self-sign SM2 root: %v", err)
	}
	rootStd, err := ParseSM2Certificate(rootDER)
	if err != nil {
		t.Fatalf("parse SM2 root: %v", err)
	}

	interKey := fixtureCAKey(t)
	interTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1002),
		Subject:               pkix.Name{CommonName: "SM2 Intermediate CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(180 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	interDER, err := createSM2FixtureCert(interTmpl, rootStd, interKey.Public(), rootKey)
	if err != nil {
		t.Fatalf("sign SM2 intermediate: %v", err)
	}
	interStd, err := ParseSM2Certificate(interDER)
	if err != nil {
		t.Fatalf("parse SM2 intermediate: %v", err)
	}

	leafKey := fixtureCAKey(t)
	leafNoAICDER, err := createSM2FixtureCert(&x509.Certificate{
		SerialNumber:          big.NewInt(1003),
		Subject:               pkix.Name{CommonName: "sm2-agent.example.com"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}, interStd, leafKey.Public(), interKey)
	if err != nil {
		t.Fatalf("sign SM2 leaf without AIC: %v", err)
	}

	// AIC 扩展（DA 由主体 SM2 密钥签名，签名算法为 SM2-with-SM3）。
	aicRef := &AIC{
		Version: 1,
		AgentId: "sm2-agent-001",
		PrincipalUid: PrincipalUid{
			Version:    1,
			Realm:      "varwof",
			Identifier: "principal-sm2-001",
			HashAlgo:   AlgorithmIdentifier{Algorithm: OIDSHA256},
		},
		Capabilities: []Capability{
			{SchemeId: "varwof-gateway-v1", CapabilityId: "connect:tls"},
		},
		DelegationMode: DelegationAuthorized,
		DelegationAuthorization: DelegationAuthorization{
			Reason:             Reason{ReasonCode: "SM2_FIXTURE", Description: "sm2 fixture delegation"},
			RequestedLifetime:  3600,
			Timestamp:          now,
			Nonce:              bytes.Repeat([]byte{0xAA}, 32),
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSM2WithSM3},
		},
	}
	fixtureSignDA(t, userPriv, userSPKI, aicRef)
	aicDER, err := asn1.Marshal(*aicRef)
	if err != nil {
		t.Fatalf("marshal AIC: %v", err)
	}
	aicExt := pkix.Extension{Id: oidAIC, Critical: false, Value: aicDER}

	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1003),
		Subject:               pkix.Name{CommonName: "sm2-agent.example.com"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{aicExt},
	}
	leafDER, err := createSM2FixtureCert(leafTmpl, interStd, leafKey.Public(), interKey)
	if err != nil {
		t.Fatalf("sign SM2 leaf with AIC: %v", err)
	}

	// 错 CA：同名 Subject、不同密钥的"无关"根——用于 subject 匹配但验签失败向量。
	badRootKey := fixtureCAKey(t)
	badRootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2001),
		Subject:               pkix.Name{CommonName: "SM2 Root CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	badRoot, err := createSM2FixtureCert(badRootTmpl, badRootTmpl, badRootKey.Public(), badRootKey)
	if err != nil {
		t.Fatalf("self-sign unrelated root: %v", err)
	}

	// ECDSA 叶子（同一 AIC 扩展 DER）：stdlib 可解析的标准证书路径对照。
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecRootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecRootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(3001),
		Subject:               pkix.Name{CommonName: "ECDSA Root CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	ecRootDER, err := x509.CreateCertificate(rand.Reader, ecRootTmpl, ecRootTmpl, &ecRootKey.PublicKey, ecRootKey)
	if err != nil {
		t.Fatal(err)
	}
	ecRoot, err := x509.ParseCertificate(ecRootDER)
	if err != nil {
		t.Fatal(err)
	}
	ecLeafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(3002),
		Subject:               pkix.Name{CommonName: "sm2-agent.example.com"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{aicExt},
	}
	ecLeafDER, err := x509.CreateCertificate(rand.Reader, ecLeafTmpl, ecRoot, &ecKey.PublicKey, ecRootKey)
	if err != nil {
		t.Fatal(err)
	}

	return &sm2Fixture{
		rootDER:      rootDER,
		interDER:     interDER,
		leafDER:      leafDER,
		viewDER:      leafDER,
		leafPriv:     leafKey,
		userPriv:     userPriv,
		badRoot:      badRoot,
		leafNoAICDER: leafNoAICDER,
		ecdsaLeafDER: ecLeafDER,
		aicExt:       aicExt,
		aic:          aicRef,
		userSPKI:     userSPKI,
	}
}

// untrustedRoots 返回一个不含真实根的受信集合（不同 Subject 的无关根）。
func (f *sm2Fixture) unrelatedRoots(t *testing.T) [][]byte {
	t.Helper()
	now := time.Now().UTC()
	k := fixtureCAKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(4001),
		Subject:               pkix.Name{CommonName: "Unrelated SM2 Root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := createSM2FixtureCert(tmpl, tmpl, k.Public(), k)
	if err != nil {
		t.Fatalf("self-sign unrelated root: %v", err)
	}
	return [][]byte{der}
}

// tamperDER 翻转 DER 末尾第 12 字节（位于签名 BIT STRING 内的 r/s 字节）。
func tamperDER(der []byte) []byte {
	out := append([]byte(nil), der...)
	out[len(out)-12] ^= 0x01
	return out
}

// ─── 正向 ─────────────────────────────────────────────────────────

func TestVerifySM2CertificateChain_OK(t *testing.T) {
	f := newSM2Fixture(t)
	intermediates := [][]byte{f.interDER}
	roots := [][]byte{f.rootDER}

	cert, err := VerifySM2CertificateChain(f.leafDER, intermediates, roots)
	if err != nil {
		t.Fatalf("verify SM2 chain: %v", err)
	}
	if cert.Subject.CommonName != "sm2-agent.example.com" {
		t.Fatalf("unexpected leaf CN: %s", cert.Subject.CommonName)
	}
	if cert.SerialNumber.Int64() != 1003 {
		t.Fatalf("unexpected serial: %v", cert.SerialNumber)
	}
	if !sm2CurveKey(cert.PublicKey) {
		t.Fatalf("leaf public key is not on the SM2 curve: %T", cert.PublicKey)
	}
}

func TestVerifySM2CertificateChain_ParentIsRoot(t *testing.T) {
	// 直接 根→叶子（无中间件）链也必须通过。
	now := time.Now().UTC()
	rootKey := fixtureCAKey(t)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "SM2 Root-CA Direct"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := createSM2FixtureCert(rootTmpl, rootTmpl, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootStd, err := ParseSM2Certificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey := fixtureCAKey(t)
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "sm2-leaf-direct"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	leafDER, err := createSM2FixtureCert(leafTmpl, rootStd, leafKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySM2CertificateChain(leafDER, nil, [][]byte{rootDER}); err != nil {
		t.Fatalf("direct leaf->root chain: %v", err)
	}
}

func TestVerifySM2Bundle_OK_AndAICParity(t *testing.T) {
	f := newSM2Fixture(t)

	// 主体签名：叶子密钥对 Data 直接签名（tjfoc sm2 Sign 对 msg 计算 SM3(ZA||msg)）。
	msg := []byte("sm2 signed payload for gateway admission")
	sig, err := f.leafPriv.Sign(rand.Reader, msg, nil)
	if err != nil {
		t.Fatal(err)
	}

	res, err := VerifySM2Bundle(SM2BundleInput{
		LeafDER:       f.leafDER,
		Intermediates: [][]byte{f.interDER},
		Roots:         [][]byte{f.rootDER},
		Data:          msg,
		Signature:     sig,
		RequireAIC:    true,
	})
	if err != nil {
		t.Fatalf("verify SM2 bundle: %v", err)
	}
	if res.Cert == nil || res.AIC == nil {
		t.Fatal("expected cert and AIC in result")
	}
	if res.AIC.AgentId != "sm2-agent-001" {
		t.Fatalf("AIC AgentId mismatch: %s", res.AIC.AgentId)
	}

	// AIC 一致性：同一 AIC 扩展 DER 分别经国密路径与标准 ECDSA 证书路径提取，
	// 结果必须完全一致（证明提取入口复用，未复制代码、无国密特有分支差异）。
	sm2Cert, err := ParseSM2Certificate(f.leafDER)
	if err != nil {
		t.Fatal(err)
	}
	sm2AIC, err := ParseAIC(sm2Cert)
	if err != nil {
		t.Fatalf("ParseAIC on SM2 parse: %v", err)
	}
	stdCert, err := x509.ParseCertificate(f.ecdsaLeafDER)
	if err != nil {
		t.Fatalf("stdlib parse of ECDSA leaf: %v", err)
	}
	stdAIC, err := ParseAIC(stdCert)
	if err != nil {
		t.Fatalf("ParseAIC on stdlib parse: %v", err)
	}
	if !reflect.DeepEqual(sm2AIC, stdAIC) {
		t.Fatalf("AIC parity mismatch:\nSM2=%+v\nECDSA=%+v", sm2AIC, stdAIC)
	}

	// 国密路径的 AIC 字段断言（与原构造一致）。
	if sm2AIC.PrincipalUid.Identifier != "principal-sm2-001" {
		t.Fatalf("PrincipalUid.Identifier mismatch: %s", sm2AIC.PrincipalUid.Identifier)
	}
	if len(sm2AIC.Capabilities) != 1 || sm2AIC.Capabilities[0].CapabilityId != "connect:tls" {
		t.Fatalf("capabilities mismatch: %+v", sm2AIC.Capabilities)
	}
	if !sm2AIC.DelegationAuthorization.SignatureAlgorithm.Algorithm.Equal(OIDSM2WithSM3) {
		t.Fatalf("DA sig algo not SM2-with-SM3: %v", sm2AIC.DelegationAuthorization.SignatureAlgorithm.Algorithm)
	}
	if len(sm2AIC.DelegationAuthorization.SignatureValue) == 0 {
		t.Fatal("expected non-empty DA signature")
	}

	// SM2 证书必须无法被 stdlib 解析（这正是 ParseSM2Certificate 为何必须走 gmsm）。
	if _, err := x509.ParseCertificate(f.leafDER); err == nil {
		t.Fatal("stdlib must fail to parse SM2 certificate (SM2 SPKI unsupported)")
	}
	if !IsSM2Certificate(f.leafDER) {
		t.Fatal("IsSM2Certificate should be true for SM2 leaf")
	}
	if IsSM2Certificate(f.ecdsaLeafDER) {
		t.Fatal("IsSM2Certificate should be false for ECDSA leaf")
	}
}

func TestVerifySM2CertificateChain_MultipleRootsIgnored(t *testing.T) {
	f := newSM2Fixture(t)
	unrelated := f.unrelatedRoots(t)
	cert, err := VerifySM2CertificateChain(f.leafDER, [][]byte{f.interDER}, append(unrelated, f.rootDER))
	if err != nil {
		t.Fatalf("chain with extra unrelated root must pass: %v", err)
	}
	if cert == nil {
		t.Fatal("expected cert")
	}
}

// ─── 反向向量 ─────────────────────────────────────────────────────

func TestVerifySM2CertificateChain_TamperedSignature(t *testing.T) {
	f := newSM2Fixture(t)
	tampered := tamperDER(f.leafDER)
	_, err := VerifySM2CertificateChain(tampered, [][]byte{f.interDER}, [][]byte{f.rootDER})
	if err == nil {
		t.Fatal("expected chain signature verification failure")
	}
	if e, ok := err.(*SM2VerifyError); ok && e.Code != SM2ReasonChainSignature {
		t.Fatalf("expected chain_signature reason, got %s", e.Code)
	}
}

func TestVerifySM2CertificateChain_UnrelatedRoot(t *testing.T) {
	f := newSM2Fixture(t)
	_, err := VerifySM2CertificateChain(f.leafDER, [][]byte{f.interDER}, f.unrelatedRoots(t))
	if err == nil {
		t.Fatal("expected chain rejection for unrelated root")
	}
	if e, ok := err.(*SM2VerifyError); ok && e.Code != SM2ReasonChainUntrusted {
		t.Fatalf("expected chain_untrusted reason, got %s", e.Code)
	}
}

func TestVerifySM2CertificateChain_WrongIssuerSameSubject(t *testing.T) {
	f := newSM2Fixture(t)
	// badRoot 与真实根同名（"SM2 Root CA"），但密钥无关：subject 匹配、验签必败。
	_, err := VerifySM2CertificateChain(f.leafDER, [][]byte{f.interDER}, [][]byte{f.badRoot})
	if err == nil {
		t.Fatal("expected chain rejection for wrong issuer (same subject)")
	}
	if e, ok := err.(*SM2VerifyError); ok {
		if e.Code != SM2ReasonChainSignature && e.Code != SM2ReasonChainUntrusted {
			t.Fatalf("expected chain_signature/chain_untrusted, got %s", e.Code)
		}
	}
}

func TestVerifySM2CertificateChain_NonSM2Chain(t *testing.T) {
	f := newSM2Fixture(t)
	// 用 ECDSA 叶子做叶子：签名算法非 OID 501 → 拒绝。
	_, err := VerifySM2CertificateChain(f.ecdsaLeafDER, nil, [][]byte{f.rootDER})
	if err == nil {
		t.Fatal("expected rejection for non-SM2 certificate")
	}
	if e, ok := err.(*SM2VerifyError); ok && e.Code != SM2ReasonNotSM2Cert {
		t.Fatalf("expected not_sm2_certificate reason, got %s", e.Code)
	}
}

func TestVerifySM2CertificateChain_TruncatedDER(t *testing.T) {
	f := newSM2Fixture(t)
	_, err := VerifySM2CertificateChain(f.leafDER[:len(f.leafDER)/2], [][]byte{f.interDER}, [][]byte{f.rootDER})
	if err == nil {
		t.Fatal("expected rejection for truncated DER")
	}
	if e, ok := err.(*SM2VerifyError); ok && e.Code != SM2ReasonParseCert {
		t.Fatalf("expected parse_certificate reason, got %s", e.Code)
	}
}

func TestVerifySM2CertificateChain_EmptyLeaf(t *testing.T) {
	_, err := VerifySM2CertificateChain(nil, nil, [][]byte{})
	if err == nil {
		t.Fatal("expected rejection for empty leaf DER")
	}
}

func TestVerifySM2Bundle_RequireAIC_Missing(t *testing.T) {
	f := newSM2Fixture(t)
	_, err := VerifySM2Bundle(SM2BundleInput{
		LeafDER:       f.leafNoAICDER,
		Intermediates: [][]byte{f.interDER},
		Roots:         [][]byte{f.rootDER},
		RequireAIC:    true,
	})
	if err == nil {
		t.Fatal("expected rejection when AIC required but missing")
	}
	if e, ok := err.(*SM2VerifyError); ok && e.Code != SM2ReasonMissingAIC {
		t.Fatalf("expected missing_aic reason, got %s", e.Code)
	}
}

func TestVerifySM2Bundle_RequireAIC_Satisfied(t *testing.T) {
	f := newSM2Fixture(t)
	res, err := VerifySM2Bundle(SM2BundleInput{
		LeafDER:       f.leafDER,
		Intermediates: [][]byte{f.interDER},
		Roots:         [][]byte{f.rootDER},
		RequireAIC:    true,
	})
	if err != nil {
		t.Fatalf("chain+AIC-only bundle: %v", err)
	}
	if res.AIC == nil || res.AIC.AgentId != "sm2-agent-001" {
		t.Fatal("AIC not extracted")
	}
}

func TestVerifySM2Bundle_TamperedSignature(t *testing.T) {
	f := newSM2Fixture(t)
	msg := []byte("payload")
	sig, err := f.leafPriv.Sign(rand.Reader, msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	sig[len(sig)-12] ^= 0x01
	_, err = VerifySM2Bundle(SM2BundleInput{
		LeafDER:       f.leafDER,
		Intermediates: [][]byte{f.interDER},
		Roots:         [][]byte{f.rootDER},
		Data:          msg,
		Signature:     sig,
		RequireAIC:    true,
	})
	if err == nil {
		t.Fatal("expected signature verification failure")
	}
	if e, ok := err.(*SM2VerifyError); ok && e.Code != SM2ReasonSignature {
		t.Fatalf("expected signature reason, got %s", e.Code)
	}
}

func TestVerifySM2Bundle_SignatureButNoData(t *testing.T) {
	f := newSM2Fixture(t)
	sig, _ := f.leafPriv.Sign(rand.Reader, []byte("x"), nil)
	_, err := VerifySM2Bundle(SM2BundleInput{
		LeafDER:       f.leafDER,
		Intermediates: [][]byte{f.interDER},
		Roots:         [][]byte{f.rootDER},
		Signature:     sig,
		RequireAIC:    true,
	})
	if err == nil {
		t.Fatal("expected failure when signature provided without data")
	}
}

// ─── 单签名验证 ───────────────────────────────────────────────────

func TestVerifySM2Signature_OK(t *testing.T) {
	f := newSM2Fixture(t)
	msg := []byte("sm2 single signature message")
	sig, err := f.leafPriv.Sign(rand.Reader, msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	// 标准 PKIX SPKI（即证书 RawSubjectPublicKeyInfo 形态）。
	pubDER, err := gmx509.MarshalPKIXPublicKey(f.leafPriv.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySM2Signature(pubDER, msg, sig); err != nil {
		t.Fatalf("verify SM2 signature: %v", err)
	}
}

func TestVerifySM2Signature_Tampered(t *testing.T) {
	f := newSM2Fixture(t)
	msg := []byte("sm2 single signature message")
	sig, err := f.leafPriv.Sign(rand.Reader, msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	sig[len(sig)-8] ^= 0x02
	pubDER, _ := gmx509.MarshalPKIXPublicKey(f.leafPriv.Public())
	err = VerifySM2Signature(pubDER, msg, sig)
	if err == nil {
		t.Fatal("expected signature verification failure after tampering")
	}
	if e, ok := err.(*SM2VerifyError); ok && e.Code != SM2ReasonSignature {
		t.Fatalf("expected signature reason, got %s", e.Code)
	}
}

func TestVerifySM2Signature_NotSM2Key(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := gmx509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	err = VerifySM2Signature(pubDER, []byte("data"), []byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected rejection of non-SM2 public key")
	}
	if e, ok := err.(*SM2VerifyError); ok && e.Code != SM2ReasonPublicKeyType {
		t.Fatalf("expected unsupported_public_key reason, got %s", e.Code)
	}
}

func TestVerifySM2Signature_EmptyInputs(t *testing.T) {
	if err := VerifySM2Signature(nil, nil, nil); err == nil {
		t.Fatal("expected failure for empty inputs")
	}
}

// ─── SM2VerifyError 原因码可审计性 ────────────────────────────────

func TestSM2VerifyError_CodeStyle(t *testing.T) {
	codes := []string{
		SM2ReasonParseCert, SM2ReasonNotSM2Cert, SM2ReasonParsePublicKey,
		SM2ReasonPublicKeyType, SM2ReasonSignature, SM2ReasonChainBuild,
		SM2ReasonChainSignature, SM2ReasonChainUntrusted, SM2ReasonMixedChain,
		SM2ReasonChainValidity, SM2ReasonMissingAIC, SM2ReasonNotSupported,
	}
	for _, c := range codes {
		e := newSM2VerifyError(c, "test %d", 1)
		if e.Code != c {
			t.Fatalf("code mismatch: %s", e.Code)
		}
		if !strings.HasPrefix(e.Error(), c+": ") {
			t.Fatalf("error must start with stable code: %q", e.Error())
		}
	}
	if ErrSM2NotSupported.Error() != "SM2 not supported: build with -tags gmsm" {
		t.Fatal("unexpected ErrSM2NotSupported text")
	}
}

// 复用包内既有类型导入，避免未使用告警。
var _ = pki.OIDSHA256
