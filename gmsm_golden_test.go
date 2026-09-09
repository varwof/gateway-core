// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

//go:build gmsm

// core 签发金标向量（-tags gmsm）的字节级闭环验证。
//
// testdata/gmsm/*.der 由 core 仓库生产签发路径签出（ca.Sign + BuildAIC + 纯
// SM2-with-SM3 OID 1.2.156.10197.1.501）：root(自签) → intermediate → leaf(含 AIC
// 扩展)。同一组字节同时存在于 core/internal/ca/testdata/gmsm/（core 侧一致性
// 验证见 core 仓库 gmsm_golden_test.go），本测试证明 gateway 侧对完全相同字节的
// 链/AIC/单签名逐项验证通过 —— 跨仓库互操作不再是"生成逻辑同构"，而是字节级证据。
//
// 手工再生成：core 仓库曾用工具见 docs/gmsm-support.md（生成后即删除，不入库）。

package gw

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	gmx509 "github.com/tjfoc/gmsm/x509"
)

// goldenExpected 对应 testdata/gmsm/expected.json（由生成器写出的期望值清单）。
type goldenExpected struct {
	LeafCN           string `json:"leafCN"`
	LeafSerialHex    string `json:"leafSerialHex"`
	IssuerCN         string `json:"issuerCN"`
	RootCN           string `json:"rootCN"`
	SignatureAlgOID  string `json:"signatureAlgOID"`
	AgentID          string `json:"agentId"`
	PrincipalRealm   string `json:"principalRealm"`
	PrincipalID      string `json:"principalId"`
	CapabilityScheme string `json:"capabilityScheme"`
	CapabilityAction string `json:"capabilityAction"`
	DAReasonCode     string `json:"daReasonCode"`
	Data             string `json:"data"`
}

func loadGolden(t *testing.T) (goldenExpected, []byte, []byte, []byte, []byte, []byte, []byte) {
	t.Helper()
	dir := filepath.Join("testdata", "gmsm")
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read testdata/gmsm/%s: %v", name, err)
		}
		return b
	}
	var exp goldenExpected
	if err := json.Unmarshal(read("expected.json"), &exp); err != nil {
		t.Fatalf("parse expected.json: %v", err)
	}
	return exp, read("root.der"), read("intermediate.der"), read("leaf.der"),
		read("leaf.spki.der"), read("leaf.data.bin"), read("leaf.sig.bin")
}

// goldenNow 是金标向量的签发时刻（certificate validity window 中央）
// 2026-09-07）。链验证的实时时钟早于这份向量的 notAfter，注入这一时刻避免
// 因测试向量过期而误报 chain_validity（向量期为一天性，非长期有效）。
func goldenNow() time.Time {
	return time.Date(2026, 9, 7, 7, 0, 0, 0, time.UTC)
}

// TestSM2GoldenFromCore_Chain 验证 core 签出的 SM2 链（字节级）在 gateway 可验签。
func TestSM2GoldenFromCore_Chain(t *testing.T) {
	exp, rootDER, interDER, leafDER, _, _, _ := loadGolden(t)

	cert, err := VerifySM2CertificateChain(leafDER, [][]byte{interDER}, [][]byte{rootDER}, goldenNow())
	if err != nil {
		t.Fatalf("verify core-signed SM2 golden chain: %v", err)
	}
	if cert.Subject.CommonName != exp.LeafCN {
		t.Fatalf("leaf CN mismatch: %q != %q", cert.Subject.CommonName, exp.LeafCN)
	}
	if cert.Issuer.CommonName != exp.IssuerCN {
		t.Fatalf("leaf issuer CN mismatch: %q != %q", cert.Issuer.CommonName, exp.IssuerCN)
	}
	if fmt.Sprintf("%040X", cert.SerialNumber) != exp.LeafSerialHex {
		t.Fatalf("leaf serial mismatch: %040X != %s", cert.SerialNumber, exp.LeafSerialHex)
	}
	if !sm2CurveKey(cert.PublicKey) {
		t.Fatalf("golden leaf public key is not on the SM2 curve: %T", cert.PublicKey)
	}
	// 根/中间亦须为 SM2 密钥（roots 豁免签名 OID 检查，但密钥必须国密）。
	for name, der := range map[string][]byte{"root": rootDER, "intermediate": interDER} {
		gc, err := gmx509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("gmsm parse %s: %v", name, err)
		}
		if gc.SignatureAlgorithm != gmx509.SM2WithSM3 {
			t.Fatalf("%s signature algorithm: got %v, want SM2WithSM3", name, gc.SignatureAlgorithm)
		}
	}
	// 标准库必须无法解析 SM2 证书（这正是 ParseSM2Certificate 存在的理由）。
	if _, err := x509.ParseCertificate(leafDER); err == nil {
		t.Fatal("stdlib must fail to parse the SM2 golden leaf")
	}
	if !IsSM2Certificate(leafDER) {
		t.Fatal("IsSM2Certificate must be true for the golden leaf")
	}
}

// TestSM2GoldenFromCore_Bundle 验证链 + AIC 提取 + 主体签名的公共入口。
func TestSM2GoldenFromCore_Bundle(t *testing.T) {
	exp, rootDER, interDER, leafDER, _, data, sig := loadGolden(t)

	res, err := VerifySM2Bundle(SM2BundleInput{
		LeafDER:       leafDER,
		Intermediates: [][]byte{interDER},
		Roots:         [][]byte{rootDER},
		Data:          data,
		Signature:     sig,
		RequireAIC:    true,
		Now:           goldenNow(),
	})
	if err != nil {
		t.Fatalf("verify core-signed golden bundle: %v", err)
	}
	if res.Cert == nil || res.AIC == nil {
		t.Fatal("expected cert and AIC in result")
	}

	aic := res.AIC
	if aic.AgentId != exp.AgentID {
		t.Fatalf("AIC agentId mismatch: %q != %q", aic.AgentId, exp.AgentID)
	}
	if aic.PrincipalUid.Realm != exp.PrincipalRealm || aic.PrincipalUid.Identifier != exp.PrincipalID {
		t.Fatalf("AIC principalUid mismatch: %+v", aic.PrincipalUid)
	}
	if len(aic.Capabilities) != 1 ||
		aic.Capabilities[0].SchemeId != exp.CapabilityScheme ||
		aic.Capabilities[0].CapabilityId != exp.CapabilityAction {
		t.Fatalf("AIC capabilities mismatch: %+v", aic.Capabilities)
	}
	if aic.DelegationAuthorization.Reason.ReasonCode != exp.DAReasonCode {
		t.Fatalf("DA reason code mismatch: %q != %q", aic.DelegationAuthorization.Reason.ReasonCode, exp.DAReasonCode)
	}
	// DA 的签名算法 OID 必须为纯 SM2-with-SM3。
	if !aic.DelegationAuthorization.SignatureAlgorithm.Algorithm.Equal(OIDSM2WithSM3) {
		t.Fatalf("DA signature algorithm: %v, want 1.2.156.10197.1.501",
			aic.DelegationAuthorization.SignatureAlgorithm.Algorithm)
	}
	if len(aic.DelegationAuthorization.SignatureValue) == 0 {
		t.Fatal("expected non-empty DA signature")
	}
	if exp.SignatureAlgOID != "1.2.156.10197.1.501" {
		t.Fatalf("expected.json signatureAlgOID drifted: %q", exp.SignatureAlgOID)
	}
}

// TestSM2GoldenFromCore_SingleSignature 验证 golden 叶子密钥对固定数据的单签名。
func TestSM2GoldenFromCore_SingleSignature(t *testing.T) {
	exp, _, _, _, spki, data, sig := loadGolden(t)

	if string(data) != exp.Data {
		t.Fatalf("expected.json data drifted: %q", data)
	}
	if err := VerifySM2Signature(spki, data, sig); err != nil {
		t.Fatalf("verify golden single signature: %v", err)
	}
}

// TestSM2GoldenFromCore_SingleSignature_Tampered 一字节篡改签名必须被拒。
func TestSM2GoldenFromCore_SingleSignature_Tampered(t *testing.T) {
	_, _, _, _, spki, data, sig := loadGolden(t)
	tampered := append([]byte(nil), sig...)
	tampered[len(tampered)-8] ^= 0x01
	err := VerifySM2Signature(spki, data, tampered)
	if err == nil {
		t.Fatal("expected signature verification failure after tampering")
	}
	if e, ok := err.(*SM2VerifyError); ok && e.Code != SM2ReasonSignature {
		t.Fatalf("expected signature reason, got %s", e.Code)
	}
}

// TestSM2GoldenFromCore_ChainTampered 篡改 golden 叶子签名必须落 chain_signature。
func TestSM2GoldenFromCore_ChainTampered(t *testing.T) {
	_, rootDER, interDER, leafDER, _, _, _ := loadGolden(t)
	_, err := VerifySM2CertificateChain(tamperDER(leafDER), [][]byte{interDER}, [][]byte{rootDER}, goldenNow())
	if err == nil {
		t.Fatal("expected chain rejection for tampered golden leaf")
	}
	if e, ok := err.(*SM2VerifyError); ok && e.Code != SM2ReasonChainSignature {
		t.Fatalf("expected chain_signature reason, got %s", e.Code)
	}
}

// TestSM2GoldenFromCore_UnrelatedRoot golden 叶子对无关根必须拒绝。
func TestSM2GoldenFromCore_UnrelatedRoot(t *testing.T) {
	_, _, interDER, leafDER, _, _, _ := loadGolden(t)
	now := time.Now().UTC()
	bad := fixtureCAKey(t)
	badTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(0xBAD1),
		Subject:               pkix.Name{CommonName: "Unrelated SM2 Root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	badDER, err := createSM2FixtureCert(badTmpl, badTmpl, bad.Public(), bad)
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifySM2CertificateChain(leafDER, [][]byte{interDER}, [][]byte{badDER}, goldenNow())
	if err == nil {
		t.Fatal("expected chain rejection for unrelated root")
	}
	if e, ok := err.(*SM2VerifyError); ok && e.Code != SM2ReasonChainUntrusted {
		t.Fatalf("expected chain_untrusted reason, got %s", e.Code)
	}
}

// TestSM2GoldenFromCore_Truncated 截断 golden DER 必须落 parse_certificate。
func TestSM2GoldenFromCore_Truncated(t *testing.T) {
	_, rootDER, interDER, leafDER, _, _, _ := loadGolden(t)
	_, err := VerifySM2CertificateChain(leafDER[:len(leafDER)/2], [][]byte{interDER}, [][]byte{rootDER})
	if err == nil {
		t.Fatal("expected rejection for truncated golden leaf")
	}
	if e, ok := err.(*SM2VerifyError); ok && e.Code != SM2ReasonParseCert {
		t.Fatalf("expected parse_certificate reason, got %s", e.Code)
	}
}
