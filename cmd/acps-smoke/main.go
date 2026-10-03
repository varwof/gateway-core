// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Command acps-smoke exercises the ACPs AAC v0 slice end to end exactly as a
// gateway would: mTLS peer certificate -> RunAccessPipelineAAC (identity
// binding, trusted context, audience/chain/replay, fail-closed PDP, audit).
// Run with: go run ./cmd/acps-smoke
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	gwc "github.com/varwof/gateway-core"
	coreacps "github.com/varwof/gateway-core/acps"
)

const (
	peerAIC  = "1.2.156.3088.1.2.34C2.478BDF.3GF546.0JU4"
	otherAIC = "1.2.156.3088.1.3.34C2.478BDF.3GF546.0JU4"
)

var failed int

func check(name string, ok bool, detail string) {
	mark := "PASS"
	if !ok {
		mark = "FAIL"
		failed++
	}
	fmt.Printf("[%s] %-42s %s\n", mark, name, detail)
}

func peerCert(cn, sanAIC string) *x509.Certificate {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42424242),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	if sanAIC != "" {
		u, _ := url.Parse("acps://" + sanAIC)
		tmpl.URIs = []*url.URL{u}
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	return cert
}

func bearer(jti string, act string) *coreacps.DelegationRecord {
	now := time.Now().Unix()
	claims := map[string]any{
		"iss":                       "https://sts.example.com",
		"sub":                       "https://idp.example.com/realm#user-123",
		"aud":                       "acps:agent:" + act,
		"exp":                       now + 3600,
		"iat":                       now - 60,
		"jti":                       jti,
		"scope":                     "coreacps.skill.invoke:data.export",
		"act":                       "agent:" + act,
		"acps_subject_type":         "human",
		"acps_delegation_id":        "dlg-" + jti[len(jti)-1:],
		"acps_delegation_mode":      coreacps.DelegationModeDynamic,
		"acps_target_aic":           act,
		"acps_chain_depth":          1,
		"acps_max_chain_depth":      5,
		"acps_allowed_partner_aics": []string{act},
	}
	payload, _ := json.Marshal(claims)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub, sig, _ := coreacps.SignRecord(payload, priv)
	return coreacps.NewSignedDelegation(coreacps.FromTokenClaims(claims), payload, sig, pub)
}

func allowAll(req *coreacps.AuthorizationRequest) (*coreacps.AuthorizationDecision, error) {
	return coreacps.Allow(), nil
}

func main() {
	chain := func(c *x509.Certificate) []*x509.Certificate { return []*x509.Certificate{c} }
	pc := &gwc.PipelineConfig{}
	req := func(bearer *coreacps.DelegationRecord, sender string) *gwc.AACRequest {
		return &gwc.AACRequest{
			Action:   "task.start",
			Resource: coreacps.AuthorizationResource{ResourceType: "skill", ResourceID: "data.export"},
			Bearer:   bearer,
			SenderID: sender,
		}
	}
	aac := &gwc.AACProfileConfig{Enabled: true, Policy: allowAll}
	guard := gwc.NewReplayGuard()
	aacReplay := &gwc.AACProfileConfig{Enabled: true, Policy: allowAll, ReplayGuard: guard}

	goodCert := peerCert(peerAIC, peerAIC)
	badCert := peerCert("not-an-aic/0", "")
	tok := bearer("jti-1", peerAIC)

	fmt.Println("== ACPs AAC v0 冒烟测试（真实网关调用路径） ==")

	// 1. AAC 未启用 → 与既有管线完全一致（默认行为不变）
	r := gwc.RunAccessPipelineAAC(chain(goodCert), pc, nil, nil)
	check("未启用 AAC 走原管线", r.Granted, fmt.Sprintf("deny=%q", r.DenyReason))

	// 2. 启用 + 合法身份 + 允许策略 → 放行
	r = gwc.RunAccessPipelineAAC(chain(goodCert), pc, aac, req(nil, ""))
	check("单跳身份调用放行", r.Granted, fmt.Sprintf("principal=%q", r.Principal))

	// 3. 带委托 token 的完整绑定链 → 放行（human -> agent 链 + 证书绑定）
	r = gwc.RunAccessPipelineAAC(chain(goodCert), pc, aacReplay, req(tok, ""))
	check("委托 token 绑定链放行", r.Granted, "")

	// 4. token 重放（同 peer 复用同一 jti）→ Invalid access token
	r = gwc.RunAccessPipelineAAC(chain(goodCert), pc, aacReplay, req(tok, ""))
	check("jti 重放拒绝(公共消息)", !r.Granted && r.DenyReason == "Invalid access token",
		fmt.Sprintf("deny=%q", r.DenyReason))

	// 5. 无证书身份 → Authentication required
	r = gwc.RunAccessPipelineAAC(chain(badCert), pc, aac, req(nil, ""))
	check("无对端身份拒绝(公共消息)", !r.Granted && r.DenyReason == "Authentication required",
		fmt.Sprintf("deny=%q", r.DenyReason))

	// 6. senderId 与对端 AIC 不一致 → Authorization failed
	r = gwc.RunAccessPipelineAAC(chain(goodCert), pc, aac, req(nil, otherAIC))
	check("senderId 不匹配拒绝(公共消息)", !r.Granted && r.DenyReason == "Authorization failed",
		fmt.Sprintf("deny=%q", r.DenyReason))

	// 7. 无策略（nil）→ fail closed Authorization failed
	noPolicy := &gwc.AACProfileConfig{Enabled: true}
	r = gwc.RunAccessPipelineAAC(chain(goodCert), pc, noPolicy, req(nil, ""))
	check("nil 策略 fail closed", !r.Granted && r.DenyReason == "Authorization failed",
		fmt.Sprintf("deny=%q", r.DenyReason))

	// 8. 证书 CN/SAN 不一致（伪造 SAN）→ Authentication required
	spoofCert := peerCert(peerAIC, otherAIC)
	r = gwc.RunAccessPipelineAAC(chain(spoofCert), pc, aac, req(nil, ""))
	check("CN/SAN 冲突拒绝", !r.Granted && r.DenyReason == "Authentication required",
		fmt.Sprintf("deny=%q", r.DenyReason))

	// 9. 审计：deny 决策写入 AuditLogger（drain 后）
	dir := tTemp()
	logFile := filepath.Join(dir, "audit.log")
	logger, _ := gwc.NewAuditLogger(logFile, nil, 1<<20, 2)
	pcAudit := &gwc.PipelineConfig{AuditLogger: logger}
	gwc.RunAccessPipelineAAC(chain(badCert), pcAudit, aac, req(nil, ""))
	logger.Close()
	data, _ := os.ReadFile(logFile)
	has := strings.Contains(string(data), `"action":"authorization_decision"`) &&
		strings.Contains(string(data), "\"level\":\"WARN\"")
	check("审计日志记录 deny/WARN", has, string(data))

	// 10. AIC 独立校验：spec 示例 + 对应 salt（0x12,0x34 -> CRC 0x646C -> 0JU4）
	specAIC := "1.2.156.3088.1.1.34C2.478BDF.3GF546.0JU4"
	aic, err := coreacps.Verify(specAIC, []byte{0x12, 0x34})
	check("AIC 结构+CRC 校验", err == nil && aic.ChecksumValidated, fmt.Sprintf("err=%v", err))
	_, err = coreacps.Verify("1.2.156.3088.1.1.34C2.478BDF.3GF546.0JUX", []byte{0x12, 0x34})
	check("篡改校验码被拒", err != nil, fmt.Sprintf("err=%v", err))

	fmt.Println("==============================")
	if failed > 0 {
		fmt.Printf("冒烟结果: %d 项失败\n", failed)
		os.Exit(1)
	}
	fmt.Println("冒烟结果: 全部通过")
}

func tTemp() string {
	d, err := os.MkdirTemp("", "acps-smoke-*")
	if err != nil {
		panic(err)
	}
	return d
}
