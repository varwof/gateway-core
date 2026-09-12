// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package acps

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/url"
	"sync"
	"testing"
	"time"
)

// benchAIC is the AIC §4.1 spec vector, whose checksum is valid under the
// spec salt {0x12,0x34} (needed to exercise the full verification path).
const benchAIC = aicSpecExample

var (
	benchSalt = []byte{0x12, 0x34} // AIC §4.1 spec-vector salt
	benchCert *x509.Certificate
	benchOnce sync.Once

	benchTokenPayload []byte
	benchTokenSig     []byte
	benchTokenPub     ed25519.PublicKey
	benchTokenRec     *DelegationRecord
	benchTokenOnce    sync.Once
)

func benchCertificate(t *testing.B) *x509.Certificate {
	t.Helper()
	benchOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		u, err := url.Parse("acps://" + benchAIC)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(9000001),
			Subject:      pkix.Name{CommonName: benchAIC},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			URIs:         []*url.URL{u},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		benchCert, err = x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
	})
	return benchCert
}

func benchDelegation(t *testing.B) (*DelegationRecord, []byte, []byte, ed25519.PublicKey) {
	t.Helper()
	benchTokenOnce.Do(func() {
		claims := map[string]any{
			"iss":                       "https://sts.example.com",
			"sub":                       "https://idp.example.com/realm#user-123",
			"aud":                       "acps:agent:" + benchAIC,
			"exp":                       time.Now().Add(time.Hour).Unix(),
			"iat":                       time.Now().Add(-time.Minute).Unix(),
			"jti":                       "bench-jti",
			"scope":                     "acps.skill.invoke:data.export",
			"act":                       "agent:" + benchAIC,
			"acps_subject_type":         "human",
			"acps_delegation_id":        "dlg-bench",
			"acps_delegation_mode":      DelegationModeDynamic,
			"acps_chain_depth":          1,
			"acps_max_chain_depth":      5,
			"acps_allowed_partner_aics": []string{benchAIC},
		}
		var err error
		benchTokenPayload, err = json.Marshal(claims)
		if err != nil {
			t.Fatal(err)
		}
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		benchTokenPub, benchTokenSig, err = SignRecord(benchTokenPayload, privateKey)
		if err != nil {
			t.Fatal(err)
		}
		benchTokenRec = NewSignedDelegation(FromTokenClaims(mustClaims(t)), benchTokenPayload, benchTokenSig, benchTokenPub)
	})
	return benchTokenRec, benchTokenPayload, benchTokenSig, benchTokenPub
}

func mustClaims(t *testing.B) map[string]any {
	t.Helper()
	var claims map[string]any
	if err := json.Unmarshal(benchTokenPayload, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

func BenchmarkVerify(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := Verify(benchAIC, benchSalt); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseAIC(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := ParseAIC(benchAIC); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCRC16CCITTFALSE(b *testing.B) {
	data := []byte("1.2.156.3088.1.2.34C2.478BDF.3GF546")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CRC16CCITTFALSE(data)
	}
}

func BenchmarkExtractPeerAIC(b *testing.B) {
	cert := benchCertificate(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ExtractPeerAIC(cert, true); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFromTokenClaims(b *testing.B) {
	benchDelegation(b) // initialize the shared token fixtures
	claims := mustClaims(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FromTokenClaims(claims)
	}
}

func BenchmarkContextConstruction(b *testing.B) {
	rec, payload, sig, pub := benchDelegation(b)
	cert := benchCertificate(b)
	providers := []ContextProvider{
		&MTLSProvider{RequireSAN: true, Salt: benchSalt},
		&TokenProvider{PresenterCert: cert},
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := BuildContext(BuildOptions{
			Providers: providers,
			Inputs:    []any{cert, NewSignedDelegation(FromTokenClaims(mustClaims(b)), payload, sig, pub)},
			Action:    "task.start",
			Resource:  AuthorizationResource{ResourceType: "skill", ResourceID: "data.export", SkillId: "data.export"},
		})
		if err != nil {
			b.Fatal(err)
		}
	}
	_ = rec
}
