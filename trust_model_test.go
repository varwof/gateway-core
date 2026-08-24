package gw

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"
)

// mockPolicyServer is used for Layer 3 online authorization tests.
type mockPolicyServer struct {
	err error
}

func (m mockPolicyServer) Name() string { return "mock-policy" }
func (m mockPolicyServer) CheckOnline(_ *x509.Certificate, _ *AIC) error {
	return m.err
}

func TestVerifyLayer1_Identity(t *testing.T) {
	t.Run("valid cert", func(t *testing.T) {
		cert := &x509.Certificate{
			Subject:   pkix.Name{CommonName: "agent", OrganizationalUnit: []string{"gateway:admin"}},
			NotBefore: time.Now().Add(-time.Hour),
			NotAfter:  time.Now().Add(time.Hour),
		}
		r := VerifyLayer1([]*x509.Certificate{cert}, &PipelineConfig{AllowRoles: []string{RoleAdmin}})
		if !r.Verified {
			t.Fatalf("expected verified, got %s", r.Reason)
		}
		if len(r.Roles) != 1 || r.Roles[0] != RoleAdmin {
			t.Fatalf("roles = %v, want [gateway:admin]", r.Roles)
		}
	})

	t.Run("expired cert", func(t *testing.T) {
		cert := &x509.Certificate{
			NotBefore: time.Now().Add(-2 * time.Hour),
			NotAfter:  time.Now().Add(-time.Hour),
		}
		r := VerifyLayer1([]*x509.Certificate{cert}, &PipelineConfig{})
		if r.Verified {
			t.Fatal("expired cert should not verify")
		}
	})

	t.Run("empty chain", func(t *testing.T) {
		r := VerifyLayer1(nil, &PipelineConfig{})
		if r.Verified {
			t.Fatal("empty chain should not verify")
		}
	})

	t.Run("insufficient roles", func(t *testing.T) {
		cert := &x509.Certificate{
			Subject:   pkix.Name{CommonName: "agent"},
			NotBefore: time.Now().Add(-time.Hour),
			NotAfter:  time.Now().Add(time.Hour),
		}
		r := VerifyLayer1([]*x509.Certificate{cert}, &PipelineConfig{AllowRoles: []string{RoleAdmin}})
		if r.Verified {
			t.Fatal("no admin role should fail")
		}
	})
}

func TestVerifyLayer2_Representation(t *testing.T) {
	t.Run("no AIC, not required → pass", func(t *testing.T) {
		cert := &x509.Certificate{
			Subject:   pkix.Name{CommonName: "agent"},
			NotBefore: time.Now().Add(-time.Hour),
			NotAfter:  time.Now().Add(time.Hour),
		}
		_, r := VerifyLayer2([]*x509.Certificate{cert}, &PipelineConfig{}, nil)
		if !r.Verified {
			t.Fatalf("expected pass without AIC: %s", r.Reason)
		}
	})

	t.Run("AIC required but absent → deny", func(t *testing.T) {
		cert := &x509.Certificate{
			Subject:   pkix.Name{CommonName: "agent"},
			NotBefore: time.Now().Add(-time.Hour),
			NotAfter:  time.Now().Add(time.Hour),
		}
		_, r := VerifyLayer2([]*x509.Certificate{cert}, &PipelineConfig{RequireAIC: true}, nil)
		if r.Verified {
			t.Fatal("RequireAIC without AIC should deny")
		}
	})

	t.Run("AIC present → pass + parsed", func(t *testing.T) {
		aic := AIC{
			AgentId:      "agent-1",
			PrincipalUid: PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "u@v.com"},
			DelegationAuthorization: DelegationAuthorization{
				Reason:             Reason{ReasonCode: "TEST", Description: "test"},
				Nonce:              make([]byte, 32),
				RequestedLifetime:  3600,
				SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
			},
		}
		aicVal, _ := asn1.Marshal(aic)
		cert := makeCertWithExt(t, oidAIC, aicVal)
		_, r := VerifyLayer2([]*x509.Certificate{cert}, &PipelineConfig{RequireAIC: true}, nil)
		if !r.Verified {
			t.Fatalf("expected pass with AIC: %s", r.Reason)
		}
		if r.AIC == nil || r.AIC.AgentId != "agent-1" {
			t.Fatal("AIC not parsed")
		}
	})
}

func TestVerifyLayer3_OnlineAuth(t *testing.T) {
	t.Run("no caches, no policy server → pass", func(t *testing.T) {
		cert := &x509.Certificate{
			Subject:   pkix.Name{CommonName: "agent"},
			NotBefore: time.Now().Add(-time.Hour),
			NotAfter:  time.Now().Add(time.Hour),
		}
		r := VerifyLayer3([]*x509.Certificate{cert}, &PipelineConfig{})
		if !r.Verified {
			t.Fatalf("expected pass: %s", r.Reason)
		}
	})

	t.Run("policy server allows", func(t *testing.T) {
		cert := &x509.Certificate{SerialNumber: big.NewInt(1)}
		r := VerifyLayer3([]*x509.Certificate{cert}, &PipelineConfig{
			PolicyServer: mockPolicyServer{},
		})
		if !r.Verified {
			t.Fatalf("policy allow should pass: %s", r.Reason)
		}
	})

	t.Run("policy server denies", func(t *testing.T) {
		cert := &x509.Certificate{SerialNumber: big.NewInt(1)}
		r := VerifyLayer3([]*x509.Certificate{cert}, &PipelineConfig{
			PolicyServer: mockPolicyServer{err: errors.New("policy says no")},
		})
		if r.Verified {
			t.Fatal("policy deny should fail")
		}
	})

	t.Run("empty chain", func(t *testing.T) {
		r := VerifyLayer3(nil, &PipelineConfig{})
		if r.Verified {
			t.Fatal("empty chain should fail")
		}
	})
}

func TestVerifyTrustLayers(t *testing.T) {
	t.Run("full pass", func(t *testing.T) {
		cert := &x509.Certificate{
			Subject:   pkix.Name{CommonName: "agent", OrganizationalUnit: []string{"gateway:admin"}},
			NotBefore: time.Now().Add(-time.Hour),
			NotAfter:  time.Now().Add(time.Hour),
		}
		r := VerifyTrustLayers([]*x509.Certificate{cert}, &PipelineConfig{
			AllowRoles:   []string{RoleAdmin},
			PolicyServer: mockPolicyServer{},
		})
		if !r.Granted {
			t.Fatalf("expected granted: %s", r.DenyReason)
		}
	})

	t.Run("L1 role deny", func(t *testing.T) {
		cert := &x509.Certificate{
			Subject:   pkix.Name{CommonName: "agent"},
			NotBefore: time.Now().Add(-time.Hour),
			NotAfter:  time.Now().Add(time.Hour),
		}
		r := VerifyTrustLayers([]*x509.Certificate{cert}, &PipelineConfig{AllowRoles: []string{RoleAdmin}})
		if r.Granted {
			t.Fatal("L1 role check should deny")
		}
	})

	t.Run("L3 policy deny", func(t *testing.T) {
		cert := &x509.Certificate{
			Subject:   pkix.Name{CommonName: "agent"},
			NotBefore: time.Now().Add(-time.Hour),
			NotAfter:  time.Now().Add(time.Hour),
		}
		r := VerifyTrustLayers([]*x509.Certificate{cert}, &PipelineConfig{
			PolicyServer: mockPolicyServer{err: errors.New("policy says no")},
		})
		if r.Granted {
			t.Fatal("L3 policy check should deny")
		}
	})

	t.Run("nil config", func(t *testing.T) {
		r := VerifyTrustLayers(nil, nil)
		if r.Granted {
			t.Fatal("nil config should deny")
		}
	})

	t.Run("nil chain", func(t *testing.T) {
		r := VerifyTrustLayers(nil, &PipelineConfig{})
		if r.Granted {
			t.Fatal("nil chain should deny")
		}
	})
}

// TestVerifyTrustLayersParity verifies that VerifyTrustLayers and RunAccessPipeline
// produce consistent admission results for the same input (three-layer explicit entry compatible with single entry).
func TestVerifyTrustLayersParity(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	aic := AIC{
		AgentId:      "agent-1",
		PrincipalUid: PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "u@v.com"},
		DelegationAuthorization: DelegationAuthorization{
			Reason:             Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
	aicVal, _ := asn1.Marshal(aic)
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         pkix.Name{CommonName: "agent"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: oidAIC, Value: aicVal}},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	chain := []*x509.Certificate{cert}

	cfg := &PipelineConfig{RequireAIC: true}
	if r1 := RunAccessPipeline(chain, cfg); !r1.Granted {
		t.Fatalf("RunAccessPipeline: %s", r1.DenyReason)
	}
	if r2 := VerifyTrustLayers(chain, cfg); !r2.Granted {
		t.Fatalf("VerifyTrustLayers: %s", r2.DenyReason)
	}
}
