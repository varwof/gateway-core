package gw

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"testing"
	"time"
)

// benchAICCert builds a certificate with an AIC extension for admission pipeline benchmarks.
// nCaps specifies the number of capabilities (short id format: varwof/demo-mysql-v1:SELECT:<table>).
func benchAICCert(b *testing.B, nCaps int) *x509.Certificate {
	b.Helper()
	tables := []string{
		"orders", "order_items", "products", "categories", "customers",
		"addresses", "payments", "refunds", "shipments", "inventory",
	}
	ops := []string{"SELECT", "INSERT", "UPDATE", "DELETE"}
	caps := make([]Capability, nCaps)
	for i := 0; i < nCaps; i++ {
		caps[i] = Capability{
			SchemeId:     "varwof/demo-mysql-v1",
			CapabilityId: ops[i%len(ops)] + ":" + tables[i%len(tables)],
		}
	}
	aic := AIC{
		AgentId:      "ops-dba-agent",
		PrincipalUid: PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "ops-dba@varwof.com"},
		Capabilities: caps,
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "OPS", Description: "db ops"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			Timestamp:          time.Now(),
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
	aicVal, err := asn1.Marshal(aic)
	if err != nil {
		b.Fatal(err)
	}
	return benchCertWithExt(b, oidAIC, aicVal)
}

// benchPipelineConfig builds an admission pipeline config (with allowlist plugin registry, simulating a real gateway).
func benchPipelineConfig(b *testing.B) *PipelineConfig {
	b.Helper()
	reg := NewPluginRegistry()
	cfgs := PluginConfigs{
		"varwof/demo-mysql-v1": {Type: "allowlist", Config: map[string]interface{}{"allow": []string{"SELECT:orders"}, "default_action": "allow"}},
		"pki":                  {Type: "allowlist", Config: map[string]interface{}{"allow": []string{"cert:list"}, "default_action": "allow"}},
	}
	if err := BuildPluginsFromConfig(reg, cfgs); err != nil {
		b.Fatal(err)
	}
	return &PipelineConfig{
		RequireAIC:               true,
		AllowRoles:               []string{"gateway:mysql-ops", "gateway:admin"},
		CapabilityPluginRegistry: reg,
		EnforceConstraints:       true,
	}
}

// BenchmarkRunAccessPipeline measures the latency of a single admission pipeline decision (E3).
// Covers: certificate validity + CRL/OCSP cache lookup (nil→skip) + RBAC role extraction +
// CheckAdmission (AIC parsing + P∩C∩T intersection + constraint check + nonce anti-replay) + plugin routing decision.
// Note: CRL/OCSP caches set to nil for shortest path; real gateways use in-memory caches which are also just map lookups.
func BenchmarkRunAccessPipeline(b *testing.B) {
	for _, n := range []int{0, 10, 50, 100, 250} {
		b.Run(fmt.Sprintf("caps-%d", n), func(b *testing.B) {
			cert := benchAICCert(b, n)
			cfg := benchPipelineConfig(b)
			chain := []*x509.Certificate{cert}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				r := RunAccessPipeline(chain, cfg)
				if !r.Granted {
					b.Fatalf("unexpected deny: %s", r.DenyReason)
				}
			}
		})
	}
}

// benchCertWithExt generates a self-signed certificate with a specified extension (test helper).
func benchCertWithExt(b *testing.B, extOID asn1.ObjectIdentifier, extValue []byte) *x509.Certificate {
	b.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ops-dba-agent", Organization: []string{"varwof.com"}, OrganizationalUnit: []string{"gateway:mysql-ops"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{
			{Id: extOID, Critical: false, Value: extValue},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		b.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		b.Fatal(err)
	}
	return cert
}
