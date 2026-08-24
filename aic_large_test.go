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

// targetExtSizes is the list of target AIC extension sizes in bytes for testing.
var targetExtSizes = []int{4096, 8192, 12288, 16384, 20480}

// genLargeAICCert generates a self-signed certificate with an AIC extension of approximately targetBytes.
// It bypasses the 256 limit in BuildAICExtension and the 16KB limit in sign.go.
// Returns the certificate and private key.
func genLargeAICCert(t *testing.T, targetBytes int) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	// Use 44-byte CapabilityId to precisely control the size of each entry
	const capIDFmt = "capability-%040d"
	baseScheme := "test-sch"

	caps := make([]Capability, 0)
	// Add a base entry first, then loop to add more until reaching the target
	for i := 0; ; i++ {
		cap := Capability{
			SchemeId:     baseScheme,
			CapabilityId: fmt.Sprintf(capIDFmt, i),
		}
		caps = append(caps, cap)

		// Marshal to check current AIC extension size
		aic := AIC{
			Version: 1,
			AgentId: "large-aic-test",

			PrincipalUid: PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "user@varwof.com"},
			Capabilities: caps,
		}
		der, err := asn1.Marshal(aic)
		if err != nil {
			t.Fatalf("asn1.Marshal failed at cap %d: %v", i, err)
		}
		if len(der) >= targetBytes {
			break
		}
		// Safety cap: at most 2000 entries to prevent infinite loop
		if i > 2000 {
			t.Fatalf("exceeded 2000 capabilities without reaching target %d bytes (got %d)", targetBytes, len(der))
		}
	}

	// Build the final AIC with the complete capability list
	aic := AIC{
		Version: 1,
		AgentId: "large-aic-test",

		PrincipalUid: PrincipalUid{KeyHash: make([]byte, 32), Version: 1, Realm: "varwof", Identifier: "user@varwof.com"},
		Capabilities: caps,
		DelegationAuthorization: DelegationAuthorization{Reason: Reason{ReasonCode: "TEST", Description: "test"},
			Nonce:              make([]byte, 32),
			RequestedLifetime:  3600,
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: OIDSigECDSAWithSHA256},
		},
	}
	aicDER, err := asn1.Marshal(aic)
	if err != nil {
		t.Fatalf("final asn1.Marshal: %v", err)
	}

	// Self-signed certificate
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "large-aic-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: oidAIC, Critical: true, Value: aicDER},
		},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	t.Logf("AIC ext size: %d bytes, cert DER: %d bytes, caps: %d", len(aicDER), len(certDER), len(caps))
	return cert, key
}

func TestLargeAIC_Generate(t *testing.T) {
	// Verify the generator can produce certificates for each target size
	for _, size := range targetExtSizes {
		t.Run(fmt.Sprintf("target_%d", size), func(t *testing.T) {
			cert, _ := genLargeAICCert(t, size)
			// Verify the AIC extension can be parsed correctly
			aic, err := ParseAIC(cert)
			if err != nil {
				t.Fatalf("ParseAICExtension failed: %v", err)
			}
			if aic == nil {
				t.Fatal("AIC extension not found")
			}
			if len(aic.Capabilities) == 0 {
				t.Fatal("no capabilities in AIC")
			}
			t.Logf("parsed %d capabilities", len(aic.Capabilities))
		})
	}
}

func BenchmarkParseAIC(b *testing.B) {
	for _, size := range targetExtSizes {
		cert, _ := genLargeAICCert(&testing.T{}, size)
		b.Run(fmt.Sprintf("AIC_%d", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := ParseAIC(cert)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
