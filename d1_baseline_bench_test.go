package gw

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
)

// d1ScopeOID simulates D1 authority-scope extension private experimental OID.
// Real D1 (draft-hood-independent-agtp) places flat scope string list in cert extension,
// this simulator uses private experimental OID to carry same-shaped data (UTF8String sequence),
// avoiding conflict with standard extensions while keeping the "cert extension parsing" cost path realistic.
var d1ScopeOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 1, 1}

// D1-style flow online-dependent network round-trip constants (spec section 3.2-5, no sleep in simulation).
// Real D1 has at least 1 online query per request (CRL/OCSP or authorization store), LAN 0.1ms / WAN 10ms two tiers.
const (
	d1RTTLANUs   = 100
	d1RTTWANUs   = 10000
	d1Roundtrips = 1
)

// d1Fixture holds all pre-built inputs for a D1-style flow benchmark (constructed during setup, not counted in timing).
type d1Fixture struct {
	leaf   *x509.Certificate
	roots  *x509.CertPool
	data   []byte
	sig    []byte
	pub    ed25519.PublicKey
	action string
}

// benchD1Chain constructs root CA + leaf (leaf has N flat scope extensions).
// Reuses the same RSA-2048 self-signed infrastructure as benchAICCert, but constructs a verifiable
// root->leaf chain, ensuring x509.Certificate.Verify takes the real chain verification path.
func benchD1Chain(b *testing.B, n int) *d1Fixture {
	b.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "D1 Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		b.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		b.Fatal(err)
	}

	tables := []string{"orders", "order_items", "products", "categories", "customers",
		"addresses", "payments", "refunds", "shipments", "inventory"}
	ops := []string{"SELECT", "INSERT", "UPDATE", "DELETE"}
	scopes := make([]string, n)
	for i := 0; i < n; i++ {
		scopes[i] = fmt.Sprintf("db:query:%s:%s", ops[i%len(ops)], tables[i%len(tables)])
	}
	// N=0 scenario: empty scope list + empty action, simulator convention allows this combo (symmetric with AIC caps-0).
	action := "db:query:SELECT:orders"
	if n == 0 {
		action = ""
	}
	scopeDER, err := asn1.Marshal(scopes)
	if err != nil {
		b.Fatal(err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "d1-agent", Organization: []string{"varwof.com"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{
			{Id: d1ScopeOID, Critical: false, Value: scopeDER},
		},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		b.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		b.Fatal(err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	data := []byte(strings.Join(scopes, "\x00"))
	sig := ed25519.Sign(priv, data)

	return &d1Fixture{leaf: leaf, roots: roots, data: data, sig: sig, pub: pub, action: action}
}

// d1Step executes the D1-style flow six steps, returns whether allowed.
// 1. TLS handshake and chain verification (x509.Verify, same chain path as AIC);
// 2. Flat scope parsing (extracts UTF8String list from cert extension);
// 3. Ed25519 commitment verification (single-use signature over canonicalized scope list);
// 4. Whole string matching (request action exact-match with scope, D1 does not support item-by-item splitting);
// 5. Online dependencies (no sleep, accounted via d1RTTLANUs/d1RTTWANUs constants in summary script).
func d1Step(f *d1Fixture) bool {
	if _, err := f.leaf.Verify(x509.VerifyOptions{
		Roots:     f.roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return false
	}

	var scopes []string
	for _, ext := range f.leaf.Extensions {
		if ext.Id.Equal(d1ScopeOID) {
			if _, err := asn1.Unmarshal(ext.Value, &scopes); err != nil {
				return false
			}
		}
	}

	if !ed25519.Verify(f.pub, f.data, f.sig) {
		return false
	}

	for _, s := range scopes {
		if s == f.action {
			return true
		}
	}
	return f.action == "" && len(scopes) == 0
}

// BenchmarkD1Baseline measures D1-style flow single-request decision latency (D1 comparison baseline).
// Covers: TLS chain verification + flat scope parsing + Ed25519 commitment verification + whole string matching;
// online dependencies not slept, recorded via d1RTTLANUs/d1RTTWANUs constants, incorporated by summary script
// into "pure computation + RTT" two columns. Compared in the same round as BenchmarkRunAccessPipeline (same caps-N tier).
func BenchmarkD1Baseline(b *testing.B) {
	for _, n := range []int{0, 10, 50, 100, 250} {
		b.Run(fmt.Sprintf("caps-%d", n), func(b *testing.B) {
			f := benchD1Chain(b, n)
			b.ReportAllocs()
			b.ResetTimer()
			granted := 0
			for i := 0; i < b.N; i++ {
				if d1Step(f) {
					granted++
				}
			}
			if n > 0 && granted != b.N {
				b.Fatalf("D1 step unexpectedly denied %d/%d", b.N-granted, b.N)
			}
		})
	}
}
