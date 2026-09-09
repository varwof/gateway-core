// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net/url"
	"testing"
	"time"
)

func TestParseSPIFFEID_NoPrefix(t *testing.T) {
	_, err := ParseSPIFFEID("https://example.com")
	if err == nil {
		t.Fatal("expected error for missing spiffe:// prefix")
	}
}

func TestParseSPIFFEID_Empty(t *testing.T) {
	_, err := ParseSPIFFEID("spiffe://")
	if err == nil {
		t.Fatal("expected error for empty trust domain")
	}
}

func TestParseSPIFFEID_NoDot(t *testing.T) {
	_, err := ParseSPIFFEID("spiffe://local")
	if err == nil {
		t.Fatal("expected error for trust domain without dot")
	}
}

func TestParseSPIFFEID_Minimal(t *testing.T) {
	s, err := ParseSPIFFEID("spiffe://example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.TrustDomain != "example.com" {
		t.Fatalf("expected example.com, got %s", s.TrustDomain)
	}
	if s.Path != "/" {
		t.Fatalf("expected /, got %s", s.Path)
	}
}

func TestParseSPIFFEID_WithPath(t *testing.T) {
	s, err := ParseSPIFFEID("spiffe://example.com/ns/default/sa/redis")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.TrustDomain != "example.com" {
		t.Fatalf("expected example.com, got %s", s.TrustDomain)
	}
	if s.Path != "/ns/default/sa/redis" {
		t.Fatalf("expected /ns/default/sa/redis, got %s", s.Path)
	}
}

func TestParseSPIFFEID_MultiDot(t *testing.T) {
	s, err := ParseSPIFFEID("spiffe://prod.us-east-1.k8s.example.com/workload/my-svc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.TrustDomain != "prod.us-east-1.k8s.example.com" {
		t.Fatalf("unexpected trust domain: %s", s.TrustDomain)
	}
}

func TestSPIFFEID_String(t *testing.T) {
	s := &SPIFFEID{TrustDomain: "example.org", Path: "/app/svc"}
	got := s.String()
	want := "spiffe://example.org/app/svc"
	if got != want {
		t.Fatalf("expected %s, got %s", want, got)
	}
}

func TestSPIFFEID_StringNil(t *testing.T) {
	var s *SPIFFEID
	if s.String() != "" {
		t.Fatal("expected empty string for nil SPIFFEID")
	}
}

func TestSPIFFEID_Equal(t *testing.T) {
	a := &SPIFFEID{TrustDomain: "a.com", Path: "/svc"}
	b := &SPIFFEID{TrustDomain: "a.com", Path: "/svc"}
	if !a.Equal(b) {
		t.Fatal("expected equal")
	}
}

func TestSPIFFEID_NotEqual(t *testing.T) {
	a := &SPIFFEID{TrustDomain: "a.com", Path: "/svc"}
	b := &SPIFFEID{TrustDomain: "b.com", Path: "/svc"}
	if a.Equal(b) {
		t.Fatal("expected not equal")
	}
}

func TestSPIFFEID_EqualNil(t *testing.T) {
	if !(*SPIFFEID)(nil).Equal(nil) {
		t.Fatal("nil should equal nil")
	}
}

func TestSPIFFEID_EqualNilNonNil(t *testing.T) {
	s := &SPIFFEID{TrustDomain: "x.com", Path: "/"}
	if s.Equal(nil) {
		t.Fatal("non-nil should not equal nil")
	}
}

func TestExtractSPIFFEID(t *testing.T) {
	cert := &x509.Certificate{
		URIs: []*url.URL{
			{Scheme: "spiffe", Host: "prod.example.com", Path: "/ns/default/sa/app"},
		},
	}
	sid := ExtractSPIFFEID(cert)
	if sid == nil {
		t.Fatal("expected non-nil SPIFFEID")
	}
	if sid.TrustDomain != "prod.example.com" {
		t.Fatalf("TrustDomain: expected prod.example.com, got %s", sid.TrustDomain)
	}
	if sid.Path != "/ns/default/sa/app" {
		t.Fatalf("Path: expected /ns/default/sa/app, got %s", sid.Path)
	}
}

func TestExtractSPIFFEID_NilCert(t *testing.T) {
	if sid := ExtractSPIFFEID(nil); sid != nil {
		t.Fatal("expected nil for nil cert")
	}
}

func TestExtractSPIFFEID_NoURIs(t *testing.T) {
	cert := &x509.Certificate{}
	if sid := ExtractSPIFFEID(cert); sid != nil {
		t.Fatal("expected nil when no URI SANs")
	}
}

func TestExtractSPIFFEID_NoSpiffeURI(t *testing.T) {
	cert := &x509.Certificate{
		URIs: []*url.URL{
			{Scheme: "https", Host: "example.com"},
		},
	}
	if sid := ExtractSPIFFEID(cert); sid != nil {
		t.Fatal("expected nil for non-spiffe URI")
	}
}

func TestExtractSPIFFEID_MissingPath(t *testing.T) {
	cert := &x509.Certificate{
		URIs: []*url.URL{
			{Scheme: "spiffe", Host: "trust.local"},
		},
	}
	sid := ExtractSPIFFEIDFromCert(cert)
	if sid == "" {
		t.Fatal("expected non-empty SPIFFE ID")
	}
}

func spiffeTestCert(uri string) *x509.Certificate {
	cert := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "spiffe-test"},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(1 * time.Hour),
	}
	if uri != "" {
		u, _ := url.Parse(uri)
		cert.URIs = []*url.URL{u}
	}
	return cert
}

func TestPipelineRequireSPIFFE_DenyNoURI(t *testing.T) {
	r := RunAccessPipeline([]*x509.Certificate{spiffeTestCert("")}, &PipelineConfig{RequireSPIFFE: true})
	if r.Granted {
		t.Fatal("expected denial when RequireSPIFFE and no SPIFFE URI")
	}
	if r.DenyReason != "spiffe id required but not present in client certificate" {
		t.Errorf("unexpected deny reason: %s", r.DenyReason)
	}
}

func TestPipelineRequireSPIFFE_Allow(t *testing.T) {
	cert := spiffeTestCert("spiffe://varwof.com/agent/scheduler-a")
	r := RunAccessPipeline([]*x509.Certificate{cert}, &PipelineConfig{RequireSPIFFE: true})
	if !r.Granted {
		t.Fatalf("expected allow, got: %s", r.DenyReason)
	}
	if r.SPIFFEID != "spiffe://varwof.com/agent/scheduler-a" {
		t.Errorf("PipelineResult.SPIFFEID = %q", r.SPIFFEID)
	}
}

func TestPipelineSPIFFETrustDomainMismatch(t *testing.T) {
	cert := spiffeTestCert("spiffe://evil.com/agent/x")
	r := RunAccessPipeline([]*x509.Certificate{cert}, &PipelineConfig{SPIFFETrustDomain: "varwof.com"})
	if r.Granted {
		t.Fatal("expected denial on trust domain mismatch")
	}
}

func TestPipelineSPIFFETrustDomainMatch(t *testing.T) {
	cert := spiffeTestCert("spiffe://varwof.com/agent/scheduler-a")
	r := RunAccessPipeline([]*x509.Certificate{cert}, &PipelineConfig{SPIFFETrustDomain: "varwof.com"})
	if !r.Granted {
		t.Fatalf("expected allow on matching trust domain, got: %s", r.DenyReason)
	}
}

func TestPipelineSPIFFEAllowedList(t *testing.T) {
	cfg := &PipelineConfig{
		AllowedSPIFFEIDs: []string{"spiffe://varwof.com/agent/known-a"},
	}
	denied := RunAccessPipeline([]*x509.Certificate{spiffeTestCert("spiffe://varwof.com/agent/other")}, cfg)
	if denied.Granted {
		t.Fatal("expected denial when SPIFFE ID not in allowlist")
	}
	allowed := RunAccessPipeline([]*x509.Certificate{spiffeTestCert("spiffe://varwof.com/agent/known-a")}, cfg)
	if !allowed.Granted {
		t.Fatalf("expected allow when SPIFFE ID in allowlist, got: %s", allowed.DenyReason)
	}
}

func TestAuditEntrySPIFFEID(t *testing.T) {
	cert := spiffeTestCert("spiffe://varwof.com/agent/audited-a")
	entry := NewAuditEntryFromConn("10.0.0.1:1234", "m", "t", cert)
	if entry.SPIFFEID != "spiffe://varwof.com/agent/audited-a" {
		t.Errorf("audit SPIFFEID = %q", entry.SPIFFEID)
	}
	denied := NewAuditEntryDenied("10.0.0.1:1234", "m", "t", "nope", cert)
	if denied.SPIFFEID != "spiffe://varwof.com/agent/audited-a" {
		t.Errorf("denied audit SPIFFEID = %q", denied.SPIFFEID)
	}
}

// --- RFC 7555 hardening: case-insensitive trust domain + charset ---

func TestParseSPIFFEID_TrustDomainLowercase(t *testing.T) {
	cases := []struct{ in, td, path string }{
		{"spiffe://VARWOF.com/agent/svc", "varwof.com", "/agent/svc"},
		{"spiffe://Prod.US-East-1.Example.com/ns/Svc", "prod.us-east-1.example.com", "/ns/Svc"},
		{"spiffe://EXAMPLE.COM", "example.com", "/"},
	}
	for _, tc := range cases {
		s, err := ParseSPIFFEID(tc.in)
		if err != nil {
			t.Fatalf("ParseSPIFFEID(%q): %v", tc.in, err)
		}
		if s.TrustDomain != tc.td {
			t.Fatalf("ParseSPIFFEID(%q) TrustDomain=%q, want %q", tc.in, s.TrustDomain, tc.td)
		}
		// Path segments are case-sensitive and preserved verbatim.
		if s.Path != tc.path {
			t.Fatalf("ParseSPIFFEID(%q) Path=%q, want %q", tc.in, s.Path, tc.path)
		}
	}
}

func TestParseSPIFFEID_CharsetReject(t *testing.T) {
	for _, in := range []string{
		"spiffe://exa!mple.com/x",
		"spiffe://exa~mple.com/x",
	} {
		if _, err := ParseSPIFFEID(in); err == nil {
			t.Fatalf("ParseSPIFFEID(%q): expected charset rejection", in)
		}
	}
}

func TestParseSPIFFEID_CharsetAllow(t *testing.T) {
	// '_' and '-' are valid trust-domain characters per RFC 7555 §2.1.
	s, err := ParseSPIFFEID("spiffe://my_svc.prod-1.example.com/agent/x")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.TrustDomain != "my_svc.prod-1.example.com" {
		t.Fatalf("TrustDomain=%q", s.TrustDomain)
	}
}

func TestValidTrustDomainCharset(t *testing.T) {
	valid := []string{"example.com", "a-b.com", "a_b.example.org", "x.y.z"}
	for _, td := range valid {
		if !validTrustDomainCharset(td) {
			t.Fatalf("validTrustDomainCharset(%q) = false, want true", td)
		}
	}
	invalid := []string{"VARWOF.com", "exa!mple.com", "exa~mple.com", "exa/mple.com", "exa mple.com", "exa:port.com"}
	for _, td := range invalid {
		if validTrustDomainCharset(td) {
			t.Fatalf("validTrustDomainCharset(%q) = true, want false", td)
		}
	}
}

func TestCanonicalSPIFFEID(t *testing.T) {
	cases := []struct{ in, want string }{
		{"spiffe://VARWOF.com/agent/svc", "spiffe://varwof.com/agent/svc"},
		{"spiffe://VARWOF.com", "spiffe://varwof.com"},
		{"spiffe://Varwof.COM/agent/Svc-A", "spiffe://varwof.com/agent/Svc-A"},
		{"spiffe://varwof.com/agent/svc", "spiffe://varwof.com/agent/svc"},
		{"https://VARWOF.com/x", "https://VARWOF.com/x"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := canonicalSPIFFEID(tc.in); got != tc.want {
			t.Fatalf("canonicalSPIFFEID(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestVerifySPIFFESAN_CaseInsensitiveTrustDomain(t *testing.T) {
	cert := spiffeTestCert("spiffe://VARWOF.com/agent/svc-a")
	if !VerifySPIFFESAN(cert, "spiffe://varwof.com/agent/svc-a") {
		t.Fatal("expected case-variant of the SAN to verify against the canonical ID")
	}
	if VerifySPIFFESAN(cert, "spiffe://varwof.com/agent/other") {
		t.Fatal("path mismatch must not verify")
	}
	if VerifySPIFFESAN(cert, "spiffe://evil.com/agent/svc-a") {
		t.Fatal("different trust domain must not verify")
	}
	if VerifySPIFFESAN(cert, "") {
		t.Fatal("empty expected ID must not verify")
	}
}

func TestPipelineSPIFFETrustDomainCaseVariant(t *testing.T) {
	// The certificate carries an uppercase variant of a trust domain that is
	// configured lowercase: RFC 7555 case-insensitivity must admit it.
	cfg := &PipelineConfig{SPIFFETrustDomain: "varwof.com"}
	allowed := RunAccessPipeline([]*x509.Certificate{spiffeTestCert("spiffe://VARWOF.COM/agent/x")}, cfg)
	if !allowed.Granted {
		t.Fatalf("expected case-variant trust domain to be admitted, got: %s", allowed.DenyReason)
	}

	// Uppercase configured trust domain vs lowercase certificate.
	cfgUp := &PipelineConfig{SPIFFETrustDomain: "VARWOF.COM"}
	allowedUp := RunAccessPipeline([]*x509.Certificate{spiffeTestCert("spiffe://varwof.com/agent/x")}, cfgUp)
	if !allowedUp.Granted {
		t.Fatalf("expected lowercase cert vs uppercase config to be admitted, got: %s", allowedUp.DenyReason)
	}

	// A genuinely different domain in either case must still be denied.
	denied := RunAccessPipeline([]*x509.Certificate{spiffeTestCert("spiffe://Evil.com/agent/x")}, cfg)
	if denied.Granted {
		t.Fatal("expected denial for a different trust domain")
	}
}

func TestPipelineSPIFFEAllowedListCaseInsensitive(t *testing.T) {
	cfg := &PipelineConfig{AllowedSPIFFEIDs: []string{"spiffe://varwof.com/agent/known-a"}}

	// Uppercase trust-domain variant of an allowlisted ID must be admitted.
	allowed := RunAccessPipeline([]*x509.Certificate{spiffeTestCert("spiffe://VARWOF.com/agent/known-a")}, cfg)
	if !allowed.Granted {
		t.Fatalf("expected case-variant allowlist match, got: %s", allowed.DenyReason)
	}

	// Allowlist entries written in a case variant must also match lowercase SANs.
	cfgUp := &PipelineConfig{AllowedSPIFFEIDs: []string{"spiffe://VARWOF.com/agent/known-a"}}
	allowedUp := RunAccessPipeline([]*x509.Certificate{spiffeTestCert("spiffe://varwof.com/agent/known-a")}, cfgUp)
	if !allowedUp.Granted {
		t.Fatalf("expected lowercase SAN vs uppercase allowlist entry, got: %s", allowedUp.DenyReason)
	}

	// Paths stay case-sensitive: a path case-variant must be denied.
	deniedPath := RunAccessPipeline([]*x509.Certificate{spiffeTestCert("spiffe://varwof.com/Agent/Known-A")}, cfg)
	if deniedPath.Granted {
		t.Fatal("expected denial for a path case-variant (paths are case-sensitive)")
	}

	// A real different path and a different trust domain must both be denied.
	deniedOther := RunAccessPipeline([]*x509.Certificate{spiffeTestCert("spiffe://varwof.com/agent/other")}, cfg)
	if deniedOther.Granted {
		t.Fatal("expected denial when ID is not allowlisted")
	}
	deniedDomain := RunAccessPipeline([]*x509.Certificate{spiffeTestCert("spiffe://evil.com/agent/known-a")}, cfg)
	if deniedDomain.Granted {
		t.Fatal("expected denial when trust domain is not allowlisted")
	}
}
