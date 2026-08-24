package gw

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func testCertWithOU(t *testing.T, ous []string) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         "test",
			OrganizationalUnit: ous,
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(1 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestExtractRoles(t *testing.T) {
	tests := []struct {
		name  string
		ous   []string
		wants []string
	}{
		{
			name:  "single role",
			ous:   []string{"gateway:admin"},
			wants: []string{"gateway:admin"},
		},
		{
			name:  "multiple roles",
			ous:   []string{"gateway:admin", "gateway:mysql-prod"},
			wants: []string{"gateway:admin", "gateway:mysql-prod"},
		},
		{
			name:  "non-gateway OU ignored",
			ous:   []string{"engineering", "gateway:redis-cache"},
			wants: []string{"gateway:redis-cache"},
		},
		{
			name:  "no roles",
			ous:   []string{"engineering", "finance"},
			wants: nil,
		},
		{
			name:  "empty",
			ous:   []string{},
			wants: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := testCertWithOU(t, tt.ous)
			roles := ExtractRoles(cert)
			if len(roles) != len(tt.wants) {
				t.Errorf("got %d roles, want %d: %v", len(roles), len(tt.wants), roles)
				return
			}
			for i, want := range tt.wants {
				if roles[i] != want {
					t.Errorf("roles[%d] = %q, want %q", i, roles[i], want)
				}
			}
		})
	}
}

func TestCheckRole(t *testing.T) {
	tests := []struct {
		name    string
		roles   []string
		allowed []string
		want    bool
	}{
		{
			name:    "direct match",
			roles:   []string{"gateway:admin"},
			allowed: []string{"gateway:admin"},
			want:    true,
		},
		{
			name:    "wildcard",
			roles:   []string{"gateway:*"},
			allowed: []string{"gateway:mysql-prod"},
			want:    true,
		},
		{
			name:    "no match",
			roles:   []string{"gateway:redis-cache"},
			allowed: []string{"gateway:mysql-prod"},
			want:    false,
		},
		{
			name:    "multiple roles one matches",
			roles:   []string{"gateway:redis-cache", "gateway:admin"},
			allowed: []string{"gateway:admin"},
			want:    true,
		},
		{
			name:    "empty roles",
			roles:   []string{},
			allowed: []string{"gateway:admin"},
			want:    false,
		},
		{
			name:    "empty allowed",
			roles:   []string{"gateway:admin"},
			allowed: []string{},
			want:    false,
		},
		{
			name:    "wildcard with multiple allowed",
			roles:   []string{"gateway:*"},
			allowed: []string{"gateway:anything"},
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckRole(tt.roles, tt.allowed)
			if got != tt.want {
				t.Errorf("CheckRole(%v, %v) = %v, want %v", tt.roles, tt.allowed, got, tt.want)
			}
		})
	}
}

func TestNewOfflineRBAC_NilRoles(t *testing.T) {
	r := NewOfflineRBAC(nil)
	if r == nil {
		t.Fatal("expected non-nil")
	}
	if r.CheckRole([]string{"gateway:admin"}) {
		t.Fatal("nil roles should not match")
	}
}

func TestNewOfflineRBAC_EmptyRoles(t *testing.T) {
	r := NewOfflineRBAC([]string{})
	if r.CheckRole([]string{"gateway:admin"}) {
		t.Fatal("empty roles should not match")
	}
}

func TestOfflineRBAC_AdminAllowed(t *testing.T) {
	r := NewOfflineRBAC([]string{"gateway:admin"})
	if !r.CheckRole([]string{"gateway:admin"}) {
		t.Fatal("admin should match admin")
	}
	if r.CheckRole([]string{"gateway:ops"}) {
		t.Fatal("admin should not match ops")
	}
}

func TestOfflineRBAC_Wildcard(t *testing.T) {
	r := NewOfflineRBAC([]string{"gateway:*"})
	if !r.CheckRole([]string{"gateway:admin"}) {
		t.Fatal("wildcard should match admin")
	}
	if !r.CheckRole([]string{"gateway:anything"}) {
		t.Fatal("wildcard should match anything")
	}
}

func TestOfflineRBAC_FromCert(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{
			OrganizationalUnit: []string{"gateway:ops", "gateway:audit"},
		},
	}
	r := NewOfflineRBACFromCert(cert)
	if !r.CheckRole([]string{"gateway:ops"}) {
		t.Fatal("ops should match")
	}
	if !r.CheckRole([]string{"gateway:audit"}) {
		t.Fatal("audit should match")
	}
	if r.CheckRole([]string{"gateway:admin"}) {
		t.Fatal("admin should not match")
	}
}

func TestOfflineRBAC_FromCertNoRoles(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{OrganizationalUnit: []string{"engineering"}},
	}
	r := NewOfflineRBACFromCert(cert)
	if r.CheckRole([]string{"gateway:admin"}) {
		t.Fatal("no gw roles should not match")
	}
}
