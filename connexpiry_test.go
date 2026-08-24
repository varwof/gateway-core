package gw

import (
	"crypto/x509"
	"math/big"
	"sync"
	"testing"
	"time"
)

// testExpiryCert constructs a test certificate with only serial number and validity period.
func testExpiryCert(serial int64, notBefore, notAfter time.Time) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
}

func TestConnExpiryRegistryRegisterUnregister(t *testing.T) {
	reg := NewConnExpiryRegistry()
	now := time.Now()
	cert := testExpiryCert(0x1234, now.Add(-time.Hour), now.Add(time.Hour))

	done1 := reg.Register("0x1234", cert)
	done2 := reg.Register("0x1234", cert)
	if reg.Len() != 1 {
		t.Fatalf("Len = %d, want 1", reg.Len())
	}
	if got := reg.Connections("0x1234"); got != 2 {
		t.Fatalf("Connections = %d, want 2", got)
	}
	done1()
	if got := reg.Connections("0x1234"); got != 1 {
		t.Fatalf("Connections after done1 = %d, want 1", got)
	}
	// Entry still exists (active connections remain).
	if reg.Len() != 1 {
		t.Fatalf("Len after done1 = %d, want 1", reg.Len())
	}
	done2()
	if reg.Len() != 0 {
		t.Fatalf("Len after done2 = %d, want 0", reg.Len())
	}
	// done is idempotent.
	done2()
	if reg.Len() != 0 {
		t.Fatalf("Len after idempotent done2 = %d, want 0", reg.Len())
	}
}

func TestConnExpiryRegistryUnregister(t *testing.T) {
	reg := NewConnExpiryRegistry()
	now := time.Now()
	cert := testExpiryCert(1, now.Add(-time.Hour), now.Add(time.Hour))
	done := reg.Register("SER-1", cert)
	_ = done
	reg.Unregister("SER-1")
	if reg.Len() != 0 {
		t.Fatalf("Len after Unregister = %d, want 0", reg.Len())
	}
	// Untracked serial number.
	reg.Unregister("never-registered")
	if reg.Len() != 0 {
		t.Fatalf("Len = %d, want 0", reg.Len())
	}
}

// TestConnExpiryRegistryExample4 reproduces patent Example 4 (P2-D-04):
// Certificate A (0x1234) with three connections C1/C2/C3 → renewed to certificate B (0x5678)
// → UpdateCert("0x1234", certB) → all three disruption scenarios skip revocation.
func TestConnExpiryRegistryExample4(t *testing.T) {
	reg := NewConnExpiryRegistry()
	now := time.Now()

	certA := testExpiryCert(0x1234, now.Add(-time.Hour), now.Add(30*time.Minute))
	certB := testExpiryCert(0x5678, now, now.Add(time.Hour))

	// Three connections C1/C2/C3 using old certificate A.
	doneC1 := reg.Register("0x1234", certA)
	doneC2 := reg.Register("0x1234", certA)
	doneC3 := reg.Register("0x1234", certA)
	if got := reg.Connections("0x1234"); got != 3 {
		t.Fatalf("Connections = %d, want 3", got)
	}

	// Renewal succeeded: UpdateCert sets renewed flag to true and updates the certificate pointer.
	if !reg.UpdateCert("0x1234", certB) {
		t.Fatal("UpdateCert returned false for tracked serial")
	}
	if !reg.Renewed("0x1234") {
		t.Fatal("renewed marker not set after UpdateCert")
	}
	if got := reg.Certificate("0x1234"); got != certB {
		t.Fatal("certificate pointer not updated after UpdateCert")
	}
	// Certificate A is not expired but has been renewed → should skip revocation.
	if !reg.ShouldSkipRevoke("0x1234") {
		t.Fatal("ShouldSkipRevoke should be true after renewal")
	}

	// Three disruption scenarios: C1/C2/C3 each close, all skip revocation.
	for _, done := range []func(){doneC1, doneC2, doneC3} {
		if !reg.ShouldSkipRevoke("0x1234") {
			t.Fatal("ShouldSkipRevoke should stay true while renewed")
		}
		done()
	}
	// Entry is pruned after all connections close.
	if reg.Len() != 0 {
		t.Fatalf("Len after all connections closed = %d, want 0", reg.Len())
	}
	// After entry is pruned, revocation is no longer affected (reverts to default behavior).
	if reg.ShouldSkipRevoke("0x1234") {
		t.Fatal("ShouldSkipRevoke should be false after entry pruned")
	}
}

func TestConnExpiryRegistryShouldSkipRevoke(t *testing.T) {
	now := time.Now()

	t.Run("not renewed and not expired → revoke", func(t *testing.T) {
		reg := NewConnExpiryRegistry()
		cert := testExpiryCert(0x100, now.Add(-time.Hour), now.Add(time.Hour))
		reg.Register("0x100", cert)
		if reg.ShouldSkipRevoke("0x100") {
			t.Fatal("expected false (should revoke)")
		}
	})

	t.Run("expired cert → skip", func(t *testing.T) {
		reg := NewConnExpiryRegistry()
		cert := testExpiryCert(0x101, now.Add(-2*time.Hour), now.Add(-time.Hour))
		reg.Register("0x101", cert)
		if !reg.ShouldSkipRevoke("0x101") {
			t.Fatal("expected true (expired, skip revoke)")
		}
	})

	t.Run("untracked serial → false", func(t *testing.T) {
		reg := NewConnExpiryRegistry()
		if reg.ShouldSkipRevoke("0x999") {
			t.Fatal("untracked serial should not skip revoke")
		}
	})

	t.Run("UpdateCert on untracked → false", func(t *testing.T) {
		reg := NewConnExpiryRegistry()
		cert := testExpiryCert(1, now, now.Add(time.Hour))
		if reg.UpdateCert("0x000", cert) {
			t.Fatal("UpdateCert should return false for untracked serial")
		}
	})
}

func TestConnExpiryRegistryStartExpiryLoop(t *testing.T) {
	reg := NewConnExpiryRegistry()
	now := time.Now()

	// Expired → will be pruned.
	expired := testExpiryCert(1, now.Add(-2*time.Hour), now.Add(-time.Hour))
	reg.Register("expired-1", expired)
	// Not expired → retained.
	alive := testExpiryCert(2, now.Add(-time.Hour), now.Add(time.Hour))
	reg.Register("alive-1", alive)

	stopCh := make(chan struct{})
	stop := reg.StartExpiryLoop(10*time.Millisecond, stopCh)
	defer stop()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if reg.Len() == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if reg.Len() != 1 {
		t.Fatalf("Len = %d, want 1 (only expired pruned)", reg.Len())
	}
	if reg.Certificate("alive-1") == nil {
		t.Fatal("alive entry should remain")
	}
	if reg.Certificate("expired-1") != nil {
		t.Fatal("expired entry should be pruned")
	}

	// Expired entries are pruned even with active connections (P2-A-16: transitional state expires naturally).
	now2 := time.Now()
	expiredWithConn := testExpiryCert(3, now2.Add(-2*time.Hour), now2.Add(-time.Hour))
	done := reg.Register("expired-conn", expiredWithConn)
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if reg.Certificate("expired-conn") == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if reg.Certificate("expired-conn") != nil {
		t.Fatal("expired entry with active connection should be pruned")
	}
	done()
}

func TestConnExpiryRegistryNilReceiver(t *testing.T) {
	var reg *ConnExpiryRegistry
	done := reg.Register("x", nil)
	done() // noop, must not panic
	if reg.UpdateCert("x", nil) {
		t.Fatal("nil UpdateCert should return false")
	}
	reg.Unregister("x") // no panic
	if reg.ShouldSkipRevoke("x") {
		t.Fatal("nil ShouldSkipRevoke should be false")
	}
	if reg.Connections("x") != 0 {
		t.Fatal("nil Connections should be 0")
	}
	if reg.Renewed("x") {
		t.Fatal("nil Renewed should be false")
	}
	if reg.Certificate("x") != nil {
		t.Fatal("nil Certificate should be nil")
	}
	if reg.Len() != 0 {
		t.Fatal("nil Len should be 0")
	}
	if reg.SerialNumbers() != nil {
		t.Fatal("nil SerialNumbers should be nil")
	}
	stop := reg.StartExpiryLoop(0, nil)
	if stop == nil {
		t.Fatal("nil StartExpiryLoop should return a stop func")
	}
}

func TestConnExpiryRegistryConcurrent(t *testing.T) {
	reg := NewConnExpiryRegistry()
	now := time.Now()
	cert := testExpiryCert(42, now.Add(-time.Hour), now.Add(time.Hour))

	const goroutines = 20
	const perG = 50
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				done := reg.Register("0x42", cert)
				reg.UpdateCert("0x42", cert)
				reg.ShouldSkipRevoke("0x42")
				done()
			}
		}()
	}
	wg.Wait()
	if reg.Len() != 0 {
		t.Fatalf("Len after concurrent register/unregister = %d, want 0", reg.Len())
	}
}
