// ConnExpiryRegistry — Certificate serial number → active connection/renewal status registry
//
// Corresponds to specification P2-A-14/15/16 and Example 4 (P2-D-04):
//   - Uses certificate serial number as key, storing *atomic.Pointer[x509.Certificate] and *atomic.Bool renewal flag;
//   - UpdateCert() updates the certificate and sets the renewal flag to true;
//   - When connection closure triggers revocation evaluation, ShouldSkipRevoke() reads the renewal flag: true → skip revocation;
//   - The expiry check goroutine polls every 5 seconds to clean up expired entries with no active connections
//     (transitional certificates expire naturally, no explicit revocation, no CRL entry).

package gw

import (
	"crypto/x509"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultConnExpiryCheckInterval is the default polling interval for the expiry check goroutine (P2-A-14: 5 seconds).
const DefaultConnExpiryCheckInterval = 5 * time.Second

// connExpiryEntry records the runtime state of a single certificate serial number.
type connExpiryEntry struct {
	cert    atomic.Pointer[x509.Certificate]
	renewed atomic.Bool
	conns   atomic.Int64
}

// ConnExpiryRegistry tracks active connection certificate validity and renewal flags
// keyed by certificate serial number.
// Thread-safe (sync.RWMutex protects the map; certificate and renewal flag are atomic reads/writes).
type ConnExpiryRegistry struct {
	mu      sync.RWMutex
	entries map[string]*connExpiryEntry
}

// NewConnExpiryRegistry creates an empty ConnExpiryRegistry.
func NewConnExpiryRegistry() *ConnExpiryRegistry {
	return &ConnExpiryRegistry{entries: make(map[string]*connExpiryEntry)}
}

// Register records an active connection (serial is the normalized hex serial number) and returns
// a deregistration function to be called when the connection closes. Multiple Register calls
// for the same serial increment the concurrent count; the renewal flag is not reset by
// new connection registration. A nil receiver returns a no-op deregistration function.
func (r *ConnExpiryRegistry) Register(serial string, cert *x509.Certificate) func() {
	if r == nil {
		return func() {}
	}
	r.mu.Lock()
	e, ok := r.entries[serial]
	if !ok {
		e = &connExpiryEntry{}
		r.entries[serial] = e
	}
	if cert != nil {
		e.cert.Store(cert)
	}
	e.conns.Add(1)
	r.mu.Unlock()

	removed := false
	return func() {
		if removed {
			return
		}
		removed = true
		// Remove entry when count reaches zero (transitional certificate expiry is natural cleanup, no CRL entry).
		if r == nil {
			return
		}
		e.conns.Add(-1)
		if e.conns.Load() <= 0 {
			r.mu.Lock()
			if cur, ok := r.entries[serial]; ok && cur == e && e.conns.Load() <= 0 {
				delete(r.entries, serial)
			}
			r.mu.Unlock()
		}
	}
}

// UpdateCert updates the certificate and sets the renewal flag to true after successful renewal (P2-A-15).
// Returns false if the serial number is not tracked.
func (r *ConnExpiryRegistry) UpdateCert(serial string, cert *x509.Certificate) bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	e, ok := r.entries[serial]
	r.mu.RUnlock()
	if !ok {
		return false
	}
	if cert != nil {
		e.cert.Store(cert)
	}
	e.renewed.Store(true)
	return true
}

// Unregister forcefully removes a serial number entry (P2-A-14 Unregister()).
func (r *ConnExpiryRegistry) Unregister(serial string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	delete(r.entries, serial)
	r.mu.Unlock()
}

// ShouldSkipRevoke reads the renewal flag and certificate validity during connection-closure
// revocation evaluation (P2-A-15): renewal flag true or certificate already expired → skip
// revocation; otherwise returns false.
// Untracked serial numbers return false (maintaining default revocation behavior).
func (r *ConnExpiryRegistry) ShouldSkipRevoke(serial string) bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	e, ok := r.entries[serial]
	r.mu.RUnlock()
	if !ok {
		return false
	}
	if e.renewed.Load() {
		return true
	}
	cert := e.cert.Load()
	if cert == nil {
		return false
	}
	return !NeedRevoke(cert)
}

// Connections returns the current active connection count for a serial number (P2-A-16 transitional state concurrent count inheritance).
func (r *ConnExpiryRegistry) Connections(serial string) int64 {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	e, ok := r.entries[serial]
	r.mu.RUnlock()
	if !ok {
		return 0
	}
	return e.conns.Load()
}

// Renewed queries the renewal flag for a serial number.
func (r *ConnExpiryRegistry) Renewed(serial string) bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	e, ok := r.entries[serial]
	r.mu.RUnlock()
	if !ok {
		return false
	}
	return e.renewed.Load()
}

// Certificate reads the current certificate for a serial number (atomic pointer, may be nil).
func (r *ConnExpiryRegistry) Certificate(serial string) *x509.Certificate {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	e, ok := r.entries[serial]
	r.mu.RUnlock()
	if !ok {
		return nil
	}
	return e.cert.Load()
}

// StartExpiryLoop starts the expiry check goroutine, polling every interval (<=0 uses default 5 seconds),
// cleaning up expired entries with no active connections (transitional certificates expire naturally,
// no explicit revocation). Returns a callable stop function (can also be stopped via external stopCh).
func (r *ConnExpiryRegistry) StartExpiryLoop(interval time.Duration, stopCh <-chan struct{}) func() {
	if interval <= 0 {
		interval = DefaultConnExpiryCheckInterval
	}
	internal := make(chan struct{})
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		defer close(done)
		for {
			select {
			case <-internal:
				return
			case <-stopCh:
				return
			case <-ticker.C:
				r.cleanupExpired()
			}
		}
	}()
	return func() {
		select {
		case <-internal:
		default:
			close(internal)
		}
		<-done
	}
}

// cleanupExpired cleans up entries with expired certificates (P2-A-16 transitional state:
// expires naturally, no explicit revocation, no CRL entry). Even entries with active connections
// are cleaned up — revocation of expired certificates should be skipped (Revoker's inner
// NeedRevoke handles the fallback), and TLS no longer accepts expired certificates.
func (r *ConnExpiryRegistry) cleanupExpired() {
	if r == nil {
		return
	}
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	for serial, e := range r.entries {
		cert := e.cert.Load()
		if cert == nil || now.After(cert.NotAfter) {
			delete(r.entries, serial)
			slog.Debug("conn-expiry: pruned expired entry", "serial", serial)
		}
	}
}

// Len returns the number of tracked serial numbers.
func (r *ConnExpiryRegistry) Len() int {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.entries)
}

// SerialNumbers returns all tracked serial numbers (for testing/metrics).
func (r *ConnExpiryRegistry) SerialNumbers() []string {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.entries))
	for s := range r.entries {
		out = append(out, s)
	}
	return out
}
