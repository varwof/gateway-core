// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ocsp"
)

// ocspHTTPClient is an HTTP client with a timeout for OCSP requests.
// A hung OCSP responder must not block gateway goroutines indefinitely.
var ocspHTTPClient = &http.Client{Timeout: 10 * time.Second}

// AIAOID is the Authority Information Access method OID.
// OCSPOID is the OCSP responder OID.
var (
	AIAOID  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	OCSPOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
)

type accessDescription struct {
	Method   asn1.ObjectIdentifier
	Location asn1.RawValue
}

// OCSPCache is an OCSP response cache with request coalescing.
type OCSPCache struct {
	mu         sync.RWMutex
	entries    map[string]*ocspCacheEntry
	ttl        time.Duration
	fallback   string
	translator Translator
	lang       string
	// inflightMu guards inflight independently from mu (which guards entries)
	// to avoid a lock-ordering deadlock between the read path (RLock) and the
	// coalescing wait path (Lock + <-wait) on the same RWMutex.
	inflightMu sync.Mutex
	inflight   map[string]chan struct{}
}

type ocspCacheEntry struct {
	status    int
	revokedAt time.Time
	cachedAt  time.Time
}

// OCSPFallbackAllow/Deny/CRL are OCSP fallback policy constants.
const (
	OCSPFallbackAllow = "allow"
	OCSPFallbackDeny  = "deny"
	OCSPFallbackCRL   = "crl"
)

// NewOCSPCache creates an OCSP cache instance.
func NewOCSPCache(ttl time.Duration, fallback string, translator Translator, lang string) *OCSPCache {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	switch fallback {
	case OCSPFallbackAllow, OCSPFallbackDeny, OCSPFallbackCRL:
	default:
		fallback = OCSPFallbackDeny
	}
	return &OCSPCache{
		entries:    make(map[string]*ocspCacheEntry),
		ttl:        ttl,
		fallback:   fallback,
		translator: translator,
		lang:       lang,
		inflight:   make(map[string]chan struct{}),
	}
}

// ExtractOCSPURL extracts the OCSP URL from the certificate's AIA extension.
func ExtractOCSPURL(cert *x509.Certificate) string {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(AIAOID) {
			var descs []accessDescription
			if _, err := asn1.Unmarshal(ext.Value, &descs); err != nil {
				continue
			}
			for _, desc := range descs {
				if desc.Method.Equal(OCSPOID) {
					if desc.Location.Tag == 6 && desc.Location.Class == asn1.ClassContextSpecific {
						return string(desc.Location.Bytes)
					}
				}
			}
		}
	}
	return ""
}

// Check queries the OCSP responder and caches the result.
func (c *OCSPCache) Check(cert, issuer *x509.Certificate) error {
	ocspURL := ExtractOCSPURL(cert)
	if ocspURL == "" {
		return nil
	}

	key := fmt.Sprintf("%s|%s", cert.SerialNumber.Text(16), ocspURL)

	c.mu.RLock()
	entry, hit := c.entries[key]
	if hit && time.Since(entry.cachedAt) < c.ttl {
		c.mu.RUnlock()
		switch entry.status {
		case ocsp.Good:
			return nil
		case ocsp.Revoked:
			return fmt.Errorf("certificate revoked by OCSP at %s", entry.revokedAt.Format(time.RFC3339))
		default:
			return fmt.Errorf("certificate status unknown by OCSP")
		}
	}
	// miss (or stale): must release the read lock before fetching
	c.mu.RUnlock()

	// B12 — request coalescing: register as the fetcher under a single lock
	// (inflightMu, separate from the cache RWMutex) so the check-and-set is
	// atomic (no two goroutines both observe !inFlight and both fetch the same
	// key), without risking a deadlock between the read path and the wait path.
	c.inflightMu.Lock()
	if wait, inFlight := c.inflight[key]; inFlight {
		c.inflightMu.Unlock()
		<-wait
		// re-check cache after the other goroutine finished
		c.mu.RLock()
		entry, hit = c.entries[key]
		c.mu.RUnlock()
		if hit {
			switch entry.status {
			case ocsp.Good:
				return nil
			case ocsp.Revoked:
				return fmt.Errorf("certificate revoked by OCSP at %s", entry.revokedAt.Format(time.RFC3339))
			default:
				return fmt.Errorf("certificate status unknown by OCSP")
			}
		}
		return c.fallbackErr("OCSP request completed but no cache entry")
	}
	ch := make(chan struct{})
	c.inflight[key] = ch
	c.inflightMu.Unlock()

	defer func() {
		c.inflightMu.Lock()
		delete(c.inflight, key)
		c.inflightMu.Unlock()
		close(ch)
	}()

	// B26 — issuer guard: ocsp.CreateRequest requires the issuer certificate to
	// build the request (issuer name + public key). When the client presents only
	// the leaf (single-cert chain), issuer is nil and must not reach CreateRequest.
	// Resolve via the fallback policy instead (allow/deny/crl) — unverifiable
	// OCSP status must not panic the gateway.
	if issuer == nil {
		return c.fallbackErr("OCSP issuer certificate unavailable for %s", cert.Subject.CommonName)
	}

	ocspReq, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return fmt.Errorf("create OCSP request: %w", err)
	}

	httpResp, err := ocspHTTPClient.Post(ocspURL, "application/ocsp-request", bytes.NewReader(ocspReq))
	if err != nil {
		return c.fallbackErr("OCSP request failed: %v", err)
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return c.fallbackErr("read OCSP response: %v", err)
	}

	resp, err := ocsp.ParseResponseForCert(body, cert, issuer)
	if err != nil {
		return c.fallbackErr("parse OCSP response: %v", err)
	}

	entry = &ocspCacheEntry{
		status:    resp.Status,
		revokedAt: resp.RevokedAt,
		cachedAt:  time.Now(),
	}

	c.mu.Lock()
	c.entries[key] = entry
	c.mu.Unlock()

	switch resp.Status {
	case ocsp.Good:
		return nil
	case ocsp.Revoked:
		return fmt.Errorf("certificate revoked by OCSP at %s", resp.RevokedAt.Format(time.RFC3339))
	default:
		return fmt.Errorf("certificate status unknown by OCSP (status %d)", resp.Status)
	}
}

func (c *OCSPCache) fallbackErr(format string, args ...interface{}) error {
	msg := fmt.Sprintf(format, args...)
	// Translator is optional (may be nil in tests / embedded usage); fall back to
	// returning the raw message key when not set.
	t := func(lang, key string, args ...any) string { return key }
	if c.translator != nil {
		t = c.translator.T
	}
	switch c.fallback {
	case OCSPFallbackAllow:
		fmt.Printf(t(c.lang, "ocsp.fallback_allow")+"\n", msg)
		return nil
	case OCSPFallbackCRL:
		fmt.Printf(t(c.lang, "ocsp.fallback_crl")+"\n", msg)
		return nil
	default:
		s := fmt.Sprintf(t(c.lang, "ocsp.fallback_deny"), msg)
		return errors.New(s)
	}
}

// Stats returns the count of good/revoked entries in the OCSP cache.
func (c *OCSPCache) Stats() (int, int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var good, revoked int
	for _, e := range c.entries {
		switch e.status {
		case ocsp.Good:
			good++
		case ocsp.Revoked:
			revoked++
		}
	}
	return good, revoked
}

// Flush clears the OCSP cache.
func (c *OCSPCache) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*ocspCacheEntry)
}

// FetchOCSPResponseRaw fetches the raw OCSP response bytes.
func FetchOCSPResponseRaw(cert, issuer *x509.Certificate, ocspURL string) ([]byte, error) {
	req, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return nil, fmt.Errorf("create OCSP request: %w", err)
	}
	httpResp, err := ocspHTTPClient.Post(ocspURL, "application/ocsp-request", bytes.NewReader(req))
	if err != nil {
		return nil, fmt.Errorf("OCSP request: %w", err)
	}
	defer httpResp.Body.Close()
	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("read OCSP response: %w", err)
	}
	return body, nil
}

// StartOCSPStapling starts the OCSP stapling background refresh.
func StartOCSPStapling(tlsCert *tls.Certificate, cfg *tls.Config, caCertFile string, stopCh <-chan struct{}, translator Translator, lang string) {
	if tlsCert == nil || len(tlsCert.Certificate) == 0 || cfg == nil {
		return
	}
	leaf := tlsCert.Leaf
	if leaf == nil {
		var err error
		leaf, err = x509.ParseCertificate(tlsCert.Certificate[0])
		if err != nil {
			return
		}
	}
	ocspURL := ExtractOCSPURL(leaf)
	if ocspURL == "" {
		return
	}
	issuer, err := LoadCACert(caCertFile)
	if err != nil {
		return
	}

	var certAtomic atomic.Value
	certAtomic.Store(tlsCert)
	cfg.GetCertificate = func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return certAtomic.Load().(*tls.Certificate), nil
	}

	refresh := func() {
		staple, err := FetchOCSPResponseRaw(leaf, issuer, ocspURL)
		if err != nil {
			fmt.Printf(translator.T(lang, "ocsp_stapling.refresh_error"), leaf.Subject.CommonName, err)
			return
		}
		if _, err := ocsp.ParseResponse(staple, issuer); err != nil {
			return
		}
		newCert := *tlsCert
		newCert.OCSPStaple = staple
		certAtomic.Store(&newCert)
	}

	refresh()
	go func() {
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				refresh()
			case <-stopCh:
				return
			}
		}
	}()
}
