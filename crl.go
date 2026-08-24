package gw

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// Translator is the internationalization translation interface.
type Translator interface {
	T(lang, key string, args ...any) string
}

// CRLCache is a CRL cache that supports periodic refresh and forced reload.
type CRLCache struct {
	caCert      *x509.Certificate
	caDN        string
	url         string
	refreshSec  time.Duration
	translator  Translator
	lang        string
	mu          sync.RWMutex
	revoked     map[string]bool
	thisUpdate  time.Time
	nextUpdate  time.Time
	lastRefresh time.Time
	client      *http.Client
	// refreshMu serializes the entire refresh (fetch + commit). Previously only
	// commit was under mu; periodic refresh from Start and concurrent ForceRefresh
	// could fetch then commit out of order — two CRLs with identical thisUpdate
	// would trigger false replay detection (flaky rel test). After serialization,
	// the later request always gets a newer thisUpdate.
	refreshMu sync.Mutex
}

// NewCRLCache creates a CRL cache instance.
func NewCRLCache(caCert *x509.Certificate, url string, refreshSec int, translator Translator, lang string) *CRLCache {
	d := time.Duration(refreshSec) * time.Second
	if d <= 0 {
		d = 5 * time.Minute
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	return &CRLCache{
		caCert:     caCert,
		caDN:       caCert.Subject.String(),
		url:        url,
		refreshSec: d,
		translator: translator,
		lang:       lang,
		revoked:    make(map[string]bool),
		client:     &http.Client{Timeout: 30 * time.Second, Transport: tr},
	}
}

// Start starts the CRL periodic refresh loop.
func (c *CRLCache) Start(stop <-chan struct{}) {
	for {
		if err := c.refresh(); err != nil {
			c.printf("crl.initial_refresh_failed", err)
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}
		break
	}
	ticker := time.NewTicker(c.refreshSec)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := c.refresh(); err != nil {
				c.printf("crl.refresh_failed", err)
			}
		case <-stop:
			return
		}
	}
}

func (c *CRLCache) printf(key string, args ...any) {
	msg := key
	if c.translator != nil {
		msg = c.translator.T(c.lang, key)
	}
	fmt.Printf(msg+"\n", args...)
}

// ForceRefresh forces an immediate CRL cache refresh.
func (c *CRLCache) ForceRefresh() error {
	return c.refresh()
}

// IsRevoked checks whether a given certificate serial number has been revoked.
func (c *CRLCache) IsRevoked(caDN string, serial *big.Int) (bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if time.Now().After(c.nextUpdate) {
		return false, fmt.Errorf("CRL expired (nextUpdate %s)", c.nextUpdate.Format(time.RFC3339))
	}
	key := caDN + "|" + serial.Text(16)
	return c.revoked[key], nil
}

// Stats returns CRL cache statistics (revocation count, this update, next update).
func (c *CRLCache) Stats() (int, time.Time, time.Time) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.revoked), c.thisUpdate, c.nextUpdate
}

// LastRefresh returns the time of the last successful refresh.
func (c *CRLCache) LastRefresh() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastRefresh
}

func (c *CRLCache) refresh() error {
	// Serialize fetch+commit: concurrent refresh could commit out of order triggering false replay detection.
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()

	resp, err := c.client.Get(c.url)
	if err != nil {
		return fmt.Errorf("fetch CRL: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read CRL body: %w", err)
	}

	block, _ := pem.Decode(body)
	if block != nil && block.Type == "X509 CRL" {
		body = block.Bytes
	}

	crl, err := x509.ParseDERCRL(body)
	if err != nil {
		return fmt.Errorf("parse CRL DER: %w", err)
	}

	crlIssuerStr := crl.TBSCertList.Issuer.String()
	var caRDN pkix.RDNSequence
	if _, err := asn1.Unmarshal(c.caCert.RawSubject, &caRDN); err != nil {
		return fmt.Errorf("unmarshal CA subject: %w", err)
	}
	if caRDN.String() != crlIssuerStr {
		return fmt.Errorf("CRL issuer %q does not match CA %q", crlIssuerStr, caRDN.String())
	}

	if err := c.caCert.CheckCRLSignature(crl); err != nil {
		return fmt.Errorf("CRL signature verification failed: %w", err)
	}

	revoked := make(map[string]bool, len(crl.TBSCertList.RevokedCertificates))
	prefix := c.caDN + "|"
	for _, entry := range crl.TBSCertList.RevokedCertificates {
		revoked[prefix+entry.SerialNumber.Text(16)] = true
	}

	c.mu.Lock()
	if !crl.TBSCertList.ThisUpdate.After(c.thisUpdate) && !c.thisUpdate.IsZero() {
		c.mu.Unlock()
		return fmt.Errorf("CRL thisUpdate %v is not newer than cached %v (replay?)",
			crl.TBSCertList.ThisUpdate, c.thisUpdate)
	}
	c.revoked = revoked
	c.thisUpdate = crl.TBSCertList.ThisUpdate
	c.nextUpdate = crl.TBSCertList.NextUpdate
	c.lastRefresh = time.Now()
	nextUpdate := c.nextUpdate
	c.mu.Unlock()

	c.printf("crl.refreshed", c.url, len(revoked), nextUpdate.Format(time.RFC3339))
	return nil
}
