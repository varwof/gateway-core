package gw

import (
	"crypto/x509"
	pki "github.com/varwof/types"
)

var oidGateway = pki.OIDGatewaySession

// ParseGatewaySessionExtension delegates to pki-types.
func ParseGatewaySessionExtension(cert *x509.Certificate) (*GatewaySessionExtension, error) {
	return pki.ParseGatewaySessionExtension(cert)
}
