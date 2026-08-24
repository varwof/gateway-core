// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/varwof/pkcs7"
)

// SelfVerifyOptions describes the parameters required for binary self-verification.
type SelfVerifyOptions struct {
	// SigPath is the path to the detached signature file (PKCS#7 .p7s).
	// Defaults to exePath+".p7s" when empty.
	SigPath string
	// Roots is the trusted CA pool for verifying the signer certificate chain.
	// When nil, only the signature is verified without chain validation.
	Roots *x509.CertPool
	// RequireExecutable checks that exePath falls within the expected location
	// for executables (prevents accidentally passing a config file path as the target program).
	RequireExecutable bool
}

// VerifySelf verifies the detached signature of the executable itself.
// exePath is the path to the binary to verify; the signature file defaults to exePath+".p7s".
// On success, returns the signer certificate for further OU/validity checks by the caller.
func VerifySelf(exePath string, roots *x509.CertPool) (*x509.Certificate, error) {
	return VerifySelfWithOptions(exePath, SelfVerifyOptions{Roots: roots})
}

// VerifySelfWithOptions is the extended version of VerifySelf, supporting custom signature file paths.
func VerifySelfWithOptions(exePath string, opts SelfVerifyOptions) (*x509.Certificate, error) {
	data, err := os.ReadFile(filepath.Clean(exePath))
	if err != nil {
		return nil, fmt.Errorf("selfverify: read binary: %w", err)
	}
	if len(data) == 0 {
		return nil, errors.New("selfverify: empty binary content")
	}
	if opts.RequireExecutable {
		fi, err := os.Stat(filepath.Clean(exePath))
		if err != nil {
			return nil, fmt.Errorf("selfverify: stat binary: %w", err)
		}
		if fi.Mode()&0o111 == 0 {
			return nil, fmt.Errorf("selfverify: %s is not executable", exePath)
		}
	}
	sigPath := opts.SigPath
	if sigPath == "" {
		sigPath = exePath + ".p7s"
	}
	sig, err := os.ReadFile(filepath.Clean(sigPath))
	if err != nil {
		return nil, fmt.Errorf("selfverify: read signature %s: %w", sigPath, err)
	}
	return VerifySignedBinary(data, sig, opts.Roots)
}

// VerifySignedBinary verifies a PKCS#7 detached signature over binary data.
// On success, returns the signer certificate; when roots is non-nil, performs additional chain validation.
func VerifySignedBinary(data, sig []byte, roots *x509.CertPool) (*x509.Certificate, error) {
	cert, err := pkcs7.VerifyDetached(sig, data)
	if err != nil {
		return nil, fmt.Errorf("selfverify: signature: %w", err)
	}
	if roots != nil {
		if _, err := cert.Verify(x509.VerifyOptions{
			Roots:     roots,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); err != nil {
			return nil, fmt.Errorf("selfverify: signer cert chain not trusted: %w", err)
		}
	}
	return cert, nil
}

// PEMRootPool builds a CertPool from PEM-encoded CA certificates.
func PEMRootPool(pemData []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, errors.New("selfverify: no PEM certificates found in roots")
	}
	return pool, nil
}

// VerifyCurrentExecutable verifies the currently running executable.
// Uses os.Executable() to locate itself; the signature file defaults to exePath+".p7s".
// Suitable for calling at program startup: returns nil on success, detailed error on failure.
func VerifyCurrentExecutable(roots *x509.CertPool) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("selfverify: resolve own path: %w", err)
	}
	if _, err := VerifySelf(exe, roots); err != nil {
		return err
	}
	return nil
}

// MustVerifyCurrentExecutable is like VerifyCurrentExecutable, but prints the error
// and terminates the process (os.Exit(1)) on verification failure.
// Typical usage is to call it as the first line in main():
//
//	gw.MustVerifyCurrentExecutable(roots)
//
// If the target program has not deployed a <self-path>.p7s signature file,
// it will fail to start (fail-closed).
func MustVerifyCurrentExecutable(roots *x509.CertPool) {
	if err := VerifyCurrentExecutable(roots); err != nil {
		fmt.Fprintln(os.Stderr, "self-verification failed:", err)
		os.Exit(1)
	}
}
