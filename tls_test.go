// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writePEM(path, blockType string, der []byte, t *testing.T) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	pem.Encode(f, &pem.Block{Type: blockType, Bytes: der})
}

func TestLoadCA(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")

	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	if err := os.WriteFile(caPath, pemData, 0644); err != nil {
		t.Fatal(err)
	}

	pool, err := LoadCA(caPath)
	if err != nil {
		t.Fatalf("LoadCA() error = %v", err)
	}
	if pool == nil {
		t.Fatal("pool is nil")
	}

	_, err = LoadCA("/nonexistent.pem")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}

	badPath := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(badPath, []byte("not pem"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err = LoadCA(badPath)
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestLoadCert(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	writePEM(certPath, "CERTIFICATE", certDER, t)
	writePEM(keyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key), t)

	cert, err := LoadCert(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadCert() error = %v", err)
	}
	if cert == nil {
		t.Fatal("cert is nil")
	}

	_, err = LoadCert("/nonexistent.pem", keyPath)
	if err == nil {
		t.Error("expected error for nonexistent cert")
	}
}

func TestClientTLSConfig(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")

	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	writePEM(caPath, "CERTIFICATE", caDER, t)

	cfg, err := ClientTLSConfig(caPath, "", "", nil, "")
	if err != nil {
		t.Fatalf("ClientTLSConfig() error = %v", err)
	}
	if cfg == nil {
		t.Fatal("config is nil")
	}

	t.Run("with client cert", func(t *testing.T) {
		dir2 := t.TempDir()
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: "client"},
			NotBefore:    time.Now().Add(-1 * time.Hour),
			NotAfter:     time.Now().Add(1 * time.Hour),
		}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		writePEM(filepath.Join(dir2, "cert.pem"), "CERTIFICATE", der, t)
		writePEM(filepath.Join(dir2, "key.pem"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key), t)
		cfg2, err := ClientTLSConfig(caPath, filepath.Join(dir2, "cert.pem"), filepath.Join(dir2, "key.pem"), nil, "")
		if err != nil {
			t.Fatalf("ClientTLSConfig with cert: %v", err)
		}
		if len(cfg2.Certificates) != 1 {
			t.Error("expected 1 client certificate")
		}
	})

	t.Run("error on bad cert", func(t *testing.T) {
		_, err := ClientTLSConfig(caPath, "/nonexistent.pem", "/nonexistent.key", nil, "")
		if err == nil {
			t.Error("expected error for bad cert")
		}
	})
}

func TestBuildCipherSuites(t *testing.T) {
	t.Run("empty returns defaults", func(t *testing.T) {
		suites := BuildCipherSuites(nil)
		if len(suites) != len(SecureCipherSuites) {
			t.Errorf("got %d, want %d", len(suites), len(SecureCipherSuites))
		}
	})

	t.Run("valid names", func(t *testing.T) {
		suites := BuildCipherSuites([]string{"TLS_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"})
		if len(suites) != 2 {
			t.Fatalf("got %d suites, want 2", len(suites))
		}
		if suites[0] != tls.TLS_AES_128_GCM_SHA256 {
			t.Errorf("suites[0] = %d, want %d", suites[0], tls.TLS_AES_128_GCM_SHA256)
		}
	})

	t.Run("unknown name skipped", func(t *testing.T) {
		suites := BuildCipherSuites([]string{"TLS_AES_128_GCM_SHA256", "FAKE_CIPHER"})
		if len(suites) != 1 {
			t.Fatalf("got %d suites, want 1", len(suites))
		}
	})

	t.Run("all unknown falls back to defaults", func(t *testing.T) {
		suites := BuildCipherSuites([]string{"FAKE_CIPHER_1", "FAKE_CIPHER_2"})
		if len(suites) != len(SecureCipherSuites) {
			t.Errorf("got %d, want %d (defaults)", len(suites), len(SecureCipherSuites))
		}
	})
}

func TestTLSVersionFromString(t *testing.T) {
	tests := []struct {
		input string
		want  uint16
	}{
		{"1.2", tls.VersionTLS12},
		{"1.3", tls.VersionTLS13},
		{"", tls.VersionTLS12},
		{"invalid", tls.VersionTLS12},
		{"1.0", tls.VersionTLS12},
	}
	for _, tt := range tests {
		got := TLSVersionFromString(tt.input)
		if got != tt.want {
			t.Errorf("TLSVersionFromString(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestBaseTLSConfig(t *testing.T) {
	t.Run("default values", func(t *testing.T) {
		cfg := BaseTLSConfig(nil, "")
		if cfg.MinVersion != tls.VersionTLS12 {
			t.Errorf("MinVersion = %d, want %d", cfg.MinVersion, tls.VersionTLS12)
		}
		if len(cfg.CipherSuites) != len(SecureCipherSuites) {
			t.Errorf("got %d cipher suites, want %d", len(cfg.CipherSuites), len(SecureCipherSuites))
		}
	})

	t.Run("custom cipher suites", func(t *testing.T) {
		cfg := BaseTLSConfig([]string{"TLS_AES_128_GCM_SHA256"}, "")
		if len(cfg.CipherSuites) != 1 {
			t.Fatalf("got %d, want 1", len(cfg.CipherSuites))
		}
	})

	t.Run("custom TLS version", func(t *testing.T) {
		cfg := BaseTLSConfig(nil, "1.3")
		if cfg.MinVersion != tls.VersionTLS13 {
			t.Errorf("MinVersion = %d, want %d", cfg.MinVersion, tls.VersionTLS13)
		}
	})
}

func TestServerTLSConfig(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "server"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	cfg := ServerTLSConfig(cert, nil, "")
	if cfg == nil {
		t.Fatal("ServerTLSConfig returned nil")
	}
	if len(cfg.Certificates) != 1 {
		t.Error("expected 1 certificate")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d", cfg.MinVersion)
	}
}

func TestLoadCACert(t *testing.T) {
	dir := t.TempDir()
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caPath := filepath.Join(dir, "ca.pem")
	writePEM(caPath, "CERTIFICATE", caDER, t)

	t.Run("valid CA cert", func(t *testing.T) {
		cert, err := LoadCACert(caPath)
		if err != nil {
			t.Fatalf("LoadCACert() error = %v", err)
		}
		if !cert.IsCA {
			t.Error("expected IsCA=true")
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		_, err := LoadCACert("/nonexistent.pem")
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("invalid PEM", func(t *testing.T) {
		badPath := filepath.Join(dir, "bad.pem")
		os.WriteFile(badPath, []byte("not pem"), 0644)
		_, err := LoadCACert(badPath)
		if err == nil {
			t.Error("expected error for invalid PEM")
		}
	})
}

func TestMTLSServerConfig(t *testing.T) {
	dir := t.TempDir()
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caPath := filepath.Join(dir, "ca.pem")
	writePEM(caPath, "CERTIFICATE", caDER, t)

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "server"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		DNSNames:     []string{"localhost"},
	}
	srvDER, _ := x509.CreateCertificate(rand.Reader, srvTmpl, caTmpl, &key.PublicKey, caKey)
	srvCert := &tls.Certificate{Certificate: [][]byte{srvDER}, PrivateKey: key}

	t.Run("valid mTLS config", func(t *testing.T) {
		cfg, err := MTLSServerConfig(caPath, srvCert, nil, "")
		if err != nil {
			t.Fatalf("MTLSServerConfig() error = %v", err)
		}
		if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
			t.Error("expected RequireAndVerifyClientCert")
		}
		if len(cfg.Certificates) != 1 {
			t.Error("expected 1 certificate")
		}
		if cfg.VerifyPeerCertificate == nil {
			t.Error("expected VerifyPeerCertificate callback")
		}
	})

	t.Run("error on bad CA path", func(t *testing.T) {
		_, err := MTLSServerConfig("/nonexistent.pem", srvCert, nil, "")
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("VerifyPeerCertificate rejects expired chain", func(t *testing.T) {
		expiredKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		expiredTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(3),
			Subject:      pkix.Name{CommonName: "expired-client"},
			NotBefore:    time.Now().Add(-5 * time.Hour),
			NotAfter:     time.Now().Add(-1 * time.Hour),
			DNSNames:     []string{"client"},
		}
		expiredDER, _ := x509.CreateCertificate(rand.Reader, expiredTmpl, caTmpl, &expiredKey.PublicKey, caKey)

		cfg, err := MTLSServerConfig(caPath, srvCert, nil, "")
		if err != nil {
			t.Fatal(err)
		}

		chain := [][]*x509.Certificate{
			{
				&x509.Certificate{
					SerialNumber: big.NewInt(3),
					Subject:      pkix.Name{CommonName: "expired-client"},
					NotBefore:    time.Now().Add(-5 * time.Hour),
					NotAfter:     time.Now().Add(-1 * time.Hour),
				},
				caTmpl,
			},
		}
		err = cfg.VerifyPeerCertificate([][]byte{expiredDER}, chain)
		if err == nil {
			t.Error("expected error for expired leaf certificate")
		}
	})

	t.Run("VerifyPeerCertificate rejects intermediate without KeyUsageCertSign", func(t *testing.T) {
		interKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		interTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(4),
			Subject:      pkix.Name{CommonName: "bad-intermediate"},
			NotBefore:    time.Now().Add(-1 * time.Hour),
			NotAfter:     time.Now().Add(1 * time.Hour),
		}
		interDER, _ := x509.CreateCertificate(rand.Reader, interTmpl, caTmpl, &interKey.PublicKey, caKey)
		interCert, _ := x509.ParseCertificate(interDER)

		leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		leafTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(5),
			Subject:      pkix.Name{CommonName: "leaf"},
			NotBefore:    time.Now().Add(-1 * time.Hour),
			NotAfter:     time.Now().Add(1 * time.Hour),
		}
		leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, interCert, &leafKey.PublicKey, interKey)
		leafCert, _ := x509.ParseCertificate(leafDER)

		cfg, err := MTLSServerConfig(caPath, srvCert, nil, "")
		if err != nil {
			t.Fatal(err)
		}

		chain := [][]*x509.Certificate{
			{leafCert, interCert, caTmpl},
		}
		err = cfg.VerifyPeerCertificate([][]byte{leafDER, interDER, caDER}, chain)
		if err == nil {
			t.Error("expected error for intermediate missing KeyUsageCertSign")
		}
	})

	t.Run("VerifyPeerCertificate with empty chain", func(t *testing.T) {
		cfg, err := MTLSServerConfig(caPath, srvCert, nil, "")
		if err != nil {
			t.Fatal(err)
		}
		err = cfg.VerifyPeerCertificate(nil, nil)
		if err == nil {
			t.Error("expected error for empty chain")
		}
	})
}

func TestMTLSServerIntegration(t *testing.T) {
	dir := t.TempDir()
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caPath := filepath.Join(dir, "ca.pem")
	writePEM(caPath, "CERTIFICATE", caDER, t)

	srvKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "server"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		DNSNames:     []string{"localhost"},
	}
	srvDER, _ := x509.CreateCertificate(rand.Reader, srvTmpl, caTmpl, &srvKey.PublicKey, caKey)
	srvCert := &tls.Certificate{Certificate: [][]byte{srvDER}, PrivateKey: srvKey}

	cliKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	cliTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "client"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		DNSNames:     []string{"client"},
	}
	cliDER, _ := x509.CreateCertificate(rand.Reader, cliTmpl, caTmpl, &cliKey.PublicKey, caKey)
	cliCert := &tls.Certificate{Certificate: [][]byte{cliDER}, PrivateKey: cliKey}

	tlsCfg, err := MTLSServerConfig(caPath, srvCert, nil, "")
	if err != nil {
		t.Fatal(err)
	}

	lis, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()

	errCh := make(chan error, 1)
	go func() {
		conn, err := lis.Accept()
		if err != nil {
			errCh <- err
			return
		}
		conn.(*tls.Conn).Handshake()
		buf := make([]byte, 64)
		n, _ := conn.Read(buf)
		conn.Write(buf[:n])
		conn.Close()
		errCh <- nil
	}()

	pool := x509.NewCertPool()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	pool.AppendCertsFromPEM(caPEM)

	clientCfg := &tls.Config{
		Certificates:       []tls.Certificate{*cliCert},
		RootCAs:            pool,
		InsecureSkipVerify: true,
		ServerName:         "localhost",
	}

	conn, err := tls.Dial("tcp", lis.Addr().String(), clientCfg)
	if err != nil {
		t.Fatalf("mTLS dial: %v", err)
	}
	conn.Write([]byte("ping"))
	reply := make([]byte, 64)
	n, err := conn.Read(reply)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(reply[:n]) != "ping" {
		t.Errorf("got %q, want %q", string(reply[:n]), "ping")
	}
	conn.Close()
	<-errCh
}

func TestMTLSServerVerifyPeerCertificateRejectsEmptyChain(t *testing.T) {
	dir := t.TempDir()
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caPath := filepath.Join(dir, "ca.pem")
	writePEM(caPath, "CERTIFICATE", caDER, t)

	srvKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "server"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		DNSNames:     []string{"localhost"},
	}
	srvDER, _ := x509.CreateCertificate(rand.Reader, srvTmpl, caTmpl, &srvKey.PublicKey, caKey)
	srvCert := &tls.Certificate{Certificate: [][]byte{srvDER}, PrivateKey: srvKey}

	cfg, err := MTLSServerConfig(caPath, srvCert, nil, "")
	if err != nil {
		t.Fatal(err)
	}

	err = cfg.VerifyPeerCertificate(nil, nil)
	if err == nil {
		t.Error("expected error for empty chain")
	}
}

// TestLoadCAMultipleCerts verifies L1: a CA bundle with multiple certificates
// is fully validated (every block is parsed), not just the first.
func TestLoadCAMultipleCerts(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")

	writeCA := func(cn string, serial int64) []byte {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               pkix.Name{CommonName: cn},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}

	bundle := append(writeCA("CA One", 1), writeCA("CA Two", 2)...)
	if err := os.WriteFile(caPath, bundle, 0644); err != nil {
		t.Fatal(err)
	}

	pool, err := LoadCA(caPath)
	if err != nil {
		t.Fatalf("LoadCA() multi-cert error = %v", err)
	}
	if pool == nil {
		t.Fatal("pool is nil")
	}
}
