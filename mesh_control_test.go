// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// meshTestCluster builds an mTLS mesh with a shared CA, returns the CA directory and per-node certificates.
func meshTestCluster(t *testing.T, names []string) (string, map[string]*tls.Certificate) {
	t.Helper()
	dir := t.TempDir()
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Mesh Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caPath := filepath.Join(dir, "ca.pem")
	writePEM(caPath, "CERTIFICATE", caDER, t)

	certs := make(map[string]*tls.Certificate)
	for i, name := range names {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 2)),
			// gateway:admin OU so control listeners accept the peer (H3 role check).
			Subject:   pkix.Name{CommonName: name, OrganizationalUnit: []string{"gateway:admin"}},
			NotBefore: time.Now().Add(-1 * time.Hour),
			NotAfter:  time.Now().Add(1 * time.Hour),
			DNSNames:  []string{"localhost"},
		}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, caTmpl, &key.PublicKey, caKey)
		certs[name] = &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	return caPath, certs
}

// meshServerConfig builds an mTLS server config (for accepting control connections).
func meshServerConfig(t *testing.T, caPath string, cert *tls.Certificate) *tls.Config {
	t.Helper()
	cfg, err := MTLSServerConfig(caPath, cert, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// meshClientConfig builds an mTLS client config (for sending control messages).
func meshClientConfig(t *testing.T, caPath string, cert *tls.Certificate) *tls.Config {
	t.Helper()
	cfg, err := ClientTLSConfig(caPath, "", "", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Certificates = []tls.Certificate{*cert}
	cfg.ServerName = "localhost"
	return cfg
}

func TestWriteReadControlMessage(t *testing.T) {
	m := NewMeshManager(MeshConfig{LocalName: "nodeA"})
	defer m.Stop()
	msg := m.NewControlMessage(ControlRevoke)
	msg.Serial = "ABC123"
	msg.KeyHash = "k1"

	var buf bytes.Buffer
	if err := writeControlMessage(&buf, msg); err != nil {
		t.Fatal(err)
	}
	got, err := readControlMessage(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != ControlRevoke || got.Serial != "ABC123" || got.KeyHash != "k1" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if got.Source != "nodeA" || got.MsgID == "" {
		t.Fatalf("missing source/msgid: %+v", got)
	}
}

func TestReadControlMessageBadMagic(t *testing.T) {
	buf := bytes.NewBuffer([]byte{0xFF, 0x00, 0x01, '{', '}'})
	if _, err := readControlMessage(buf); err == nil {
		t.Fatal("expected error on bad magic")
	}
}

func TestReadControlMessageMissingFields(t *testing.T) {
	m := NewMeshManager(MeshConfig{LocalName: "x"})
	msg := m.NewControlMessage(ControlRevoke)
	msg.Type = ""
	var buf bytes.Buffer
	writeControlMessage(&buf, msg)
	if _, err := readControlMessage(&buf); err == nil {
		t.Fatal("expected error on missing type")
	}
}

func TestHandleControlMessageSelfOriginIgnored(t *testing.T) {
	m := NewMeshManager(MeshConfig{LocalName: "nodeA"})
	defer m.Stop()
	called := false
	m.SetControlHandler(func(ControlMessage) error {
		called = true
		return nil
	})
	msg := m.NewControlMessage(ControlRevoke)
	var buf bytes.Buffer
	writeControlMessage(&buf, msg)
	if err := m.HandleControlMessage(&buf); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("self-origin message must be ignored (anti-loop)")
	}
}

func TestHandleControlMessageDedup(t *testing.T) {
	m := NewMeshManager(MeshConfig{LocalName: "nodeB"})
	defer m.Stop()
	var mu sync.Mutex
	count := 0
	m.SetControlHandler(func(ControlMessage) error {
		mu.Lock()
		count++
		mu.Unlock()
		return nil
	})

	msg := ControlMessage{
		Type: ControlRevoke, Source: "nodeA", MsgID: "nodeA-1",
		Timestamp: time.Now().UnixMilli(), Serial: "S1",
	}
	for i := 0; i < 3; i++ {
		var buf bytes.Buffer
		writeControlMessage(&buf, msg)
		if err := m.HandleControlMessage(&buf); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if count != 1 {
		t.Fatalf("expected handler called once (dedup), got %d", count)
	}
}

// TestMeshControlBroadcastThreeNode Three-node real mTLS cluster: A broadcasts revoke,
// B/C control listeners receive and trigger handler (revocation status synced).
func TestMeshControlBroadcastThreeNode(t *testing.T) {
	caPath, certs := meshTestCluster(t, []string{"nodeA", "nodeB", "nodeC"})

	// Start control listeners for B/C, record received messages
	type receiver struct {
		mgr  *MeshManager
		addr string
		got  chan ControlMessage
	}
	receivers := make(map[string]*receiver)

	for _, name := range []string{"nodeB", "nodeC"} {
		lis, err := tls.Listen("tcp", "127.0.0.1:0", meshServerConfig(t, caPath, certs[name]))
		if err != nil {
			t.Fatal(err)
		}
		defer lis.Close()
		mgr := NewMeshManager(MeshConfig{
			LocalName: name,
			TLSConfig: meshClientConfig(t, caPath, certs[name]),
		})
		got := make(chan ControlMessage, 4)
		mgr.SetControlHandler(func(msg ControlMessage) error {
			got <- msg
			return nil
		})
		go mgr.ServeControlListener(lis)
		receivers[name] = &receiver{mgr: mgr, addr: lis.Addr().String(), got: got}
	}

	// A as sender
	managerA := NewMeshManager(MeshConfig{
		LocalName: "nodeA",
		TLSConfig: meshClientConfig(t, caPath, certs["nodeA"]),
	})
	defer managerA.Stop()
	managerA.mu.Lock()
	managerA.peers = append(managerA.peers,
		newHealthyPeer("nodeB", receivers["nodeB"].addr, 1, nil),
		newHealthyPeer("nodeC", receivers["nodeC"].addr, 1, nil),
	)
	managerA.mu.Unlock()

	if err := managerA.BroadcastRevoke("SERIAL-77", "HASH77"); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"nodeB", "nodeC"} {
		select {
		case msg := <-receivers[name].got:
			if msg.Type != ControlRevoke {
				t.Fatalf("%s: expected revoke, got %v", name, msg.Type)
			}
			if msg.Serial != "SERIAL-77" || msg.Source != "nodeA" {
				t.Fatalf("%s: payload mismatch %+v", name, msg)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: timeout waiting for revoke broadcast", name)
		}
	}
}

// TestMeshControlBroadcastDisconnect Two nodes: A broadcasts disconnect (kick),
// B receives and triggers callback by agentId (emergency disable propagation).
func TestMeshControlBroadcastDisconnect(t *testing.T) {
	caPath, certs := meshTestCluster(t, []string{"nodeA", "nodeB"})

	lis, err := tls.Listen("tcp", "127.0.0.1:0", meshServerConfig(t, caPath, certs["nodeB"]))
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()
	managerB := NewMeshManager(MeshConfig{
		LocalName: "nodeB",
		TLSConfig: meshClientConfig(t, caPath, certs["nodeB"]),
	})
	got := make(chan ControlMessage, 4)
	managerB.SetControlHandler(func(msg ControlMessage) error {
		got <- msg
		return nil
	})
	go managerB.ServeControlListener(lis)

	managerA := NewMeshManager(MeshConfig{
		LocalName: "nodeA",
		TLSConfig: meshClientConfig(t, caPath, certs["nodeA"]),
	})
	defer managerA.Stop()
	managerA.mu.Lock()
	managerA.peers = append(managerA.peers, newHealthyPeer("nodeB", lis.Addr().String(), 1, nil))
	managerA.mu.Unlock()

	if err := managerA.BroadcastDisconnect("agent-42", "security incident"); err != nil {
		t.Fatal(err)
	}
	select {
	case msg := <-got:
		if msg.Type != ControlDisconnect {
			t.Fatalf("expected disconnect, got %v", msg.Type)
		}
		if msg.AgentId != "agent-42" || msg.Reason != "security incident" {
			t.Fatalf("payload mismatch %+v", msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for disconnect broadcast")
	}
}

// TestMeshControlDedupCleanup Verifies dedup table entry is removed after cleanup.
func TestMeshControlDedupCleanup(t *testing.T) {
	m := NewMeshManager(MeshConfig{LocalName: "nodeB"})
	defer m.Stop()
	m.ctrlDedup["nodeA-1"] = time.Now().Add(-10 * time.Minute)
	m.StartDedupCleanup(10 * time.Millisecond)
	deadline := time.Now().Add(2 * time.Second)
	for {
		m.ctrlMu.Lock()
		_, ok := m.ctrlDedup["nodeA-1"]
		m.ctrlMu.Unlock()
		if !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("dedup entry not cleaned up")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestMeshSendControlToPeer Verifies single-peer send path (no HealthyPeers injection dependency).
func TestMeshSendControlToPeer(t *testing.T) {
	caPath, certs := meshTestCluster(t, []string{"nodeA", "nodeB"})

	lis, err := tls.Listen("tcp", "127.0.0.1:0", meshServerConfig(t, caPath, certs["nodeB"]))
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()
	managerB := NewMeshManager(MeshConfig{
		LocalName: "nodeB",
		TLSConfig: meshClientConfig(t, caPath, certs["nodeB"]),
	})
	got := make(chan ControlMessage, 4)
	managerB.SetControlHandler(func(msg ControlMessage) error {
		got <- msg
		return nil
	})
	go managerB.ServeControlListener(lis)

	managerA := NewMeshManager(MeshConfig{
		LocalName: "nodeA",
		TLSConfig: meshClientConfig(t, caPath, certs["nodeA"]),
	})
	defer managerA.Stop()
	managerA.mu.Lock()
	managerA.peers = append(managerA.peers, newHealthyPeer("nodeB", lis.Addr().String(), 1, nil))
	managerA.mu.Unlock()

	msg := managerA.NewControlMessage(ControlPeerSync)
	msg.Version = 42
	if err := managerA.SendControl("nodeB", msg); err != nil {
		t.Fatal(err)
	}
	select {
	case gotMsg := <-got:
		if gotMsg.Type != ControlPeerSync || gotMsg.Version != 42 {
			t.Fatalf("payload mismatch %+v", gotMsg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for peer_sync")
	}
}
