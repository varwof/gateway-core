package gw

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

var errMockSign = errors.New("mock sign error")

func TestTSAProofLoggerSignFailed(t *testing.T) {
	chain := NewAuditChain(100, nil)
	chain.Seal([][]byte{[]byte("test-entry")}, "")

	tsa := NewTSAClient("http://tsa.test.local")
	tsa.SignFunc = func(data []byte) ([]byte, error) {
		return nil, errMockSign
	}

	path := os.TempDir() + "/tsa_proof_fail_test.log"
	defer os.Remove(path)

	logger := NewTSAProofLogger(path, tsa, chain, 3600)
	stopCh := make(chan struct{})
	logger.Start(stopCh)
	time.Sleep(200 * time.Millisecond)
	close(stopCh)
	time.Sleep(100 * time.Millisecond)
	_ = logger.Close()
}

func TestTSAProofLoggerHappyPath(t *testing.T) {
	chain := NewAuditChain(100, nil)
	chain.Seal([][]byte{[]byte("entry1")}, "")

	tsa := NewTSAClient("http://tsa.test.local")
	tsa.SignFunc = func(data []byte) ([]byte, error) {
		return []byte("mock-tst"), nil
	}

	path := os.TempDir() + "/tsa_proof_happy_test.log"
	defer os.Remove(path)

	logger := NewTSAProofLogger(path, tsa, chain, 3600)

	stopCh := make(chan struct{})
	logger.Start(stopCh)
	time.Sleep(200 * time.Millisecond)
	close(stopCh)
	time.Sleep(100 * time.Millisecond)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	var entry TSAProofEntry
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("parse entry: %v", err)
	}
	if entry.Root != chain.LatestRoot() {
		t.Fatalf("expected root %s, got %s", chain.LatestRoot(), entry.Root)
	}
	if entry.TST == "" {
		t.Fatal("expected non-empty TST")
	}
	if entry.Batch != 0 {
		t.Fatalf("expected batch 0, got %d", entry.Batch)
	}
}

func TestTSAProofLoggerStartStop(t *testing.T) {
	chain := NewAuditChain(100, nil)
	chain.Seal([][]byte{[]byte("entry1")}, "")

	tsa := NewTSAClient("http://tsa.test.local")
	signCount := 0
	tsa.SignFunc = func(data []byte) ([]byte, error) {
		signCount++
		return []byte("mock-tst"), nil
	}

	path := os.TempDir() + "/tsa_proof_start_stop_test.log"
	defer os.Remove(path)

	logger := NewTSAProofLogger(path, tsa, chain, 1)

	stopCh := make(chan struct{})
	logger.Start(stopCh)

	time.Sleep(2500 * time.Millisecond)

	close(stopCh)
	time.Sleep(200 * time.Millisecond)

	if signCount < 2 {
		t.Fatalf("expected at least 2 signs (initial + >=1 tick), got %d", signCount)
	}
}

func TestTSAProofLoggerIntervalZero(t *testing.T) {
	chain := NewAuditChain(100, nil)
	tsa := NewTSAClient("http://127.0.0.1:1")
	path := os.TempDir() + "/tsa_proof_zero_test.log"
	defer os.Remove(path)

	logger := NewTSAProofLogger(path, tsa, chain, 0)
	if logger.interval != 3600*time.Second {
		t.Fatalf("expected default interval 3600s, got %v", logger.interval)
	}
}

func TestTSAProofLoggerCloseIdempotent(t *testing.T) {
	tsa := NewTSAClient("http://127.0.0.1:1")
	path := os.TempDir() + "/tsa_proof_close_test.log"
	defer os.Remove(path)

	logger := NewTSAProofLogger(path, tsa, NewAuditChain(100, nil), 3600)
	if err := logger.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := logger.Close(); err != nil {
		t.Fatalf("close again: %v", err)
	}
}
