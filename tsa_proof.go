// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// TSAProofEntry is a TSA audit proof entry.
type TSAProofEntry struct {
	Time  string `json:"time"`
	Root  string `json:"root"`
	TST   string `json:"tst"`
	Batch int    `json:"batch"`
}

// TSAProofLogger is the TSA audit proof logger.
type TSAProofLogger struct {
	mu       sync.Mutex
	path     string
	tsa      *TSAClient
	chain    *AuditChain
	file     *os.File
	interval time.Duration
	stopCh   chan struct{}
}

// NewTSAProofLogger creates a TSA audit proof logger.
func NewTSAProofLogger(path string, tsa *TSAClient, chain *AuditChain, intervalSec int) *TSAProofLogger {
	if intervalSec <= 0 {
		intervalSec = 3600
	}
	return &TSAProofLogger{
		path:     path,
		tsa:      tsa,
		chain:    chain,
		interval: time.Duration(intervalSec) * time.Second,
		stopCh:   make(chan struct{}),
	}
}

// Start starts the TSA audit proof periodic recording loop.
func (l *TSAProofLogger) Start(stopCh chan struct{}) {
	file, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("tsa_proof: open %s: %v", l.path, err)
		return
	}
	l.mu.Lock()
	l.file = file
	l.mu.Unlock()

	latest := l.chain.LatestRootBytes()
	if latest != nil {
		if err := l.signAndAppend(latest); err != nil {
			log.Printf("tsa_proof: initial sign: %v", err)
		}
	}

	go func() {
		ticker := time.NewTicker(l.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				root := l.chain.LatestRootBytes()
				if root == nil {
					continue
				}
				if err := l.signAndAppend(root); err != nil {
					log.Printf("tsa_proof: sign: %v", err)
				}
			case <-stopCh:
				l.Close()
				return
			case <-l.stopCh:
				l.Close()
				return
			}
		}
	}()
}

func (l *TSAProofLogger) signAndAppend(root []byte) error {
	tst, err := l.tsa.Sign(root)
	if err != nil {
		return fmt.Errorf("tsa sign: %w", err)
	}

	entry := TSAProofEntry{
		Time:  time.Now().UTC().Format(time.RFC3339),
		Root:  fmt.Sprintf("%x", root),
		TST:   base64.StdEncoding.EncodeToString(tst),
		Batch: l.chain.BatchCount() - 1,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal proof entry: %w", err)
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return fmt.Errorf("tsa_proof: file not open")
	}
	if _, err := l.file.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write proof: %w", err)
	}
	return nil
}

// Close closes the TSA proof log file.
func (l *TSAProofLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// SetAuditChain sets the audit chain reference (runtime replacement).
func (l *TSAProofLogger) SetAuditChain(chain *AuditChain) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.chain = chain
}

// Stop stops the TSA proof logger.
func (l *TSAProofLogger) Stop() {
	close(l.stopCh)
}
