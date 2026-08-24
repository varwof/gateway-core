// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writePluginDecision(t *testing.T, entry PluginAuditEntry) (SignedAuditEntry, error) {
	t.Helper()
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.log")
	logger, err := NewAuditLogger(auditPath, nil, 10*1024*1024, 3)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	LogPluginDecision(logger, entry)
	logger.Close()

	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	var signed SignedAuditEntry
	if err := json.Unmarshal(data, &signed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return signed, nil
}

// TestPluginAuditLevel_Allow allow decisions default to INFO, and Level is passed through to the audit entry.
func TestPluginAuditLevel_Allow(t *testing.T) {
	signed, err := writePluginDecision(t, PluginAuditEntry{
		Scheme:       "mysql-v1",
		CapabilityID: "query",
		Decision:     "allow",
		Reason:       "ok",
	})
	if err != nil {
		t.Fatal(err)
	}
	if signed.Entry.Level != "INFO" {
		t.Fatalf("allow decision: level = %q, want INFO", signed.Entry.Level)
	}
}

// TestPluginAuditLevel_DenyWarns deny/error decisions default to WARN.
func TestPluginAuditLevel_DenyWarns(t *testing.T) {
	for _, d := range []string{"deny", "error"} {
		signed, err := writePluginDecision(t, PluginAuditEntry{
			Scheme:       "mysql-v1",
			CapabilityID: "query",
			Decision:     d,
			Reason:       "blocked",
		})
		if err != nil {
			t.Fatal(err)
		}
		if signed.Entry.Level != "WARN" {
			t.Fatalf("decision %q: level = %q, want WARN", d, signed.Entry.Level)
		}
	}
}

// TestPluginAuditLevel_Explicit explicit Level overrides inference.
func TestPluginAuditLevel_Explicit(t *testing.T) {
	signed, err := writePluginDecision(t, PluginAuditEntry{
		Scheme:       "mysql-v1",
		CapabilityID: "query",
		Decision:     "allow",
		Reason:       "custom",
		Level:        "WARN",
	})
	if err != nil {
		t.Fatal(err)
	}
	if signed.Entry.Level != "WARN" {
		t.Fatalf("explicit level = %q, want WARN", signed.Entry.Level)
	}
}

// TestPluginAuditLevel_NilLogger nil logger does not panic.
func TestPluginAuditLevel_NilLogger(t *testing.T) {
	LogPluginDecision(nil, PluginAuditEntry{
		Scheme:       "s",
		CapabilityID: "c",
		Decision:     "allow",
	})
}
