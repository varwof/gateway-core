// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"os"
	"testing"
)

func TestAuditIndexCreate(t *testing.T) {
	path := tempDB(t)
	defer os.Remove(path)

	idx, err := NewAuditIndex(path)
	if err != nil {
		t.Fatalf("create index: %v", err)
	}
	defer idx.Close()

	if idx.DBPath() != path {
		t.Fatalf("expected path %s, got %s", path, idx.DBPath())
	}
}

func TestAuditIndexIndexAndSearchByCN(t *testing.T) {
	path := tempDB(t)
	defer os.Remove(path)

	idx, err := NewAuditIndex(path)
	if err != nil {
		t.Fatalf("create index: %v", err)
	}
	defer idx.Close()

	entry := &AuditEntry{
		Time:         "2026-07-08T10:00:00Z",
		Action:       "connected",
		ClientCN:     "test-client",
		ClientSerial: "ABC123",
		Mapping:      "test-mapping",
		Target:       "10.0.0.1:443",
		SrcIP:        "192.168.1.1",
	}

	if err := idx.Index(entry); err != nil {
		t.Fatalf("index entry: %v", err)
	}

	results, err := idx.Search(&AuditIndexQuery{CN: "test-client"})
	if err != nil {
		t.Fatalf("search by CN: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].CN != "test-client" {
		t.Fatalf("expected CN test-client, got %s", results[0].CN)
	}
}

func TestAuditIndexSearchBySerial(t *testing.T) {
	path := tempDB(t)
	defer os.Remove(path)

	idx, err := NewAuditIndex(path)
	if err != nil {
		t.Fatalf("create index: %v", err)
	}
	defer idx.Close()

	entry := &AuditEntry{
		Time:         "2026-07-08T10:00:00Z",
		Action:       "connected",
		ClientCN:     "test-client",
		ClientSerial: "SERIAL-001",
		Mapping:      "test",
		Target:       "10.0.0.1:443",
		SrcIP:        "10.0.0.2",
	}
	idx.Index(entry)

	results, err := idx.Search(&AuditIndexQuery{Serial: "SERIAL-001"})
	if err != nil {
		t.Fatalf("search by serial: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

func TestAuditIndexSearchByTimeRange(t *testing.T) {
	path := tempDB(t)
	defer os.Remove(path)

	idx, err := NewAuditIndex(path)
	if err != nil {
		t.Fatalf("create index: %v", err)
	}
	defer idx.Close()

	entries := []*AuditEntry{
		{Time: "2026-07-08T10:00:00Z", Action: "a", Mapping: "m", Target: "t1", SrcIP: "1"},
		{Time: "2026-07-08T11:00:00Z", Action: "b", Mapping: "m", Target: "t2", SrcIP: "2"},
		{Time: "2026-07-08T12:00:00Z", Action: "c", Mapping: "m", Target: "t3", SrcIP: "3"},
	}
	for _, e := range entries {
		idx.Index(e)
	}

	since := parseTime("2026-07-08T10:00:00Z")
	until := parseTime("2026-07-08T11:00:00Z")
	results, err := idx.Search(&AuditIndexQuery{
		Since: since,
		Until: until,
	})
	if err != nil {
		t.Fatalf("search by time: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results in time range, got %d", len(results))
	}
}

func TestAuditIndexLimitAndOffset(t *testing.T) {
	path := tempDB(t)
	defer os.Remove(path)

	idx, err := NewAuditIndex(path)
	if err != nil {
		t.Fatalf("create index: %v", err)
	}
	defer idx.Close()

	for i := 0; i < 10; i++ {
		entry := &AuditEntry{
			Time:     "2026-07-08T10:00:00Z",
			Action:   "test",
			ClientCN: "user",
			Mapping:  "m",
			Target:   "t",
			SrcIP:    "127.0.0.1",
		}
		idx.Index(entry)
	}

	results, err := idx.Search(&AuditIndexQuery{CN: "user", Limit: 3, Offset: 0})
	if err != nil {
		t.Fatalf("search with limit: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results with limit, got %d", len(results))
	}
}

func TestAuditIndexSize(t *testing.T) {
	path := tempDB(t)
	defer os.Remove(path)

	idx, err := NewAuditIndex(path)
	if err != nil {
		t.Fatalf("create index: %v", err)
	}
	defer idx.Close()

	size, err := idx.Size()
	if err != nil {
		t.Fatalf("size: %v", err)
	}
	if size <= 0 {
		t.Fatalf("expected positive size, got %d", size)
	}
}

func TestAuditIndexDropAndReindex(t *testing.T) {
	path := tempDB(t)
	defer os.Remove(path)

	idx, err := NewAuditIndex(path)
	if err != nil {
		t.Fatalf("create index: %v", err)
	}
	defer idx.Close()

	entry := &AuditEntry{
		Time:     "2026-07-08T10:00:00Z",
		Action:   "connected",
		ClientCN: "user1",
		Mapping:  "m",
		Target:   "t",
		SrcIP:    "1.2.3.4",
	}
	idx.Index(entry)

	if err := idx.Drop(); err != nil {
		t.Fatalf("drop: %v", err)
	}

	results, err := idx.Search(&AuditIndexQuery{CN: "user1"})
	if err != nil {
		t.Fatalf("search after drop: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results after drop, got %d", len(results))
	}
}

func TestParseTime(t *testing.T) {
	ts := parseTime("2026-07-08T10:00:00Z")
	if ts == 0 {
		t.Fatal("expected non-zero timestamp")
	}
	ts2 := parseTime("invalid")
	if ts2 != 0 {
		t.Fatal("expected 0 for invalid time")
	}
	ts3 := parseTime("")
	if ts3 != 0 {
		t.Fatal("expected 0 for empty time")
	}
}

func BenchmarkAuditIndex(b *testing.B) {
	path := tempDB(b)
	defer os.Remove(path)

	idx, err := NewAuditIndex(path)
	if err != nil {
		b.Fatalf("create index: %v", err)
	}
	defer idx.Close()

	entry := &AuditEntry{
		Time:     "2026-07-08T10:00:00Z",
		Action:   "connected",
		ClientCN: "bench-user",
		Mapping:  "m",
		Target:   "t",
		SrcIP:    "1.2.3.4",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		entry.ClientCN = "bench-user"
		idx.Index(entry)
	}
}

func TestTokenize(t *testing.T) {
	tokens := tokenize("Hello World test")
	if len(tokens) != 3 {
		t.Fatalf("expected 3 tokens, got %d: %v", len(tokens), tokens)
	}
	if tokens[0] != "hello" {
		t.Fatalf("expected hello, got %s", tokens[0])
	}
}

func TestTokenize_ColonSep(t *testing.T) {
	tokens := tokenize("gateway:admin")
	if len(tokens) != 2 {
		t.Fatalf("expected 2 tokens (gateway admin), got %d: %v", len(tokens), tokens)
	}
}

func TestTokenize_IP(t *testing.T) {
	tokens := tokenize("192.168.10.20")
	if len(tokens) != 4 {
		t.Fatalf("expected 4 tokens for IP, got %d: %v", len(tokens), tokens)
	}
}

func TestTokenize_Empty(t *testing.T) {
	if tokens := tokenize(""); tokens != nil {
		t.Fatal("expected nil for empty input")
	}
}

func TestTokenize_StopWords(t *testing.T) {
	tokens := tokenize("the and this is not a test")
	if len(tokens) != 1 || tokens[0] != "test" {
		t.Fatalf("expected [test], got %v", tokens)
	}
}

func TestTokenize_Dedupe(t *testing.T) {
	tokens := tokenize("hello hello world")
	if len(tokens) != 2 {
		t.Fatalf("expected 2 unique tokens, got %d: %v", len(tokens), tokens)
	}
}

func TestIntersectStrSlices(t *testing.T) {
	a := []string{"x", "y", "z"}
	b := []string{"y", "z", "w"}
	c := []string{"z", "w"}
	result := intersectStrSlices([][]string{a, b, c})
	if len(result) != 1 || result[0] != "z" {
		t.Fatalf("expected [z], got %v", result)
	}
}

func TestIntersectStrSlices_Empty(t *testing.T) {
	result := intersectStrSlices([][]string{{"a"}, {"b"}})
	if len(result) != 0 {
		t.Fatal("expected empty intersection")
	}
}

func TestIntersectStrSlices_Single(t *testing.T) {
	result := intersectStrSlices([][]string{{"a", "b", "c"}})
	if len(result) != 3 {
		t.Fatalf("expected 3 results, got %v", result)
	}
}

func TestIndexFTSAndSearchFTS(t *testing.T) {
	path := tempDB(t)
	defer os.Remove(path)

	idx, err := NewAuditIndex(path)
	if err != nil {
		t.Fatalf("create index: %v", err)
	}
	defer idx.Close()

	entry := &AuditEntry{
		Time:         "2026-07-08T10:00:00Z",
		Action:       "connected",
		ClientCN:     "alice",
		ClientSerial: "SER001",
		Mapping:      "ssh-gateway",
		Target:       "10.0.0.1:22",
		DenyReason:   "",
		SrcIP:        "192.168.1.1",
		Roles:        []string{"gateway:admin"},
	}
	if err := idx.Index(entry); err != nil {
		t.Fatalf("index: %v", err)
	}
	if err := idx.IndexFTS(entry); err != nil {
		t.Fatalf("index fts: %v", err)
	}

	results, err := idx.SearchFTS("alice", 10)
	if err != nil {
		t.Fatalf("search fts: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result for alice, got %d", len(results))
	}

	results, err = idx.SearchFTS("admin", 10)
	if err != nil {
		t.Fatalf("search fts: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result for admin, got %d", len(results))
	}
}

func TestSearchFTS_MultiToken(t *testing.T) {
	path := tempDB(t)
	defer os.Remove(path)

	idx, err := NewAuditIndex(path)
	if err != nil {
		t.Fatalf("create index: %v", err)
	}
	defer idx.Close()

	entries := []*AuditEntry{
		{Time: "2026-07-08T10:00:00Z", Action: "denied", ClientCN: "alice", Mapping: "ssh", Target: "10.0.0.1:22", DenyReason: "wrong role", SrcIP: "1.1.1.1"},
		{Time: "2026-07-08T10:01:00Z", Action: "connected", ClientCN: "bob", Mapping: "ssh", Target: "10.0.0.1:22", SrcIP: "2.2.2.2"},
		{Time: "2026-07-08T10:02:00Z", Action: "denied", ClientCN: "carol", Mapping: "web", Target: "10.0.0.2:443", DenyReason: "expired cert", SrcIP: "3.3.3.3"},
	}
	for _, e := range entries {
		if err := idx.Index(e); err != nil {
			t.Fatal(err)
		}
		if err := idx.IndexFTS(e); err != nil {
			t.Fatal(err)
		}
	}

	// Both tokens hit simultaneously (denied + alice)
	results, err := idx.SearchFTS("denied alice", 10)
	if err != nil {
		t.Fatalf("search fts: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result for 'denied alice', got %d", len(results))
	}

	// Only denied hits (2 results)
	results, err = idx.SearchFTS("denied", 10)
	if err != nil {
		t.Fatalf("search fts: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results for 'denied', got %d", len(results))
	}
}

func TestSearchFTS_NoMatch(t *testing.T) {
	path := tempDB(t)
	defer os.Remove(path)

	idx, err := NewAuditIndex(path)
	if err != nil {
		t.Fatalf("create index: %v", err)
	}
	defer idx.Close()

	entry := &AuditEntry{
		Time:    "2026-07-08T10:00:00Z",
		Action:  "connected",
		Mapping: "m",
		Target:  "t",
		SrcIP:   "1.2.3.4",
	}
	if err := idx.Index(entry); err != nil {
		t.Fatal(err)
	}
	if err := idx.IndexFTS(entry); err != nil {
		t.Fatal(err)
	}

	results, err := idx.SearchFTS("nonexistent", 10)
	if err != nil {
		t.Fatalf("search fts: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(results))
	}
}

func tempDB(t interface{ Name() string }) string {
	return os.TempDir() + "/audit_index_test_" + t.Name() + ".db"
}
