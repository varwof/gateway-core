package gw

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════
// metrics.go
// ═══════════════════════════════════════════════════════════════════

func TestMetricCounter_IncAndAdd(t *testing.T) {
	c := NewMetricCounter("boost2_req_total", "total requests", "method")
	RegisterCounter(c)
	c.Inc("GET")
	c.Inc("GET")
	c.Inc("POST")
	c.Add(10, "GET")

	out := RenderMetrics("test")
	if !strings.Contains(out, `boost2_req_total{method="GET"} 12`) {
		t.Fatalf("expected GET=12, got:\n%s", out)
	}
	if !strings.Contains(out, `boost2_req_total{method="POST"} 1`) {
		t.Fatalf("expected POST=1, got:\n%s", out)
	}
}

func TestMetricGauge_SetAndAdd(t *testing.T) {
	g := NewMetricGauge("boost2_active_conns", "active connections", "proto")
	RegisterGauge(g)
	g.Set(5, "tcp")
	g.Add(3, "tcp")
	g.Add(-2, "tcp")
	g.Set(1, "udp")

	out := RenderMetrics("test")
	if !strings.Contains(out, `boost2_active_conns{proto="tcp"} 6`) {
		t.Fatalf("expected tcp=6, got:\n%s", out)
	}
	if !strings.Contains(out, `boost2_active_conns{proto="udp"} 1`) {
		t.Fatalf("expected udp=1, got:\n%s", out)
	}
}

func TestMetricHistogram_Observe(t *testing.T) {
	h := NewMetricHistogram("boost2_latency_ms", "latency", []string{"method"}, 10, 50, 100)
	RegisterHistogram(h)
	h.Observe(5, "GET")
	h.Observe(25, "GET")
	h.Observe(75, "POST")
	h.Observe(200, "GET")

	out := RenderMetrics("test")
	if !strings.Contains(out, "boost2_latency_ms_bucket") {
		t.Fatalf("expected histogram buckets, got:\n%s", out)
	}
	if !strings.Contains(out, "boost2_latency_ms_count") {
		t.Fatalf("expected _count, got:\n%s", out)
	}
	if !strings.Contains(out, "boost2_latency_ms_sum") {
		t.Fatalf("expected _sum, got:\n%s", out)
	}
	if !strings.Contains(out, `method="GET"`) {
		t.Fatalf("expected GET label, got:\n%s", out)
	}
	if !strings.Contains(out, `method="POST"`) {
		t.Fatalf("expected POST label, got:\n%s", out)
	}
}

func TestMetricHistogram_NoLabels(t *testing.T) {
	h := NewMetricHistogram("boost2_simple_hist", "simple", []string{}, 1, 5)
	RegisterHistogram(h)
	h.Observe(3)
	out := RenderMetrics("test")
	if !strings.Contains(out, "boost2_simple_hist_bucket") {
		t.Fatalf("expected histogram bucket, got:\n%s", out)
	}
}

func TestRegisterAndRender(t *testing.T) {
	c := NewMetricCounter("test_reg_counter", "help")
	RegisterCounter(c)
	g := NewMetricGauge("test_reg_gauge", "help")
	RegisterGauge(g)
	h := NewMetricHistogram("test_reg_hist", "help", []string{}, 1, 10)
	RegisterHistogram(h)

	c.Inc()
	g.Set(42)
	h.Observe(5)

	out := RenderMetrics("build=v1.0")
	if !strings.Contains(out, "# HELP build=v1.0") {
		t.Fatalf("missing build info, got:\n%s", out)
	}
	if !strings.Contains(out, "test_reg_counter") {
		t.Fatalf("missing counter, got:\n%s", out)
	}
	if !strings.Contains(out, "test_reg_gauge") {
		t.Fatalf("missing gauge, got:\n%s", out)
	}
	if !strings.Contains(out, "test_reg_hist") {
		t.Fatalf("missing histogram, got:\n%s", out)
	}
}

func TestMetricGauge_NegativeValues(t *testing.T) {
	g := NewMetricGauge("boost2_neg_test", "help")
	RegisterGauge(g)
	g.Add(-10, "")
	g.Add(-5, "")
	out := RenderMetrics("test")
	if !strings.Contains(out, "boost2_neg_test") {
		t.Fatalf("expected metric in output")
	}
}

func TestMetricCounter_NoLabels(t *testing.T) {
	c := NewMetricCounter("boost2_simple_ctr", "help")
	RegisterCounter(c)
	c.Inc()
	c.Inc()
	out := RenderMetrics("test")
	if !strings.Contains(out, "boost2_simple_ctr") {
		t.Fatalf("expected counter in output")
	}
}

// ═══════════════════════════════════════════════════════════════════
// merkle.go
// ═══════════════════════════════════════════════════════════════════

func TestHashLeaf(t *testing.T) {
	h := HashLeaf([]byte("hello"))
	if len(h) != 32 {
		t.Fatalf("expected 32, got %d", len(h))
	}
	h2 := HashLeaf([]byte("hello"))
	if hex.EncodeToString(h) != hex.EncodeToString(h2) {
		t.Fatal("expected same hash for same input")
	}
}

func TestHashNode(t *testing.T) {
	left := HashLeaf([]byte("a"))
	right := HashLeaf([]byte("b"))
	node := HashNode(left, right)
	if len(node) != 32 {
		t.Fatalf("expected 32, got %d", len(node))
	}
	// Order matters
	node2 := HashNode(right, left)
	if hex.EncodeToString(node) == hex.EncodeToString(node2) {
		t.Fatal("expected different hash for swapped inputs")
	}
}

func TestMerkleTree_Empty(t *testing.T) {
	tree := NewMerkleTree(nil)
	if tree.Root() != nil {
		t.Fatal("expected nil root")
	}
	if tree.RootHex() != "" {
		t.Fatal("expected empty RootHex")
	}
}

func TestMerkleTree_Single(t *testing.T) {
	tree := NewMerkleTree([][]byte{[]byte("leaf1")})
	if tree.Root() == nil {
		t.Fatal("expected non-nil root")
	}
	if tree.RootHex() == "" {
		t.Fatal("expected non-empty RootHex")
	}
}

func TestMerkleTree_Multiple(t *testing.T) {
	leaves := [][]byte{
		[]byte("a"), []byte("b"), []byte("c"), []byte("d"),
	}
	tree := NewMerkleTree(leaves)
	if tree.Root() == nil {
		t.Fatal("expected non-nil root")
	}

	// Odd number of leaves
	tree2 := NewMerkleTree([][]byte{[]byte("x"), []byte("y"), []byte("z")})
	if tree2.Root() == nil {
		t.Fatal("expected non-nil root for odd leaves")
	}
}

func TestMerkleProofAndVerify(t *testing.T) {
	leaves := [][]byte{
		[]byte("entry1"), []byte("entry2"), []byte("entry3"), []byte("entry4"),
	}
	tree := NewMerkleTree(leaves)

	for i := range leaves {
		proof, err := tree.Proof(i)
		if err != nil {
			t.Fatalf("Proof(%d): %v", i, err)
		}
		if !VerifyProof(leaves[i], proof, tree.Root()) {
			t.Fatalf("VerifyProof failed for leaf %d", i)
		}
		// Wrong leaf should fail
		if VerifyProof([]byte("wrong"), proof, tree.Root()) {
			t.Fatalf("VerifyProof should fail for wrong leaf %d", i)
		}
	}
}

func TestMerkleProof_OutOfRange(t *testing.T) {
	tree := NewMerkleTree([][]byte{[]byte("a"), []byte("b")})
	_, err := tree.Proof(-1)
	if err == nil {
		t.Fatal("expected error for -1")
	}
	_, err = tree.Proof(2)
	if err == nil {
		t.Fatal("expected error for index 2")
	}
}

func TestAuditChain_SealAndVerify(t *testing.T) {
	var sealed []string
	chain := NewAuditChain(10, func(root []byte) {
		sealed = append(sealed, hex.EncodeToString(root))
	})

	entries := [][]byte{[]byte("e1"), []byte("e2"), []byte("e3")}
	st := chain.Seal(entries, "")
	if st.BatchNumber != 0 {
		t.Fatalf("expected batch 0, got %d", st.BatchNumber)
	}
	if st.Size != 3 {
		t.Fatalf("expected size 3, got %d", st.Size)
	}
	if st.Root == "" {
		t.Fatal("expected non-empty root")
	}
	if len(sealed) != 1 {
		t.Fatalf("expected 1 onSeal callback, got %d", len(sealed))
	}

	// Verify proof
	leaf := entries[0]
	proof, err := treeProofFor(chain, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := chain.Verify(0, leaf, proof)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("expected valid proof")
	}
}

func treeProofFor(chain *AuditChain, batch, leafIdx int) ([]ProofStep, error) {
	// Build the tree again to get proof
	entries := [][]byte{[]byte("e1"), []byte("e2"), []byte("e3")}
	tree := NewMerkleTree(entries)
	return tree.Proof(leafIdx)
}

func TestAuditChain_VerifyBatchNotFound(t *testing.T) {
	chain := NewAuditChain(10, nil)
	_, err := chain.Verify(0, []byte("x"), nil)
	if err == nil {
		t.Fatal("expected error for empty chain")
	}
	chain.Seal([][]byte{[]byte("a")}, "")
	_, err = chain.Verify(99, []byte("x"), nil)
	if err == nil {
		t.Fatal("expected error for batch 99")
	}
}

func TestAuditChain_LatestRoot(t *testing.T) {
	chain := NewAuditChain(10, nil)
	if chain.LatestRoot() != "" {
		t.Fatal("expected empty")
	}
	chain.Seal([][]byte{[]byte("a")}, "")
	if chain.LatestRoot() == "" {
		t.Fatal("expected non-empty after seal")
	}
	if chain.LatestRootBytes() == nil {
		t.Fatal("expected non-nil LatestRootBytes")
	}
}

func TestAuditChain_BatchCount(t *testing.T) {
	chain := NewAuditChain(10, nil)
	if chain.BatchCount() != 0 {
		t.Fatal("expected 0")
	}
	chain.Seal([][]byte{[]byte("a")}, "")
	chain.Seal([][]byte{[]byte("b")}, chain.LatestRoot())
	if chain.BatchCount() != 2 {
		t.Fatalf("expected 2, got %d", chain.BatchCount())
	}
}

func TestAuditChain_Dump(t *testing.T) {
	chain := NewAuditChain(10, nil)
	chain.Seal([][]byte{[]byte("a"), []byte("b")}, "")
	dump := chain.Dump()
	if !strings.Contains(dump, "|") {
		t.Fatalf("expected pipe-delimited dump, got: %s", dump)
	}
}

func TestAuditChain_GetTree(t *testing.T) {
	chain := NewAuditChain(10, nil)
	chain.Seal([][]byte{[]byte("a")}, "")
	if chain.GetTree(0) == nil {
		t.Fatal("expected tree at 0")
	}
	if chain.GetTree(-1) != nil {
		t.Fatal("expected nil for -1")
	}
	if chain.GetTree(1) != nil {
		t.Fatal("expected nil for 1")
	}
}

func TestAuditChain_DefaultBatchSize(t *testing.T) {
	chain := NewAuditChain(0, nil)
	if chain.batchSize != 1000 {
		t.Fatalf("expected 1000, got %d", chain.batchSize)
	}
}

func TestVerifyJSON(t *testing.T) {
	chain := NewAuditChain(10, nil)
	entries := [][]byte{[]byte("e1"), []byte("e2")}
	st := chain.Seal(entries, "")

	leaf := hex.EncodeToString(entries[0])
	resp := chain.VerifyJSON(&VerifyRequest{
		Batch: 0,
		Leaf:  leaf,
		Proof: []ProofStepJSON{},
	})
	// May be false (wrong proof) but should not error on encoding
	if resp.Error != "" {
		t.Fatalf("unexpected error: %s", resp.Error)
	}
	_ = st
}

func TestVerifyJSON_BadLeaf(t *testing.T) {
	chain := NewAuditChain(10, nil)
	resp := chain.VerifyJSON(&VerifyRequest{
		Batch: 0,
		Leaf:  "not-hex!",
	})
	if resp.Error == "" {
		t.Fatal("expected error for bad hex")
	}
}

func TestVerifyJSON_BadSibling(t *testing.T) {
	chain := NewAuditChain(10, nil)
	chain.Seal([][]byte{[]byte("a")}, "")
	resp := chain.VerifyJSON(&VerifyRequest{
		Batch: 0,
		Leaf:  hex.EncodeToString([]byte("a")),
		Proof: []ProofStepJSON{{Sibling: "bad-hex!", Left: false}},
	})
	if resp.Error == "" {
		t.Fatal("expected error for bad sibling hex")
	}
}

// ═══════════════════════════════════════════════════════════════════
// rbac.go — extended tests (basic tests in rbac_test.go)
// ═══════════════════════════════════════════════════════════════════

func TestOfflineRBAC(t *testing.T) {
	r := NewOfflineRBAC([]string{"gateway:admin"})
	if !r.CheckRole([]string{"gateway:admin"}) {
		t.Fatal("expected match")
	}
	if r.CheckRole([]string{"gateway:ops"}) {
		t.Fatal("expected no match")
	}
}

func TestOfflineRBAC_NilRoles(t *testing.T) {
	r := NewOfflineRBAC(nil)
	if r.CheckRole([]string{"gateway:admin"}) {
		t.Fatal("expected no match for nil roles")
	}
}

func TestNewOfflineRBACFromCert(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{OrganizationalUnit: []string{"gateway:deploy"}},
	}
	r := NewOfflineRBACFromCert(cert)
	if !r.CheckRole([]string{"gateway:deploy"}) {
		t.Fatal("expected match")
	}
}

func TestPeerCertRoles_NoTLS(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	roles := PeerCertRoles(r)
	if roles != nil {
		t.Fatalf("expected nil, got %v", roles)
	}
}

func TestRequireRoles(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	if RequireRoles(r, []string{"gateway:admin"}) {
		t.Fatal("expected false for no TLS")
	}
}

// ═══════════════════════════════════════════════════════════════════
// mask.go — extended tests (basic tests in mask_test.go)
// ═══════════════════════════════════════════════════════════════════

func TestMaskFilePath_NoDir(t *testing.T) {
	got := MaskFilePath("secret.pem")
	if strings.Contains(got, "secret") {
		t.Fatalf("should mask, got %s", got)
	}
	if !strings.HasSuffix(got, ".pem") {
		t.Fatalf("expected .pem suffix, got %s", got)
	}
}

func TestMaskFilePath_NoExt(t *testing.T) {
	got := MaskFilePath("/tmp/secretfile")
	if strings.Contains(got, "secretfile") {
		t.Fatalf("should mask, got %s", got)
	}
	if !strings.HasPrefix(got, "/tmp/") {
		t.Fatalf("expected /tmp/ prefix, got %s", got)
	}
}

func TestMaskFilePath_Empty(t *testing.T) {
	if got := MaskFilePath(""); got != "" {
		t.Fatalf("expected empty, got %s", got)
	}
}

func TestMaskFilePath_ShortBase(t *testing.T) {
	got := MaskFilePath("ab.pem")
	if !strings.HasSuffix(got, ".pem") {
		t.Fatalf("expected .pem suffix, got %s", got)
	}
}

func TestMaskToken_Short(t *testing.T) {
	got := MaskToken("short")
	if strings.ContainsAny(got, "short") {
		t.Fatalf("should be fully masked, got %s", got)
	}
}

func TestMaskToken_Empty(t *testing.T) {
	if got := MaskToken(""); got != "" {
		t.Fatalf("expected empty, got %s", got)
	}
}

func TestMaskEmail_NoAt(t *testing.T) {
	got := MaskEmail("noatmark")
	// No @, falls back to MaskString
	if len(got) != len("noatmark") {
		t.Fatalf("expected same length, got %s", got)
	}
}

func TestMaskEmail_ShortLocal(t *testing.T) {
	got := MaskEmail("ab@example.com")
	if !strings.HasSuffix(got, "@example.com") {
		t.Fatalf("expected domain, got %s", got)
	}
}

func TestSanitizeString_Printable(t *testing.T) {
	got := SanitizeString("Hello World 123!@#")
	if got != "Hello World 123!@#" {
		t.Fatalf("expected unchanged, got %q", got)
	}
}

// ═══════════════════════════════════════════════════════════════════
// tracker.go
// ═══════════════════════════════════════════════════════════════════

func TestConnectionTracker_AddRemove(t *testing.T) {
	tr := NewConnectionTracker()
	if !tr.Add("serial1", 5) {
		t.Fatal("expected true")
	}
	if tr.Count("serial1") != 1 {
		t.Fatalf("expected 1, got %d", tr.Count("serial1"))
	}
	if tr.Total() != 1 {
		t.Fatalf("expected total 1, got %d", tr.Total())
	}
	tr.Remove("serial1")
	if tr.Count("serial1") != 0 {
		t.Fatalf("expected 0 after remove, got %d", tr.Count("serial1"))
	}
}

func TestConnectionTracker_MaxLimit(t *testing.T) {
	tr := NewConnectionTracker()
	tr.Add("s", 2)
	tr.Add("s", 2)
	if tr.Add("s", 2) {
		t.Fatal("expected false (at max)")
	}
}

func TestConnectionTracker_NoLimit(t *testing.T) {
	tr := NewConnectionTracker()
	for i := int64(0); i < 100; i++ {
		if !tr.Add("s", 0) {
			t.Fatal("expected true with max=0 (no limit)")
		}
	}
	if tr.Count("s") != 100 {
		t.Fatalf("expected 100, got %d", tr.Count("s"))
	}
}

func TestConnectionTracker_RemoveBelowZero(t *testing.T) {
	tr := NewConnectionTracker()
	tr.Remove("nonexistent") // should not panic
	if tr.Count("nonexistent") != 0 {
		t.Fatal("expected 0")
	}
}

func TestConnectionTracker_Snapshot(t *testing.T) {
	tr := NewConnectionTracker()
	tr.Add("a", 0)
	tr.Add("b", 0)
	snap := tr.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("expected 2, got %d", len(snap))
	}
	// Snapshot is a copy
	delete(snap, "a")
	if tr.Count("a") != 1 {
		t.Fatal("deleting snapshot should not affect tracker")
	}
}

func TestConnectionTracker_Render(t *testing.T) {
	tr := NewConnectionTracker()
	tr.Add("long-serial-number-abcdef", 0)
	tr.Add("short", 0)
	out := tr.Render()
	if !strings.Contains(out, "cert_") {
		t.Fatalf("expected cert_ prefix, got:\n%s", out)
	}
	// long serial should be truncated to 16
	if strings.Contains(out, "long-serial-number-abcdef") {
		t.Fatalf("long serial should be truncated, got:\n%s", out)
	}
}

func TestConnectionTracker_TotalMultiple(t *testing.T) {
	tr := NewConnectionTracker()
	tr.Add("a", 0)
	tr.Add("a", 0)
	tr.Add("b", 0)
	if tr.Total() != 3 {
		t.Fatalf("expected 3, got %d", tr.Total())
	}
}

func TestConnectionTracker_EmptyRender(t *testing.T) {
	tr := NewConnectionTracker()
	out := tr.Render()
	if out != "" {
		t.Fatalf("expected empty, got %q", out)
	}
}
