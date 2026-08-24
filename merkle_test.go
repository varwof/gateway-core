package gw

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestMerkleTreeEmpty(t *testing.T) {
	m := NewMerkleTree(nil)
	if m.Root() != nil {
		t.Fatal("expected nil root for empty tree")
	}
}

func TestMerkleTreeSingleLeaf(t *testing.T) {
	leaf := []byte("hello")
	m := NewMerkleTree([][]byte{leaf})
	expected := sha256.Sum256([]byte("hello"))
	if string(m.Root()) != string(expected[:]) {
		t.Fatalf("root mismatch for single leaf")
	}
}

func TestMerkleTreeTwoLeaves(t *testing.T) {
	a, b := []byte("a"), []byte("b")
	m := NewMerkleTree([][]byte{a, b})
	ha := HashLeaf(a)
	hb := HashLeaf(b)
	expected := HashNode(ha, hb)
	if string(m.Root()) != string(expected) {
		t.Fatalf("root mismatch for two leaves")
	}
}

func TestMerkleTreeVerify(t *testing.T) {
	leaves := [][]byte{
		[]byte("entry1"),
		[]byte("entry2"),
		[]byte("entry3"),
		[]byte("entry4"),
	}
	m := NewMerkleTree(leaves)
	root := m.Root()

	for i, leaf := range leaves {
		proof, err := m.Proof(i)
		if err != nil {
			t.Fatalf("proof for index %d: %v", i, err)
		}
		if !VerifyProof(leaf, proof, root) {
			t.Fatalf("verify failed for leaf %d", i)
		}
	}
}

func TestMerkleTreeOddLeaves(t *testing.T) {
	leaves := [][]byte{
		[]byte("entry1"),
		[]byte("entry2"),
		[]byte("entry3"),
	}
	m := NewMerkleTree(leaves)
	root := m.Root()

	for i, leaf := range leaves {
		proof, err := m.Proof(i)
		if err != nil {
			t.Fatalf("proof for index %d: %v", i, err)
		}
		if !VerifyProof(leaf, proof, root) {
			t.Fatalf("verify failed for leaf %d", i)
		}
	}
}

func TestMerkleTreeInvalidProof(t *testing.T) {
	leaves := [][]byte{
		[]byte("entry1"),
		[]byte("entry2"),
	}
	m := NewMerkleTree(leaves)
	root := m.Root()

	proof, _ := m.Proof(0)
	if VerifyProof([]byte("fake"), proof, root) {
		t.Fatal("verify should fail for fake leaf")
	}
}

func TestMerkleTreeLarge(t *testing.T) {
	n := 100
	leaves := make([][]byte, n)
	for i := range leaves {
		leaves[i] = []byte{byte(i)}
	}
	m := NewMerkleTree(leaves)
	root := m.Root()

	for i, leaf := range leaves {
		proof, err := m.Proof(i)
		if err != nil {
			t.Fatalf("proof for index %d: %v", i, err)
		}
		if !VerifyProof(leaf, proof, root) {
			t.Fatalf("verify failed for leaf %d", i)
		}
	}
}

func TestAuditChainSeal(t *testing.T) {
	var sealedRoots [][]byte
	onSeal := func(root []byte) {
		sealedRoots = append(sealedRoots, root)
	}

	chain := NewAuditChain(10, onSeal)

	entries := [][]byte{
		[]byte("audit1"),
		[]byte("audit2"),
	}
	st := chain.Seal(entries, "")
	if st.BatchNumber != 0 {
		t.Fatalf("expected batch 0, got %d", st.BatchNumber)
	}
	if st.Size != 2 {
		t.Fatalf("expected size 2, got %d", st.Size)
	}
	if st.Root == "" {
		t.Fatal("expected non-empty root")
	}

	if chain.BatchCount() != 1 {
		t.Fatalf("expected 1 batch, got %d", chain.BatchCount())
	}

	if len(sealedRoots) != 1 {
		t.Fatalf("expected 1 seal callback, got %d", len(sealedRoots))
	}
}

func TestAuditChainVerify(t *testing.T) {
	chain := NewAuditChain(10, nil)

	entries := [][]byte{
		[]byte("entry_a"),
		[]byte("entry_b"),
		[]byte("entry_c"),
	}
	st := chain.Seal(entries, "")

	tree := NewMerkleTree(entries)
	proof, _ := tree.Proof(1)

	ok, err := chain.Verify(st.BatchNumber, entries[1], proof)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if !ok {
		t.Fatal("expected verify to succeed")
	}

	// wrong batch
	_, err = chain.Verify(99, entries[1], proof)
	if err == nil {
		t.Fatal("expected error for invalid batch")
	}
}

func TestAuditChainMultipleBatches(t *testing.T) {
	chain := NewAuditChain(10, nil)

	// batch 0
	prev := ""
	for i := 0; i < 3; i++ {
		entries := [][]byte{[]byte("batch" + string(rune('0'+i)))}
		st := chain.Seal(entries, prev)
		prev = st.Root
	}

	if chain.BatchCount() != 3 {
		t.Fatalf("expected 3 batches, got %d", chain.BatchCount())
	}

	// verify that chain links
	trees := make([]*MerkleTree, 3)
	for i := 0; i < 3; i++ {
		st := chain.GetTree(i)
		trees[i] = NewMerkleTree([][]byte{[]byte("batch" + string(rune('0'+i)))})
		if st.Root != trees[i].RootHex() {
			t.Fatalf("batch %d root mismatch", i)
		}
	}
}

func TestAuditChainDump(t *testing.T) {
	chain := NewAuditChain(10, nil)
	chain.Seal([][]byte{[]byte("e1")}, "")
	chain.Seal([][]byte{[]byte("e2")}, chain.LatestRoot())

	dump := chain.Dump()
	if dump == "" {
		t.Fatal("expected non-empty dump")
	}
}

func TestProofStepJSON(t *testing.T) {
	sibling := sha256.Sum256([]byte("sibling"))
	step := ProofStep{Sibling: sibling[:], Left: true}
	_ = step
}

func BenchmarkMerkleTree(b *testing.B) {
	leaves := make([][]byte, 1000)
	for i := range leaves {
		leaves[i] = []byte{byte(i)}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewMerkleTree(leaves)
	}
}

func TestRootHex(t *testing.T) {
	m := NewMerkleTree([][]byte{[]byte("test")})
	h := m.RootHex()
	if len(h) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(h))
	}
	_, err := hex.DecodeString(h)
	if err != nil {
		t.Fatalf("invalid hex: %v", err)
	}
}
