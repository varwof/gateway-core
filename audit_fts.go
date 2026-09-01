// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode"

	bolt "go.etcd.io/bbolt"
)

// stopWords are common words ignored in the FTS index.
var stopWords = map[string]bool{
	"the": true, "a": true, "an": true, "is": true, "was": true,
	"are": true, "were": true, "be": true, "been": true, "being": true,
	"have": true, "has": true, "had": true, "do": true, "does": true,
	"did": true, "will": true, "would": true, "could": true, "should": true,
	"may": true, "might": true, "can": true, "shall": true, "to": true,
	"of": true, "in": true, "for": true, "on": true, "with": true,
	"at": true, "by": true, "from": true, "as": true, "into": true,
	"through": true, "during": true, "after": true,
	"above": true, "below": true, "between": true, "and": true, "or": true,
	"not": true, "no": true, "but": true, "if": true, "so": true,
	"this": true, "that": true, "it": true, "its": true, "error": true,
}

// tokenize splits text into lowercase tokens, filtering stop words and short words.
// Also splits on common delimiters like : . / - _.
func tokenize(text string) []string {
	if text == "" {
		return nil
	}
	// Replace common delimiters with spaces
	replacer := strings.NewReplacer(
		":", " ", ".", " ", "/", " ",
		"-", " ", "_", " ", "=", " ",
	)
	text = replacer.Replace(text)
	seen := make(map[string]bool)
	var tokens []string
	for _, field := range strings.Fields(text) {
		word := strings.TrimFunc(strings.ToLower(field), func(r rune) bool {
			return !unicode.IsLetter(r) && !unicode.IsDigit(r)
		})
		if len(word) < 2 || stopWords[word] {
			continue
		}
		if !seen[word] {
			seen[word] = true
			tokens = append(tokens, word)
		}
	}
	return tokens
}

// ftsFields returns the text of fields in an audit entry that are available for full-text search.
func ftsFields(entry *AuditEntry) string {
	var parts []string
	if entry.Action != "" {
		parts = append(parts, entry.Action)
	}
	if entry.ClientCN != "" {
		parts = append(parts, entry.ClientCN)
	}
	if entry.DenyReason != "" {
		parts = append(parts, entry.DenyReason)
	}
	if entry.Target != "" {
		parts = append(parts, entry.Target)
	}
	if entry.SrcIP != "" {
		parts = append(parts, entry.SrcIP)
	}
	if entry.Mapping != "" {
		parts = append(parts, entry.Mapping)
	}
	if entry.AgentId != "" {
		parts = append(parts, entry.AgentId)
	}
	if entry.SPIFFEID != "" {
		parts = append(parts, entry.SPIFFEID)
	}
	if entry.PrincipalUid != "" {
		parts = append(parts, entry.PrincipalUid)
	}
	if len(entry.Roles) > 0 {
		parts = append(parts, strings.Join(entry.Roles, " "))
	}
	if len(entry.Capabilities) > 0 {
		parts = append(parts, strings.Join(entry.Capabilities, " "))
	}
	return strings.Join(parts, " ")
}

// appendWordPosting appends hash to a space-separated postings list, evicting
// the oldest entries beyond max. Finding 23: by_word postings must not grow
// without bound on hot terms.
func appendWordPosting(existing []byte, hash string, max int) []byte {
	if len(existing) == 0 {
		return []byte(hash)
	}
	words := strings.Fields(string(existing))
	for _, w := range words {
		if w == hash {
			return existing
		}
	}
	words = append(words, hash)
	if max > 0 && len(words) > max {
		words = words[len(words)-max:]
	}
	return []byte(strings.Join(words, " "))
}

// indexFTSInTx is the FTS indexing function used internally by Index, reusing an existing transaction.
func indexFTSInTx(tx *bolt.Tx, hash string, entry *AuditEntry) error {
	tokens := tokenize(ftsFields(entry))
	if len(tokens) == 0 {
		return nil
	}
	bw, err := tx.CreateBucketIfNotExists([]byte("by_word"))
	if err != nil {
		return err
	}
	for _, tok := range tokens {
		existing := bw.Get([]byte(tok))
		updated := appendWordPosting(existing, hash, MaxPostingsPerKey)
		if err := bw.Put([]byte(tok), updated); err != nil {
			return err
		}
	}
	return nil
}

// IndexFTS indexes the text fields of an audit entry as searchable word tokens.
// Typically called automatically by Index(), but can also be used standalone.
func (idx *AuditIndex) IndexFTS(entry *AuditEntry) error {
	data := entryToJSON(entry)
	hash := fmt.Sprintf("%x", HashLeaf(data))
	tokens := tokenize(ftsFields(entry))
	if len(tokens) == 0 {
		return nil
	}
	return idx.db.Update(func(tx *bolt.Tx) error {
		bw := tx.Bucket([]byte("by_word"))
		if bw == nil {
			var err error
			bw, err = tx.CreateBucketIfNotExists([]byte("by_word"))
			if err != nil {
				return err
			}
		}
		for _, tok := range tokens {
			existing := bw.Get([]byte(tok))
			updated := appendWordPosting(existing, hash, MaxPostingsPerKey)
			if err := bw.Put([]byte(tok), updated); err != nil {
				return err
			}
		}
		return nil
	})
}

// SearchFTS executes a full-text search query, returning matching audit index entries.
// Multiple words in the query are ANDed together. Results are sorted by time descending.
func (idx *AuditIndex) SearchFTS(query string, limit int) ([]AuditIndexEntry, error) {
	if limit <= 0 {
		return nil, nil
	}
	tokens := tokenize(query)
	if len(tokens) == 0 {
		return nil, nil
	}
	var merged []AuditIndexEntry
	err := idx.db.View(func(tx *bolt.Tx) error {
		bw := tx.Bucket([]byte("by_word"))
		if bw == nil {
			return nil
		}
		e := tx.Bucket([]byte("entries"))
		if e == nil {
			return nil
		}
		// Collect hash sets for each token
		var sets [][]string
		for _, tok := range tokens {
			val := bw.Get([]byte(tok))
			if val == nil {
				return nil
			}
			sets = append(sets, strings.Fields(string(val)))
		}
		if len(sets) == 0 {
			return nil
		}
		// Intersect multiple token sets
		hashes := intersectStrSlices(sets)
		if len(hashes) == 0 {
			return nil
		}
		// Load entries and collect timestamps
		type he struct {
			hash string
			time int64
		}
		var entries []he
		for _, h := range hashes {
			raw := e.Get([]byte(h))
			if raw == nil {
				continue
			}
			var entry AuditEntry
			if err := json.Unmarshal(raw, &entry); err != nil {
				continue
			}
			t := parseTime(entry.Time)
			entries = append(entries, he{hash: h, time: t})
		}
		// Sort by time descending
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].time > entries[j].time
		})
		if len(entries) > limit {
			entries = entries[:limit]
		}
		for _, hentry := range entries {
			entry := idx.loadEntry(tx, []byte(hentry.hash))
			if entry != nil {
				merged = append(merged, *entry)
			}
		}
		return nil
	})
	return merged, err
}

func entryToJSON(entry *AuditEntry) []byte {
	data, _ := json.Marshal(entry)
	return data
}

// intersectStrSlices returns strings that appear in all slices.
func intersectStrSlices(sets [][]string) []string {
	if len(sets) == 0 {
		return nil
	}
	freq := make(map[string]int)
	for _, s := range sets[0] {
		freq[s]++
	}
	for i := 1; i < len(sets); i++ {
		seen := make(map[string]bool)
		for _, s := range sets[i] {
			if !seen[s] {
				freq[s]++
				seen[s] = true
			}
		}
	}
	target := len(sets)
	var result []string
	for s, c := range freq {
		if c == target {
			result = append(result, s)
		}
	}
	return result
}
