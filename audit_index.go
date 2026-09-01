// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// AuditIndex is the audit log index, a hash-chain index based on bbolt.
type AuditIndex struct {
	db *bolt.DB
}

// MaxPostingsPerKey caps the number of hash postings kept under a single
// by_cn / by_serial / by_word key (finding 23). Without a bound these postings
// lists grow forever on high-activity keys (common CN, common word).
const MaxPostingsPerKey = 1000

// AuditIndexEntry is an audit index entry containing hash and metadata.
type AuditIndexEntry struct {
	Hash     string `json:"hash"`
	CN       string `json:"cn,omitempty"`
	Serial   string `json:"serial,omitempty"`
	Action   string `json:"action"`
	Target   string `json:"target,omitempty"`
	Time     int64  `json:"time"`
	RawEntry string `json:"raw_entry,omitempty"`
}

// AuditIndexQuery is the audit index query parameters.
type AuditIndexQuery struct {
	CN     string `json:"cn,omitempty"`
	Serial string `json:"serial,omitempty"`
	Since  int64  `json:"since,omitempty"`
	Until  int64  `json:"until,omitempty"`
	Limit  int    `json:"limit,omitempty"`
	Offset int    `json:"offset,omitempty"`
}

// NewAuditIndex creates an audit index instance.
func NewAuditIndex(path string) (*AuditIndex, error) {
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open audit index: %w", err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range []string{"entries", "by_cn", "by_serial", "by_time", "by_word"} {
			if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
				return fmt.Errorf("create bucket %s: %w", name, err)
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &AuditIndex{db: db}, nil
}

// Close closes the audit index database.
func (idx *AuditIndex) Close() error {
	return idx.db.Close()
}

// Index indexes a single audit entry.
func (idx *AuditIndex) Index(entry *AuditEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal entry: %w", err)
	}
	hash := fmt.Sprintf("%x", HashLeaf(data))

	ts := parseTime(entry.Time)
	idxEntry := AuditIndexEntry{
		Hash:     hash,
		CN:       entry.ClientCN,
		Serial:   entry.ClientSerial,
		Action:   entry.Action,
		Target:   entry.Target,
		Time:     ts,
		RawEntry: string(data),
	}

	return idx.db.Update(func(tx *bolt.Tx) error {
		e := tx.Bucket([]byte("entries"))
		if err := e.Put([]byte(hash), data); err != nil {
			return err
		}

		bt := tx.Bucket([]byte("by_time"))
		tKey := make([]byte, 8, 8+len(hash))
		binary.BigEndian.PutUint64(tKey, uint64(ts))
		tKey = append(tKey, []byte(hash)...)
		if err := bt.Put(tKey, []byte(hash)); err != nil {
			return err
		}

		if idxEntry.CN != "" {
			bc := tx.Bucket([]byte("by_cn"))
			updated := appendPosting(bc.Get([]byte(idxEntry.CN)), hash, '\n', MaxPostingsPerKey)
			if err := bc.Put([]byte(idxEntry.CN), updated); err != nil {
				return err
			}
		}
		if idxEntry.Serial != "" {
			bs := tx.Bucket([]byte("by_serial"))
			updated := appendPosting(bs.Get([]byte(idxEntry.Serial)), hash, '\n', MaxPostingsPerKey)
			if err := bs.Put([]byte(idxEntry.Serial), updated); err != nil {
				return err
			}
		}

		// Auto full-text index
		if err := indexFTSInTx(tx, hash, entry); err != nil {
			return err
		}

		return nil
	})
}

// Search searches the audit index by query criteria.
func (idx *AuditIndex) Search(q *AuditIndexQuery) ([]AuditIndexEntry, error) {
	var results []AuditIndexEntry
	limit := q.Limit
	if limit <= 0 {
		limit = 100
	}

	err := idx.db.View(func(tx *bolt.Tx) error {
		if q.CN != "" {
			bc := tx.Bucket([]byte("by_cn"))
			return idx.searchByIndex(bc, []byte(q.CN), tx, q, &results, limit)
		}
		if q.Serial != "" {
			bs := tx.Bucket([]byte("by_serial"))
			return idx.searchByIndex(bs, []byte(q.Serial), tx, q, &results, limit)
		}
		bt := tx.Bucket([]byte("by_time"))
		c := bt.Cursor()

		start := make([]byte, 8)
		if q.Since > 0 {
			binary.BigEndian.PutUint64(start, uint64(q.Since))
		} else {
			binary.BigEndian.PutUint64(start, 0)
		}

		end := make([]byte, 8)
		if q.Until > 0 {
			binary.BigEndian.PutUint64(end, uint64(q.Until))
			// Composite key = time(8B) + hash, extend end to full width to ensure entries within the until second are hit
			end = append(end, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)
		} else {
			binary.BigEndian.PutUint64(end, ^uint64(0))
		}

		skipped := 0
		for k, v := c.Seek(start); k != nil && bytesLessOrEqual(k, end); k, v = c.Next() {
			if skipped < q.Offset {
				skipped++
				continue
			}
			if len(results) >= limit {
				break
			}
			entry := idx.loadEntry(tx, v)
			if entry != nil {
				results = append(results, *entry)
			}
		}
		return nil
	})

	if err != nil {
		return nil, err
	}
	return results, nil
}

func (idx *AuditIndex) searchByIndex(bucket *bolt.Bucket, key []byte, tx *bolt.Tx, q *AuditIndexQuery, results *[]AuditIndexEntry, limit int) error {
	val := bucket.Get(key)
	if val == nil {
		return nil
	}
	hashes := splitLines(val)
	skipped := 0
	for _, h := range hashes {
		if skipped < q.Offset {
			skipped++
			continue
		}
		if len(*results) >= limit {
			break
		}
		entry := idx.loadEntry(tx, []byte(h))
		if entry != nil {
			if q.Since > 0 && entry.Time < q.Since {
				continue
			}
			if q.Until > 0 && entry.Time > q.Until {
				continue
			}
			*results = append(*results, *entry)
		}
	}
	return nil
}

func (idx *AuditIndex) loadEntry(tx *bolt.Tx, hash []byte) *AuditIndexEntry {
	e := tx.Bucket([]byte("entries"))
	data := e.Get(hash)
	if data == nil {
		return nil
	}
	var entry AuditEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil
	}
	return &AuditIndexEntry{
		Hash:     string(hash),
		CN:       entry.ClientCN,
		Serial:   entry.ClientSerial,
		Action:   entry.Action,
		Target:   entry.Target,
		Time:     parseTime(entry.Time),
		RawEntry: string(data),
	}
}

// Size returns the index database size.
func (idx *AuditIndex) Size() (int64, error) {
	var size int64
	err := idx.db.View(func(tx *bolt.Tx) error {
		size = int64(tx.Size())
		return nil
	})
	return size, err
}

// Drop clears all index data.
func (idx *AuditIndex) Drop() error {
	return idx.db.Update(func(tx *bolt.Tx) error {
		for _, name := range []string{"entries", "by_cn", "by_serial", "by_time", "by_word"} {
			b := tx.Bucket([]byte(name))
			if b != nil {
				if err := tx.DeleteBucket([]byte(name)); err != nil {
					return err
				}
				if _, err := tx.CreateBucket([]byte(name)); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// DBPath returns the underlying database file path for external inspection.
func (idx *AuditIndex) DBPath() string {
	return idx.db.Path()
}

func parseTime(s string) int64 {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return 0
	}
	return t.Unix()
}

func bytesLessOrEqual(a, b []byte) bool {
	return string(a) <= string(b)
}

func splitLines(data []byte) []string {
	var lines []string
	start := 0
	for i := 0; i < len(data); i++ {
		if data[i] == '\n' {
			if i > start {
				lines = append(lines, string(data[start:i]))
			}
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, string(data[start:]))
	}
	return lines
}

// appendPosting appends hash to an existing postings list (separated by sep),
// evicting the oldest entries so the list never exceeds max. Finding 23: the
// by_cn / by_serial postings must not grow without bound on hot keys.
func appendPosting(existing []byte, hash string, sep byte, max int) []byte {
	if len(existing) == 0 {
		return []byte(hash)
	}
	lines := splitLines(existing)
	lines = append(lines, hash)
	if max > 0 && len(lines) > max {
		lines = lines[len(lines)-max:]
	}
	out := make([]byte, 0, len(existing)+len(hash)+1)
	for i, l := range lines {
		if i > 0 {
			out = append(out, sep)
		}
		out = append(out, l...)
	}
	if sep != '\n' {
		return append(out, sep)
	}
	return out
}
