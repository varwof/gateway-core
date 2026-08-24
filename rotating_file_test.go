// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package gw

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRotatingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	rf, err := NewRotatingFile(path, 50, 2)
	if err != nil {
		t.Fatalf("NewRotatingFile: %v", err)
	}

	_, err = rf.Write([]byte("hello\n"))
	if err != nil {
		t.Fatal(err)
	}

	big := make([]byte, 60)
	for i := range big {
		big[i] = 'x'
	}
	big = append(big, '\n')

	_, err = rf.Write(big)
	if err != nil {
		t.Fatal(err)
	}

	_, err = rf.Write([]byte("after rotate\n"))
	if err != nil {
		t.Fatal(err)
	}

	rf.Close()

	if _, err := os.Stat(path + ".1"); err != nil {
		t.Errorf("backup .1 should exist: %v", err)
	}

	data, _ := os.ReadFile(path)
	if len(data) == 0 {
		t.Error("rotated file should not be empty")
	}
}

func TestRotatingFileNilMaxSize(t *testing.T) {
	dir := t.TempDir()
	rf, err := NewRotatingFile(filepath.Join(dir, "test.log"), 10*1024*1024, 3)
	if err != nil {
		t.Fatal(err)
	}
	rf.Write([]byte("small\n"))
	rf.Close()
}
