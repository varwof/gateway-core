// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gw

import (
	"os"
	"syscall"
	"testing"
)

func TestIsReloadSignal(t *testing.T) {
	if !IsReloadSignal(syscall.SIGHUP) {
		t.Fatal("SIGHUP should be reload signal")
	}
	if IsReloadSignal(syscall.SIGTERM) {
		t.Fatal("SIGTERM should not be reload signal")
	}
}

func TestRegisterReloadSignal(t *testing.T) {
	ch := make(chan os.Signal, 1)
	RegisterReloadSignal(ch)
	// Just ensure it doesn't panic; we can't easily send SIGHUP in test
}
