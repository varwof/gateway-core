// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gw

import "os"

// RegisterReloadSignal registers the hot-reload signal (no-op on Windows).
func RegisterReloadSignal(_ chan os.Signal) {}

// IsReloadSignal checks whether the signal is a hot-reload signal (always false on Windows).
func IsReloadSignal(_ os.Signal) bool {
	return false
}
