//go:build !windows

package gw

import (
	"os"
	"os/signal"
	"syscall"
)

// RegisterReloadSignal registers the SIGHUP hot-reload signal.
func RegisterReloadSignal(sigCh chan os.Signal) {
	signal.Notify(sigCh, syscall.SIGHUP)
}

// IsReloadSignal checks whether the signal is SIGHUP hot-reload.
func IsReloadSignal(sig os.Signal) bool {
	return sig == syscall.SIGHUP
}
