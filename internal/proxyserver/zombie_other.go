//go:build !linux

package proxyserver

// isZombie is Linux-only. On macOS launchd is PID 1 and reaps orphans, and
// the daemon is not supported on Windows.
func isZombie(int) bool { return false }
