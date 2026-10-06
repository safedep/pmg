//go:build !linux

package platform

// On macOS launchd is PID 1 and reaps orphans. The proxy daemon is not
// supported on Windows.
func isZombieProcess(int) bool { return false }
