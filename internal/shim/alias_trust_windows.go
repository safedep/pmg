//go:build windows

package shim

// trustedAlias has no ownership model to check on Windows, so per-user
// shims keep the resolved executable path there.
func trustedAlias(string) bool { return false }
