//go:build !linux

package platform

// Only Linux runs the enforcing listener. Elsewhere every accept error ends
// the listener, until a platform needs its own list.
func isTransientAcceptError(error) bool { return false }
