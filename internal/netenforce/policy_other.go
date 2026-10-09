//go:build !linux

package netenforce

// WritableExemptPaths is Linux-only. Enforcement fails its preflight on
// every other platform before exempt paths matter.
func WritableExemptPaths([]string) []string { return nil }
