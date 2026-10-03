//go:build !linux

package proxyserver

// RunnerExemptGlobs is Linux-only. Enforcement fails its preflight on every
// other platform before the globs matter.
func RunnerExemptGlobs() []string { return nil }

func processRunning(string) bool { return false }
