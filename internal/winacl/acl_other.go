//go:build !windows

// Package winacl applies and verifies the PMG security descriptor on a
// Windows system install. The Unix forms do nothing: the system paths on
// Linux live under /etc and /usr/local, which only root can write, and
// their modes are handled by fsutil.
package winacl

func ProcessIsElevated() bool { return false }

func RequireTrustedExisting(string) error { return nil }
