//go:build !windows

// Package winacl reads and writes the Windows access control of the paths a
// system install owns. The Unix forms do nothing: the system paths on Linux
// live under /etc and /usr/local, which only root can write, so a standard
// user cannot pre-create, link or edit anything there, and mode bits are
// handled by fsutil.
package winacl

func ProcessIsElevated() bool { return false }

func Protect(string) error { return nil }

func RequireNotReparsePoint(string) error { return nil }

func RequireTrustedExisting(string) error { return nil }

func RequireProtectedDir(string) error { return nil }

func RequireAdminOnlyWritable(string) error { return nil }

func RequireExecutableByAll(string) error { return nil }
