//go:build windows

package winacl

// ProcessIsElevated reports whether UAC elevated this process.
func ProcessIsElevated() bool { return processIsElevated() }

// Protect applies the PMG security descriptor to a path.
func Protect(path string) error { return protect(path) }

// RequireProtected checks whether a path has the PMG security descriptor.
func RequireProtected(path string) error { return requireProtected(path) }

// RequireAdministrativeControl checks whether administrators control a path.
func RequireAdministrativeControl(path string) error { return requireAdministrativeControl(path) }

// RequireNotReparsePoint rejects a link or junction at a path.
func RequireNotReparsePoint(path string) error { return requireNotReparsePoint(path) }

// RequireTrustedExisting checks an existing file against the PMG security descriptor.
func RequireTrustedExisting(path string) error { return requireTrustedExisting(path) }
