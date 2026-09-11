//go:build windows

// Package winacl applies and verifies security for objects in a Windows system install.
// Its threat model includes a standard user before or after installation.
// It trusts Administrators and SYSTEM.
// It does not trust standard users.
// The PMG security descriptor gives full control to Administrators and SYSTEM.
// It gives read and execute access to Users.
// It blocks DACL inheritance.
// PMG-written objects must use the exact PMG security descriptor.
// ACL reads and writes use one handle that does not follow links.
package winacl

// Protect replaces the owner and DACL of path with the PMG security descriptor.
// It refuses a link or junction.
// It refuses an object that a standard user owns.
// It checks and updates the object through one handle.
// It returns an error when the process is not elevated.
func Protect(path string) error { return protect(path) }

// RequireProtected requires the exact PMG owner and protected DACL.
// It requires the exact set of access entries.
// It refuses a link or junction.
func RequireProtected(path string) error { return requireProtected(path) }

// RequireAdministrativeControl requires Administrators or SYSTEM to own path.
// It rejects any allow entry that gives another principal write or delete access.
// It refuses an access entry that it cannot evaluate.
// It refuses a link or junction.
// It accepts safe inherited entries from an administrator or MDM.
func RequireAdministrativeControl(path string) error { return requireAdministrativeControl(path) }

// RequireNotReparsePoint rejects a symbolic link or junction at path.
// It accepts a path that does not exist.
func RequireNotReparsePoint(path string) error { return requireNotReparsePoint(path) }

// RequireTrustedExisting accepts a path that does not exist.
// An existing path must be a regular file with the PMG security descriptor.
// It refuses a link or junction.
// Callers must run this check before they read the file.
func RequireTrustedExisting(path string) error { return requireTrustedExisting(path) }
