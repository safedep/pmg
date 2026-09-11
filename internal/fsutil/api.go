package fsutil

import "os"

// SamePath reports whether a and b name the same path after cleaning.
// It folds case on Windows.
// It preserves case on other systems.
// It does not resolve symbolic links.
func SamePath(a, b string) bool { return samePath(a, b) }

// PathWithinDir reports whether path is dir itself or lexically inside it.
// It returns false when either path is empty.
// It uses the same comparison rules as SamePath.
func PathWithinDir(path, dir string) bool { return pathWithinDir(path, dir) }

// SecureSystemPath secures a path that PMG created or fully manages.
// On Unix, a root process sets root ownership and applies mode.
// On Unix, a non-root process leaves the path unchanged.
// On Windows, the function ignores mode and applies the PMG security descriptor.
// It returns an error on Windows when the process is not elevated.
func SecureSystemPath(path string, mode os.FileMode) error { return secureSystemPath(path, mode) }

// PrepareSystemDir creates a system directory that PMG manages.
// On Unix, a root process applies root ownership and mode 0755 to each directory it creates.
// It leaves existing Unix directories unchanged.
// On Windows, it protects the directory and its vendor parent.
// It also protects existing Windows directories.
// It refuses a Windows directory that a standard user owns.
// It refuses a Windows directory that is a link or junction.
func PrepareSystemDir(dir string) error { return prepareSystemDir(dir) }

// RequireTrustedSystemFile returns nil on Unix.
// On Windows, it accepts a path that does not exist.
// An existing Windows path must be a regular file with the PMG security descriptor.
// Callers must run this check before they read the file.
func RequireTrustedSystemFile(path string) error { return requireTrustedSystemFile(path) }

// RemoveSystemFile removes a system file that PMG manages.
// A missing file is not an error.
// On Windows, it first requires administrative control of the two parent directories.
// The Windows parent directories must not be links or junctions.
func RemoveSystemFile(path string) error { return removeSystemFile(path) }

// RequireSystemControlled returns nil on Unix.
// On Windows, Administrators or SYSTEM must own the path.
// No other principal may have write or delete access.
// The path must not be a link or junction.
// Callers must run this check before they use a managed configuration.
func RequireSystemControlled(path string) error { return requireSystemControlled(path) }
