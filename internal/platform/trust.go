package platform

import "os"

// ProtectSystemPath secures a path that PMG created or fully manages.
// On Unix, a privileged process sets root ownership and applies mode.
// On Unix, an unprivileged process leaves the path unchanged.
// On Windows, the function ignores mode and applies the PMG security descriptor.
// It refuses a Windows link or junction, and an object a standard user owns.
// It returns an error on Windows when the process is not elevated.
func ProtectSystemPath(path string, mode os.FileMode) error { return protectSystemPath(path, mode) }

// PrepareSystemDir creates a system directory that PMG manages.
// On Unix, a privileged process applies root ownership and mode 0755 to each directory it creates.
// It leaves existing Unix directories unchanged.
// On Windows, it protects the directory and its vendor parent.
// It also protects existing Windows directories.
// It refuses a Windows directory that a standard user owns, or that is a link or junction.
func PrepareSystemDir(dir string) error { return prepareSystemDir(dir) }

// RequireTrustedSystemFile returns nil on Unix.
// On Windows, it accepts a path that does not exist.
// An existing Windows path must be a regular file with the exact PMG security descriptor.
// The installer and doctor use it. Callers must run this check before they read the file.
func RequireTrustedSystemFile(path string) error { return requireTrustedSystemFile(path) }

// RequireProtected returns nil on Unix.
// On Windows, path must exist and carry the exact PMG owner and protected DACL.
// It refuses a link or junction.
func RequireProtected(path string) error { return requireProtected(path) }

// RequireSystemControlled checks that only a system account controls path.
// On Unix, root must own path and each directory from / down to it.
// No group or other write is allowed, except on a sticky directory.
// A link is followed only when root owns it, and its target must pass the same check.
// On Windows, it checks path alone. Administrators or SYSTEM must own it.
// No other principal may have write or delete access.
// It accepts safe inherited entries from an administrator or MDM.
// A Windows path must not be a link or junction.
// The runtime uses it before it obeys a managed configuration.
func RequireSystemControlled(path string) error { return requireSystemControlled(path) }

// RequireExclusiveSystemDir refuses a directory in which an account other
// than the system account can create an entry. RequireSystemControlled
// accepts a sticky directory that others can write, such as /tmp in a path.
// A directory that holds a managed file must refuse that too, or another
// account can create the file between a check and a write.
func RequireExclusiveSystemDir(path string) error { return requireExclusiveSystemDir(path) }

// RequireNotReparsePoint rejects a symbolic link at path, and a junction on Windows.
// It accepts a path that does not exist.
func RequireNotReparsePoint(path string) error { return requireNotReparsePoint(path) }

// RemoveSystemFile removes a system file that PMG manages.
// A missing file is not an error.
// On Windows, it first requires administrative control of the two parent directories.
// The Windows parent directories must not be links or junctions.
func RemoveSystemFile(path string) error { return removeSystemFile(path) }
