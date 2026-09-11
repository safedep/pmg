//go:build !windows

package fsutil

import (
	"fmt"
	"os"
)

// SecureSystemPath makes a path pmg created or fully manages safe for every
// user to read and for the superuser alone to write. os.WriteFile and
// os.Mkdir honor the process umask, so system-wide artifacts must be
// repaired explicitly. The two platforms differ: Unix sets root ownership
// and mode, and is a no-op for a process that is not root, because per-user
// artifacts follow the invoking user's umask by design. Windows applies the
// PMG security descriptor, ignores mode, and returns an error for a process
// that is not elevated.
func SecureSystemPath(path string, mode os.FileMode) error {
	if os.Geteuid() != 0 {
		return nil
	}

	if err := os.Chown(path, 0, 0); err != nil {
		return fmt.Errorf("failed to set root ownership on %s: %w", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("failed to set permissions on %s: %w", path, err)
	}
	return nil
}

// PrepareSystemDir creates a PMG-owned system directory. /etc has no hole a
// standard user can pre-create through, so pre-existing directories keep
// their permissions.
func PrepareSystemDir(dir string) error { return MkdirAllRootOwned(dir, 0o755) }

// RequireTrustedSystemFile and RequireSystemControlled are Windows checks.
// A standard user cannot put a file under /etc.
func RequireTrustedSystemFile(string) error { return nil }

func RequireSystemControlled(string) error { return nil }
