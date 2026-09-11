//go:build !windows

package fsutil

import (
	"fmt"
	"os"
)

// secureSystemPath makes a path pmg created or fully manages safe for every
// user to read and for the superuser alone to write. os.WriteFile and
// os.Mkdir honor the process umask, so system-wide artifacts must be
// repaired explicitly. The two platforms differ: Unix sets root ownership
// and mode, and is a no-op for a process that is not root, because per-user
// artifacts follow the invoking user's umask by design. Windows applies the
// PMG security descriptor, ignores mode, and returns an error for a process
// that is not elevated.
func secureSystemPath(path string, mode os.FileMode) error {
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

// prepareSystemDir creates a PMG-owned system directory. /etc has no hole a
// standard user can pre-create through, so pre-existing directories keep
// their permissions.
func prepareSystemDir(dir string) error { return mkdirAllRootOwned(dir, 0o755) }

// requireTrustedSystemFile and requireSystemControlled are Windows checks.
// A standard user cannot put a file under /etc.
func requireTrustedSystemFile(string) error { return nil }

func requireSystemControlled(string) error { return nil }

// removeSystemFile deletes a PMG-owned file. A missing file is not an error.
func removeSystemFile(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove config file %q: %w", path, err)
	}
	return nil
}
