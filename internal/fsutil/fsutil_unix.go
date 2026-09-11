//go:build !windows

package fsutil

import (
	"fmt"
	"os"
)

// File creation honors the process umask.
// Root repairs system artifacts while other users keep their configured umask.
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

// A standard user cannot create an entry under /etc.
// PMG therefore leaves existing directories unchanged.
func prepareSystemDir(dir string) error { return mkdirAllRootOwned(dir, 0o755) }

func requireTrustedSystemFile(string) error { return nil }

func requireSystemControlled(string) error { return nil }

func removeSystemFile(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove config file %q: %w", path, err)
	}
	return nil
}
