//go:build !windows

package fsutil

import (
	"fmt"
	"os"
)

// ForceRootOwned sets root ownership and mode on a path pmg created or fully
// manages. os.WriteFile and os.Mkdir honor the process umask, so system-wide
// artifacts must be repaired explicitly to stay usable by every user. No-op
// when not running as root: chown would fail, and per-user artifacts follow
// the invoking user's umask by design.
func ForceRootOwned(path string, mode os.FileMode) error {
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
