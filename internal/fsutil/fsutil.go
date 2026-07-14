// Package fsutil provides small filesystem helpers shared across pmg packages.
package fsutil

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PathWithinDir reports whether path is dir itself or lexically inside it.
func PathWithinDir(path, dir string) bool {
	if path == "" || dir == "" {
		return false
	}

	cleanPath, cleanDir := filepath.Clean(path), filepath.Clean(dir)
	return cleanPath == cleanDir || strings.HasPrefix(cleanPath, cleanDir+string(os.PathSeparator))
}

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

// MkdirAllRootOwned creates dir and any missing parents like os.MkdirAll,
// forcing root ownership and mode on every component this call creates.
// Pre-existing directories are left untouched: pmg only manages permissions
// of artifacts it creates.
func MkdirAllRootOwned(dir string, mode os.FileMode) error {
	if info, err := os.Stat(dir); err == nil {
		if info.IsDir() {
			return nil
		}
		return fmt.Errorf("%s exists and is not a directory", dir)
	}

	if parent := filepath.Dir(dir); parent != dir {
		if err := MkdirAllRootOwned(parent, mode); err != nil {
			return err
		}
	}

	if err := os.Mkdir(dir, mode); err != nil {
		if os.IsExist(err) {
			return nil
		}
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	return ForceRootOwned(dir, mode)
}
