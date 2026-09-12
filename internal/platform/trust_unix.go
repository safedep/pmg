//go:build unix

package platform

import (
	"fmt"
	"os"
	"path/filepath"
)

// File creation honors the process umask.
// Root repairs system artifacts while other users keep their configured umask.
func protectSystemPath(path string, mode os.FileMode) error {
	if !IsPrivileged() {
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

// mkdirAllRootOwned creates dir and any missing parents like os.MkdirAll,
// forcing root ownership and mode on every component this call creates.
// Pre-existing directories are left untouched: pmg only manages permissions
// of artifacts it creates.
func mkdirAllRootOwned(dir string, mode os.FileMode) error {
	if info, err := os.Stat(dir); err == nil {
		if info.IsDir() {
			return nil
		}
		return fmt.Errorf("%s exists and is not a directory", dir)
	}

	if parent := filepath.Dir(dir); parent != dir {
		if err := mkdirAllRootOwned(parent, mode); err != nil {
			return err
		}
	}

	if err := os.Mkdir(dir, mode); err != nil {
		if os.IsExist(err) {
			return nil
		}
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	return protectSystemPath(dir, mode)
}

func requireTrustedSystemFile(string) error { return nil }

func requireProtected(string) error { return nil }

func requireSystemControlled(string) error { return nil }

func requireNotReparsePoint(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to inspect %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a link, which PMG does not follow in a system path", path)
	}
	return nil
}

func removeSystemFile(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove config file %q: %w", path, err)
	}
	return nil
}
