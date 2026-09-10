// Package fsutil provides small filesystem helpers shared across pmg packages.
package fsutil

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// comparablePath returns the key that SamePath and PathWithinDir compare.
// It is a cleaned path, upper-cased on Windows, where C:\Users\Dev and
// C:\Users\dev name one directory and NTFS compares names through an upcase
// table. The key keeps its case everywhere else: only Windows guarantees
// case-insensitivity, and a false match on a case-sensitive volume would
// strip a directory PMG does not own. The key is for comparison only. It
// resolves no symlink and is not a path to open.
func comparablePath(path string) string {
	cleaned := filepath.Clean(path)
	if runtime.GOOS == "windows" {
		return strings.ToUpper(cleaned)
	}
	return cleaned
}

// SamePath reports whether a and b name the same path lexically.
func SamePath(a, b string) bool {
	return comparablePath(a) == comparablePath(b)
}

// PathWithinDir reports whether path is dir itself or lexically inside it.
func PathWithinDir(path, dir string) bool {
	if path == "" || dir == "" {
		return false
	}

	keyPath, keyDir := comparablePath(path), comparablePath(dir)
	return keyPath == keyDir || strings.HasPrefix(keyPath, keyDir+string(os.PathSeparator))
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
