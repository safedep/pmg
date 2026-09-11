//go:build windows

package fsutil

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/internal/winacl"
	"golang.org/x/sys/windows"
)

func knownFolder(id *windows.KNOWNFOLDERID) func() string {
	return sync.OnceValue(func() string {
		dir, err := windows.KnownFolderPath(id, 0)
		if err != nil {
			log.Warnf("failed to resolve a Windows known folder: %v", err)
			return ""
		}
		return dir
	})
}

func secureSystemPath(path string, _ os.FileMode) error { return winacl.Protect(path) }

// ProgramData permits a standard user to create a directory.
// PMG therefore checks and protects both managed components.
func prepareSystemDir(dir string) error {
	components := []string{filepath.Dir(dir), dir}
	for _, d := range components {
		if err := winacl.RequireNotReparsePoint(d); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}
	for _, d := range components {
		if err := winacl.Protect(d); err != nil {
			return err
		}
	}
	return nil
}

func requireTrustedSystemFile(path string) error { return winacl.RequireTrustedExisting(path) }

// os.Remove deletes by name and can follow a junction in a parent path.
// The parent checks prevent a user from redirecting the deletion.
func removeSystemFile(path string) error {
	dir := filepath.Dir(path)
	for _, d := range []string{filepath.Dir(dir), dir} {
		if _, err := os.Lstat(d); os.IsNotExist(err) {
			return nil
		}
		if err := winacl.RequireAdministrativeControl(d); err != nil {
			return fmt.Errorf("refusing to remove %s: %w", path, err)
		}
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove %s: %w", path, err)
	}
	return nil
}

func requireSystemControlled(path string) error { return winacl.RequireAdministrativeControl(path) }
