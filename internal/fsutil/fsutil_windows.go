//go:build windows

package fsutil

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/safedep/pmg/internal/winacl"
	"golang.org/x/sys/windows"
)

// KnownFolder resolves a shell known folder once. The shell knows where the
// folder is. The matching environment variable in a user's process is theirs
// to set, so it is never consulted.
func KnownFolder(id *windows.KNOWNFOLDERID, fallback string) func() string {
	return sync.OnceValue(func() string {
		dir, err := windows.KnownFolderPath(id, 0)
		if err != nil {
			return fallback
		}
		return dir
	})
}

// SecureSystemPath makes a path pmg created or fully manages safe for every
// user to read and for administrators alone to write. The two platforms
// differ: Windows applies the PMG security descriptor, ignores mode, and
// returns an error for a process that is not elevated. Unix sets root
// ownership and mode, and is a no-op for a process that is not root.
func SecureSystemPath(path string, _ os.FileMode) error { return winacl.Protect(path) }

// PrepareSystemDir creates a PMG-owned system directory and its vendor
// parent. ProgramData lets a standard user create a directory, and one
// created that way stays theirs, so both components get the PMG descriptor
// even when they already exist, and neither may be a link, or the writes
// that follow would land where that user pointed them.
func PrepareSystemDir(dir string) error {
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

// RequireTrustedSystemFile accepts a path that does not exist, and otherwise
// requires a regular file that carries the PMG descriptor.
func RequireTrustedSystemFile(path string) error { return winacl.RequireTrustedExisting(path) }
