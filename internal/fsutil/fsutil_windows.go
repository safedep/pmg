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

// knownFolder resolves a shell known folder once. The shell knows where the
// folder is. The matching environment variable in a user's process is theirs
// to set, so it is never consulted. When the shell cannot say, the result is
// "", because a guessed drive would protect the wrong tree.
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

// secureSystemPath makes a path pmg created or fully manages safe for every
// user to read and for administrators alone to write. The two platforms
// differ: Windows applies the PMG security descriptor, ignores mode, and
// returns an error for a process that is not elevated. Unix sets root
// ownership and mode, and is a no-op for a process that is not root.
func secureSystemPath(path string, _ os.FileMode) error { return winacl.Protect(path) }

// prepareSystemDir creates a PMG-owned system directory and its vendor
// parent. ProgramData lets a standard user create a directory, and one
// created that way stays theirs, so both components get the PMG descriptor
// even when they already exist. A component a standard user owns is refused
// rather than repaired, and neither may be a link, or the writes that
// follow would land where that user pointed them.
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

// requireTrustedSystemFile accepts a path that does not exist, and otherwise
// requires a regular file that carries the PMG descriptor.
func requireTrustedSystemFile(path string) error { return winacl.RequireTrustedExisting(path) }

// removeSystemFile deletes a PMG-owned file by name after it has established
// that the two directories above it are not links and are under
// administrative control. A delete by name follows a junction a standard
// user planted in place of a parent, and would remove a file of their
// choosing. A missing file is not an error.
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

// requireSystemControlled requires that Administrators or SYSTEM own path,
// that no other principal may write or delete it, and that it is not a
// link. The runtime applies it to the managed config before it obeys the
// file.
func requireSystemControlled(path string) error { return winacl.RequireAdministrativeControl(path) }
