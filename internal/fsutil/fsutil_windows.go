//go:build windows

package fsutil

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/safedep/pmg/internal/winacl"
)

// ForceRootOwned is the Windows form of the Unix helper. It puts the PMG
// security descriptor on a path pmg created or fully manages. The mode has
// no Windows meaning.
func ForceRootOwned(path string, _ os.FileMode) error { return winacl.Protect(path) }

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
