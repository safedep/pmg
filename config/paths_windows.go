//go:build windows

package config

import (
	"path/filepath"

	"github.com/safedep/pmg/internal/fsutil"
	"golang.org/x/sys/windows"
)

// PROGRAMDATA in a user's process is theirs to set, and a value of their
// choosing would point PMG away from the managed config that governs them.
var programData = fsutil.KnownFolder(windows.FOLDERID_ProgramData, `C:\ProgramData`)

// globalConfigDir returns the directory for the globally managed config file.
func globalConfigDir() string {
	if globalConfigDirOverride != "" {
		return globalConfigDirOverride
	}
	return filepath.Join(programData(), "safedep", "pmg")
}
