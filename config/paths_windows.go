//go:build windows

package config

import (
	"path/filepath"
	"sync"

	"golang.org/x/sys/windows"
)

// The shell knows where ProgramData is. PROGRAMDATA in a user's process is
// theirs to set, and a value of their choosing would point PMG away from the
// managed config that governs them.
var programData = sync.OnceValue(func() string {
	dir, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return `C:\ProgramData`
	}
	return dir
})

// globalConfigDir returns the directory for the globally managed config file.
func globalConfigDir() string {
	if globalConfigDirOverride != "" {
		return globalConfigDirOverride
	}
	return filepath.Join(programData(), "safedep", "pmg")
}
