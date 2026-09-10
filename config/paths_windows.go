//go:build windows

package config

import "golang.org/x/sys/windows"

// The shell knows where ProgramData is. PROGRAMDATA in a user's process is
// theirs to set, and a value of their choosing would point PMG away from the
// managed config that governs them.
func init() {
	programDataDir = `C:\ProgramData`
	if dir, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0); err == nil {
		programDataDir = dir
	}
}
