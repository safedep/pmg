//go:build windows

package config

import "golang.org/x/sys/windows"

// programDataDir asks the shell for ProgramData rather than the environment.
// PROGRAMDATA in a user's process is theirs to set, and a value of their
// choosing would point PMG away from the managed config that governs them.
func programDataDir() string {
	dir, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return `C:\ProgramData`
	}
	return dir
}
