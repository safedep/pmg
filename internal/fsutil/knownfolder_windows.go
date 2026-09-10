//go:build windows

package fsutil

import (
	"sync"

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
