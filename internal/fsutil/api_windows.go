//go:build windows

package fsutil

import "golang.org/x/sys/windows"

// KnownFolder resolves a Windows known folder once.
func KnownFolder(id *windows.KNOWNFOLDERID) func() string { return knownFolder(id) }
