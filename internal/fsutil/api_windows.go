//go:build windows

package fsutil

import "golang.org/x/sys/windows"

// KnownFolder returns a function that resolves a Windows shell known folder once.
// It does not use the matching environment variable because the user controls it.
// The returned function logs a warning and returns an empty string when resolution fails.
// Callers must treat an empty string as an unresolved folder.
func KnownFolder(id *windows.KNOWNFOLDERID) func() string { return knownFolder(id) }
