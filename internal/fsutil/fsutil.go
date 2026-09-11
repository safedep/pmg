// Package fsutil provides small filesystem helpers shared across pmg packages.
package fsutil

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Windows folds case because NTFS compares names through an upcase table.
// Other systems preserve case because a false match could identify a path that PMG does not own.
func comparablePath(path string) string {
	cleaned := filepath.Clean(path)
	if runtime.GOOS == "windows" {
		return strings.ToUpper(cleaned)
	}
	return cleaned
}

func samePath(a, b string) bool {
	return comparablePath(a) == comparablePath(b)
}

func pathWithinDir(path, dir string) bool {
	if path == "" || dir == "" {
		return false
	}

	keyPath, keyDir := comparablePath(path), comparablePath(dir)
	return keyPath == keyDir || strings.HasPrefix(keyPath, keyDir+string(os.PathSeparator))
}
