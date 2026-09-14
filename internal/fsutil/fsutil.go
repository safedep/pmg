// Package fsutil provides small filesystem helpers shared across pmg packages.
package fsutil

import (
	"os"
	"path/filepath"
	"strings"
)

func comparablePath(path string) string {
	return foldCasePath(filepath.Clean(path))
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
