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

func sameFile(a, b string) bool {
	aInfo, err := os.Stat(a)
	if err != nil {
		return false
	}

	bInfo, err := os.Stat(b)
	if err != nil {
		return false
	}

	return os.SameFile(aInfo, bInfo)
}

func pathWithinDir(path, dir string) bool {
	if path == "" || dir == "" {
		return false
	}

	keyPath, keyDir := comparablePath(path), comparablePath(dir)
	return keyPath == keyDir || strings.HasPrefix(keyPath, keyDir+string(os.PathSeparator))
}
