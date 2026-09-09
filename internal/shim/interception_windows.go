//go:build windows

package shim

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func interceptionPathEntries() ([]string, error) {
	return registryPathEntries()
}

// interceptionLookPath resolves a name over the given PATH entries with the
// PATHEXT rule, so the answer matches what a new shell would run.
func interceptionLookPath(pathEntries []string) func(string) (string, error) {
	exts := pathExtensions()
	return func(name string) (string, error) {
		return lookInDirs(name, pathEntries, exts)
	}
}

func pathExtensions() []string {
	exts := os.Getenv("PATHEXT")
	if exts == "" {
		exts = ".COM;.EXE;.BAT;.CMD"
	}
	return strings.Split(exts, ";")
}

// lookInDirs lower-cases each extension, as exec.LookPath does, so a
// resolved path reads `npm.cmd` rather than `npm.CMD`.
func lookInDirs(name string, dirs, exts []string) (string, error) {
	for _, dir := range dirs {
		for _, ext := range exts {
			candidate := filepath.Join(dir, name+strings.ToLower(ext))
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate, nil
			}
		}
	}
	return "", &exec.Error{Name: name, Err: exec.ErrNotFound}
}
