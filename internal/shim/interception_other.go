//go:build !windows

package shim

import (
	"os"
	"os/exec"
	"path/filepath"
)

func interceptionPathEntries() ([]string, error) {
	return filepath.SplitList(os.Getenv("PATH")), nil
}

func interceptionLookPath([]string) func(string) (string, error) {
	return exec.LookPath
}
