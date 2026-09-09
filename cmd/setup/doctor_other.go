//go:build !windows

package setup

import (
	"os"
	"os/exec"
	"path/filepath"

	"github.com/safedep/pmg/internal/doctor"
)

func shimPathEntries() []string {
	return filepath.SplitList(os.Getenv("PATH"))
}

func shimLookPath([]string) func(string) (string, error) {
	return exec.LookPath
}

func checkShimDirectoryFiles(shimDir string) doctor.CheckResult {
	info, err := os.Stat(shimDir)
	if err != nil || !info.IsDir() {
		return doctor.CheckResult{
			Status:  doctor.StatusFail,
			Message: "Shim directory not found",
		}
	}
	return doctor.CheckResult{
		Status:  doctor.StatusPass,
		Message: "Shim directory found",
	}
}

// warnShadowedManagers is Windows only. On Unix the rc file prepends the
// shim directory to PATH, so no machine-wide entry sits ahead of it.
func warnShadowedManagers(string) {}

// shadowedFix is empty on Unix, so the doctor table keeps its usual hint.
func shadowedFix([]string, func(string) (string, error)) string { return "" }
