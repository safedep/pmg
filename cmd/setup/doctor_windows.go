//go:build windows

package setup

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/internal/alias"
	"github.com/safedep/pmg/internal/doctor"
	"github.com/safedep/pmg/internal/shim"
	"github.com/safedep/pmg/internal/ui"
)

// shimPathEntries returns the PATH a new shell gets, from the registry.
// Doctor often runs in the shell that ran `pmg setup install`, whose process
// PATH predates the new entry.
func shimPathEntries() []string {
	entries, err := shim.RegistryPathEntries()
	if err != nil {
		log.Warnf("failed to read PATH from the registry, using the process PATH: %v", err)
		return filepath.SplitList(os.Getenv("PATH"))
	}
	return entries
}

// shimLookPath resolves a name over the given PATH entries with the PATHEXT
// rule, so the answer matches what a new shell would run.
func shimLookPath(pathEntries []string) func(string) (string, error) {
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

// checkShimDirectoryFiles checks each .cmd shim, and that it names the
// pmg.exe that runs now. A shim from an older install can point at a binary
// that is gone.
func checkShimDirectoryFiles(shimDir string) doctor.CheckResult {
	pmgBin, err := os.Executable()
	if err != nil {
		return doctor.CheckResult{
			Status:  doctor.StatusWarn,
			Message: fmt.Sprintf("Could not resolve pmg.exe: %v", err),
		}
	}

	managers := alias.DefaultConfig().PackageManagers
	var missing, stale []string
	for _, pm := range managers {
		content, err := os.ReadFile(filepath.Join(shimDir, shim.ShimFileName(pm)))
		if err != nil {
			missing = append(missing, pm)
			continue
		}
		if !shim.ShimNamesBinary(string(content), pmgBin) {
			stale = append(stale, pm)
		}
	}

	switch {
	case len(missing) == len(managers):
		return doctor.CheckResult{
			Status:  doctor.StatusFail,
			Message: "Shim directory not found",
		}
	case len(stale) > 0:
		return doctor.CheckResult{
			Status:  doctor.StatusFail,
			Message: fmt.Sprintf("Shims for %s name another pmg.exe", strings.Join(stale, ", ")),
		}
	case len(missing) > 0:
		return doctor.CheckResult{
			Status:  doctor.StatusFail,
			Message: fmt.Sprintf("Shims missing for %s", strings.Join(missing, ", ")),
		}
	}
	return doctor.CheckResult{
		Status:  doctor.StatusPass,
		Message: "Shims found, each names this pmg.exe",
	}
}

// warnShadowedManagers reports the package managers a new shell would still
// resolve outside the shim directory. Windows builds PATH as the machine
// value, then the user value, so a manager installed for the machine (the
// Node.js MSI puts npm under C:\Program Files\nodejs) sits ahead of a user
// PATH entry, and install alone cannot change that.
func warnShadowedManagers(binDir string) {
	_, shadowed := partitionResolutions(resolveManagers(
		alias.DefaultConfig().PackageManagers, []string{binDir}, shimLookPath(shimPathEntries())))
	if len(shadowed) == 0 {
		return
	}

	fmt.Printf("\n%s A new shell resolves these managers ahead of the shims, so PMG does not intercept them:\n",
		ui.Colors.Yellow("⚠"))
	for _, line := range shadowedLines(shadowed) {
		fmt.Printf("   %s\n", line)
	}
	fmt.Printf("   %s\n", shadowedActions)
}

// shadowedActions names what a user can do today. A user PATH entry can
// never move ahead of a machine PATH entry, so "reorder PATH" is not an
// option for a manager that a machine-wide installer put there.
const shadowedActions = "Run them as `pmg <manager>`, or install that manager for your user only, so it lands on the user PATH behind the shims."

// shadowedFix fills the doctor Fix column with the same lines the install
// warning prints, joined with the actions.
func shadowedFix(shadowed []managerResolution) string {
	return strings.Join(append(shadowedLines(shadowed), shadowedActions), " ")
}

func shadowedLines(shadowed []managerResolution) []string {
	lines := make([]string, 0, len(shadowed))
	for _, r := range shadowed {
		lines = append(lines, fmt.Sprintf("%s is %s.", r.Name, r.Path))
	}
	return lines
}
