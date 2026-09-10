//go:build windows

package shim

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/safedep/pmg/internal/fsutil"
	"golang.org/x/sys/windows"
)

// defaultSystemBinDir is the machine-wide shim directory. Program Files
// inherits an ACL that only administrators can write, which is what makes
// the directory safe at the front of the machine PATH. The known folder is
// asked, not the environment, which the caller's shell controls.
func defaultSystemBinDir() string {
	programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		programFiles = `C:\Program Files`
	}
	return filepath.Join(programFiles, "safedep", "pmg", "bin")
}

// Windows has no profile.d. The machine PATH carries the shim directory.
func defaultSystemProfilePath() string { return "" }

// installSystemPath puts the shim directory first on the machine PATH, and
// the binary's directory on it too, so `pmg` itself resolves in every
// terminal. The shims are checked first: a file a standard user can write
// must not be the first `npm` on the machine PATH, where an elevated process
// would run it. The binary's directory passed the same checks in
// validateSystemExecutable.
func installSystemPath(binDir, pmgBin string) error {
	if err := validateSystemShimDir(binDir); err != nil {
		return err
	}
	if err := registerMachinePath(binDir); err != nil {
		return err
	}
	return appendMachinePath(filepath.Dir(pmgBin))
}

// removeSystemPath takes the shim directory off the machine PATH. The
// binary's directory stays, as /usr/local/bin does on Linux: the binary is
// still there, and the entry may predate PMG.
func removeSystemPath(binDir, _ string) error { return unregisterMachinePath(binDir) }

func systemPathInstalled(binDir string) bool {
	found, err := machinePathContains(binDir)
	return err == nil && found
}

// validateSystemExecutable rejects a binary a standard user could replace.
// Every system shim runs this path as whichever user typed the command, so
// the file and its directory must be writable by administrators only, no
// ancestor may let a standard user swap a path component, and every user
// must be able to run the file. Symbolic links and junctions are resolved
// first, so the checks apply to the file that runs.
func validateSystemExecutable(path string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("failed to inspect pmg executable %s: %w", path, err)
	}
	if !systemExecutableOwnershipCheck {
		return nil
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("failed to resolve pmg executable %s: %w", path, err)
	}
	if err := fsutil.RequireAdminOnlyWritable(resolved); err != nil {
		return err
	}
	if err := fsutil.RequireProtectedDir(filepath.Dir(resolved)); err != nil {
		return err
	}
	return fsutil.RequireExecutableByAll(resolved)
}

// validateSystemShimDir applies the binary's rules to the shim directory
// and every shim in it. A shim overwritten in place keeps the DACL it had,
// so the files are checked one by one, not through the directory.
func validateSystemShimDir(dir string) error {
	if !systemExecutableOwnershipCheck {
		return nil
	}
	if err := fsutil.RequireNotReparsePoint(dir); err != nil {
		return err
	}
	if err := fsutil.RequireProtectedDir(dir); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("failed to list the shim directory %s: %w", dir, err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if err := fsutil.RequireAdminOnlyWritable(filepath.Join(dir, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}
