//go:build windows

package shim

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/safedep/pmg/internal/fsutil"
	"github.com/safedep/pmg/internal/winacl"
	"golang.org/x/sys/windows"
)

// The system install lives at fixed paths under Program Files, which only
// administrators can write. The known folder is asked, not the
// environment, which the caller's shell controls.
//
//	%ProgramFiles%\safedep            vendor directory
//	%ProgramFiles%\safedep\pmg        product directory, holds pmg.exe
//	%ProgramFiles%\safedep\pmg\bin    shim directory
func defaultSystemBinDir() string {
	programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		programFiles = `C:\Program Files`
	}
	return filepath.Join(programFiles, "safedep", "pmg", "bin")
}

// Windows has no profile.d. The machine PATH carries the shim directory.
func defaultSystemProfilePath() string { return "" }

func systemProductDir(binDir string) string { return filepath.Dir(binDir) }

func systemBinaryPath(binDir string) string {
	return filepath.Join(systemProductDir(binDir), "pmg.exe")
}

// systemObjects lists every PMG-owned object of a system install, parents
// first, so the same list serves protection and verification.
func systemObjects(binDir string) ([]string, error) {
	product := systemProductDir(binDir)
	objects := []string{filepath.Dir(product), product, binDir, systemBinaryPath(binDir)}
	entries, err := os.ReadDir(binDir)
	if err != nil {
		return nil, fmt.Errorf("failed to list the shim directory %s: %w", binDir, err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			objects = append(objects, filepath.Join(binDir, entry.Name()))
		}
	}
	return objects, nil
}

// validateSystemExecutable requires the running binary to be the canonical
// one. Every system shim runs that path as whichever user typed the
// command, so it must sit where only administrators can write, and no
// component on the way may be a link.
func validateSystemExecutable(path string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("failed to inspect pmg executable %s: %w", path, err)
	}
	if !systemExecutableOwnershipCheck {
		return nil
	}
	want := systemBinaryPath(SystemBinDir())
	if !fsutil.SamePath(path, want) {
		return fmt.Errorf("pmg runs from %s. A system install needs it at %s. Unpack the release there and run the install again", path, want)
	}
	product := systemProductDir(SystemBinDir())
	for _, p := range []string{filepath.Dir(product), product, path} {
		if err := winacl.RequireNotReparsePoint(p); err != nil {
			return err
		}
	}
	return nil
}

// protectSystemObjects puts the PMG descriptor on the vendor directory, the
// product directory, the shim directory and the binary. The shims get it
// as they are written. A directory a standard user pre-created, or a file
// that kept an old descriptor when it was overwritten, is repaired here.
func protectSystemObjects(binDir, pmgBin string) error {
	product := systemProductDir(binDir)
	for _, p := range []string{filepath.Dir(product), product, binDir, pmgBin} {
		if err := winacl.Protect(p); err != nil {
			return err
		}
	}
	return nil
}

// validateSystemInstall requires the PMG descriptor on every object, the
// shims included. Install runs it before the shim directory goes on the
// machine PATH, and doctor runs it to report drift.
func validateSystemInstall(binDir string) error {
	if !systemExecutableOwnershipCheck {
		return nil
	}
	objects, err := systemObjects(binDir)
	if err != nil {
		return err
	}
	for _, p := range objects {
		if err := winacl.RequireProtected(p); err != nil {
			return err
		}
	}
	return nil
}

// installSystemPath puts the shim directory first on the machine PATH, and
// the product directory on it too, so `pmg` itself resolves in every
// terminal. Nothing goes on the PATH until every object is protected: the
// first `npm` on the machine PATH runs for elevated processes as well.
func installSystemPath(binDir, pmgBin string) error {
	if err := validateSystemInstall(binDir); err != nil {
		return err
	}
	if err := machinePath.prepend(binDir); err != nil {
		return err
	}
	return machinePath.append(filepath.Dir(pmgBin))
}

// removeSystemPath takes the shim directory off the machine PATH. The
// product directory stays, as /usr/local/bin does on Linux: the binary is
// still there.
func removeSystemPath(binDir, _ string) error { return machinePath.remove(binDir) }

func systemPathInstalled(binDir string) bool {
	found, err := machinePath.contains(binDir)
	return err == nil && found
}
