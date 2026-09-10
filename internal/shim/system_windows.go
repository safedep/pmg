//go:build windows

package shim

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/fsutil"
	"github.com/safedep/pmg/internal/winacl"
	"golang.org/x/sys/windows"
)

var programFiles = fsutil.KnownFolder(windows.FOLDERID_ProgramFiles, `C:\Program Files`)

func defaultSystemBinDir() string {
	return filepath.Join(programFiles(), "safedep", "pmg", "bin")
}

// Windows has no profile.d. The machine PATH carries the shim directory.
func defaultSystemProfilePath() string { return "" }

// The system install lives at fixed paths under Program Files, which only
// administrators can write.
//
//	%ProgramFiles%\safedep            vendor directory
//	%ProgramFiles%\safedep\pmg        product directory, holds pmg.exe
//	%ProgramFiles%\safedep\pmg\bin    shim directory
func newSystemLayout() systemLayout {
	binDir := SystemBinDir()
	product := filepath.Dir(binDir)
	return systemLayout{
		BinDir:     binDir,
		ProductDir: product,
		Binary:     filepath.Join(product, "pmg.exe"),
	}
}

func (l systemLayout) vendorDir() string { return filepath.Dir(l.ProductDir) }

// objects lists every PMG-owned object of a system install, parents first.
func (l systemLayout) objects() ([]string, error) {
	objects := []string{l.vendorDir(), l.ProductDir, l.BinDir, l.Binary}
	entries, err := os.ReadDir(l.BinDir)
	if err != nil {
		return nil, fmt.Errorf("failed to list the shim directory %s: %w", l.BinDir, err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			objects = append(objects, filepath.Join(l.BinDir, entry.Name()))
		}
	}
	return objects, nil
}

// validateBinary requires the running binary to be the canonical one. Every
// system shim runs that path as whichever user typed the command, so it
// must sit where only administrators can write, and no component on the way
// may be a link.
func (l systemLayout) validateBinary(path string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("failed to inspect pmg executable %s: %w", path, err)
	}
	if !fsutil.SamePath(path, l.Binary) {
		return usefulerror.NewUsefulError().
			WithCode(errcodes.PermissionDenied).
			WithHumanError(fmt.Sprintf("pmg runs from %s, and a system install needs it at %s", path, l.Binary)).
			WithHelp(fmt.Sprintf("Unpack the release into %s and run the install again", l.ProductDir)).
			Wrap(fmt.Errorf("pmg executable %s is not at %s", path, l.Binary))
	}
	for _, p := range []string{l.vendorDir(), l.ProductDir, path} {
		if err := winacl.RequireNotReparsePoint(p); err != nil {
			return err
		}
	}
	return nil
}

// protect puts the PMG descriptor on the vendor directory, the product
// directory, the shim directory and the binary. The shims get it as they
// are written. A directory a standard user pre-created, or a file that kept
// an old descriptor when it was overwritten, is repaired here.
func (l systemLayout) protect() error {
	for _, p := range []string{l.vendorDir(), l.ProductDir, l.BinDir, l.Binary} {
		if err := winacl.Protect(p); err != nil {
			return err
		}
	}
	return nil
}

// validate requires the PMG descriptor on every object, the shims included.
// Install runs it before the shim directory goes on the machine PATH, and
// doctor runs it to report drift.
func (l systemLayout) validate() error {
	objects, err := l.objects()
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

// installPath puts the shim directory first on the machine PATH, and the
// product directory on it too, so `pmg` itself resolves in every terminal.
// Nothing goes on the PATH until every object is protected: the first `npm`
// on the machine PATH runs for elevated processes as well.
func (l systemLayout) installPath() error {
	if err := l.validate(); err != nil {
		return err
	}
	if err := machinePath.prepend(l.BinDir); err != nil {
		return err
	}
	return machinePath.append(l.ProductDir)
}

// removePath takes the shim directory off the machine PATH. The product
// directory stays on it: the binary stays on disk, and a typed `pmg` must
// still run after `pmg setup remove --system`.
func (l systemLayout) removePath() error { return machinePath.remove(l.BinDir) }

func (l systemLayout) pathInstalled() bool {
	found, err := machinePath.contains(l.BinDir)
	return err == nil && found
}
