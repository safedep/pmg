//go:build windows

package shim

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/alias"
	"github.com/safedep/pmg/internal/fsutil"
	"github.com/safedep/pmg/internal/winacl"
	"golang.org/x/sys/windows"
)

var programFiles = fsutil.KnownFolder(windows.FOLDERID_ProgramFiles)

// defaultSystemBinDir is "" when the shell cannot say where Program Files
// is, and every system-install entry point then reports that.
func defaultSystemBinDir() string {
	if programFiles() == "" {
		return ""
	}
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
func newSystemLayout() (systemLayout, error) {
	binDir := SystemBinDir()
	if binDir == "" {
		return systemLayout{}, errors.New("cannot resolve the Program Files folder, so there is no place for a system install")
	}
	product := filepath.Dir(binDir)
	return systemLayout{
		BinDir:     binDir,
		ProductDir: product,
		Binary:     filepath.Join(product, "pmg.exe"),
		ConfigFile: systemConfigFile(),
	}, nil
}

// systemConfigFileOverride replaces the managed config path in tests.
var systemConfigFileOverride string

func systemConfigFile() string {
	if systemConfigFileOverride != "" {
		return systemConfigFileOverride
	}
	return config.SystemConfigFilePath()
}

func (l systemLayout) vendorDir() string { return filepath.Dir(l.ProductDir) }

// objects lists every PMG-owned object of a system install, parents first.
// The shims are the expected set, one per supported manager by name, not
// whatever the directory holds: a shim that lost its marker must still be
// checked, and a file an administrator dropped in is not PMG's to judge.
func (l systemLayout) objects() []string {
	objects := []string{l.vendorDir(), l.ProductDir, l.BinDir, l.Binary}
	for _, pm := range alias.DefaultConfig().PackageManagers {
		objects = append(objects, filepath.Join(l.BinDir, shimFileName(pm)))
	}
	return objects
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
// are written. Protect refuses an object a standard user owns, so a
// directory such a user pre-created stops the install with its name.
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
	for _, p := range l.objects() {
		if err := winacl.RequireProtected(p); err != nil {
			return err
		}
	}
	return nil
}

// validateConfig is the doctor row for the managed config: both ProgramData
// directories and the file must exist and carry the PMG descriptor. The
// runtime asks less of the file, administrative control, so an MDM that
// copied it into place still governs. Doctor asks for the descriptor the
// install writes and names the drift.
func (l systemLayout) validateConfig() error {
	if l.ConfigFile == "" {
		return nil
	}
	dir := filepath.Dir(l.ConfigFile)
	for _, p := range []string{filepath.Dir(dir), dir} {
		if err := winacl.RequireProtected(p); err != nil {
			return err
		}
	}
	return winacl.RequireTrustedExisting(l.ConfigFile)
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
