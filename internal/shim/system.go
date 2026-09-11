package shim

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/safedep/pmg/internal/alias"
)

// systemLayout is where a system install lives. Each platform builds it in
// newSystemLayout, and the shim manager carries it, so no path is derived
// twice.
type systemLayout struct {
	BinDir     string // shim directory
	ProductDir string // holds the pmg binary
	// Binary is where the platform requires the pmg binary. "" where any
	// path that passes validateBinary is accepted.
	Binary      string
	ProfilePath string // login-shell snippet, "" where the platform has none
	ConfigFile  string // managed config, "" where doctor does not check it
}

// These overrides replace OS-level system install paths in tests. There is
// intentionally no env var or flag for them.
var (
	systemBinDirOverride      string
	systemProfilePathOverride string
	// resolveExecutable resolves the running pmg binary for system install.
	// Overridable in tests so validation does not run against the go-build test
	// binary, which is group-writable under a 002 umask.
	resolveExecutable = currentExecutable
)

// SystemBinDir returns the directory for system-wide PMG shims.
func SystemBinDir() string {
	if systemBinDirOverride != "" {
		return systemBinDirOverride
	}
	return defaultSystemBinDir()
}

// SystemProfilePath returns the path of the system profile.d snippet, or ""
// on Windows, where the machine PATH carries the shim directory instead.
func SystemProfilePath() string {
	if systemProfilePathOverride != "" {
		return systemProfilePathOverride
	}
	return defaultSystemProfilePath()
}

// NewSystemShimManager creates a shim manager for system-wide install. The
// executable is validated by Install, not here, so Remove works even when
// the installed binary is no longer suitable.
func NewSystemShimManager() (*ShimManager, error) {
	layout, err := newSystemLayout()
	if err != nil {
		return nil, err
	}
	pmgBin, err := resolveExecutable()
	if err != nil {
		return nil, err
	}
	return newSystemShimManager(layout, pmgBin), nil
}

func newSystemShimManager(layout systemLayout, pmgBin string) *ShimManager {
	return &ShimManager{config: ShimConfig{
		BinDir:          layout.BinDir,
		PMGBin:          pmgBin,
		PackageManagers: alias.DefaultConfig().PackageManagers,
		SkipUserPath:    true,
		System:          &layout,
	}}
}

// SystemShimsInstalled reports whether the system shim directory contains at
// least one shim script.
func SystemShimsInstalled() bool {
	return shimsPresent(SystemBinDir())
}

// SystemShimBinary returns the pmg binary path that installed system shims
// execute. ok is false when no system shim with a resolvable binary is
// present. All shims are written from the same template in one pass, so
// reading one suffices.
func SystemShimBinary() (string, bool) {
	content, ok := firstShimContent(SystemBinDir())
	if !ok {
		return "", false
	}
	return parseShimBinary(content)
}

// ErrNoSystemBinary is returned when system shims exist but none names a
// pmg binary. Doctor reports it as a warning, not a failure.
var ErrNoSystemBinary = errors.New("no system shim names a pmg binary")

// ValidateSystemInstall re-checks the binary the system shims run, every
// object of the system install and the managed config, for `pmg setup
// doctor`. It returns the binary path it checked.
func ValidateSystemInstall() (string, error) {
	binary, ok := SystemShimBinary()
	if !ok {
		return "", ErrNoSystemBinary
	}
	layout, err := newSystemLayout()
	if err != nil {
		return binary, err
	}
	if err := layout.validateBinary(binary); err != nil {
		return binary, err
	}
	if err := layout.validate(); err != nil {
		return binary, err
	}
	return binary, layout.validateConfig()
}

func shimsPresent(dir string) bool {
	_, ok := firstShimContent(dir)
	return ok
}

// firstShimContent returns the content of the first managed shim script in dir.
func firstShimContent(dir string) (string, bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", false
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		content, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err == nil && strings.Contains(string(content), shimScriptMarker) {
			return string(content), true
		}
	}
	return "", false
}
