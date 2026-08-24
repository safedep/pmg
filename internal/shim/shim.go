package shim

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/alias"
	"github.com/safedep/pmg/internal/fsutil"
)

const (
	shimMarker       = "PMG shims"
	shimScriptMarker = "# PMG shim - do not edit, managed by pmg setup"
	// legacyUserDirName is the pre-XDG per-user PMG directory in $HOME.
	legacyUserDirName = ".pmg"
	// shimPMGBinVar is the shell variable in every shim script that holds the
	// pmg binary path. parseShimPMGBin reads it back, so the name is shared.
	shimPMGBinVar = "PMG_BIN"
)

type ShimConfig struct {
	BinDir  string
	HomeDir string
	// CleanupBinDirs lists per-user shim directories Remove must clear in
	// addition to BinDir, so an uninstall strands nothing when more than one
	// layout is populated. Empty for managers that own a single directory
	// (system install, tests).
	CleanupBinDirs  []string
	PMGBin          string
	PackageManagers []string
	Shells          []alias.Shell
	// SkipShellRc skips per-user shell rc PATH edits. Used by system install,
	// which relies on the system profile or ENV PATH instead.
	SkipShellRc bool
	// SystemProfile installs and removes the OS login-shell PATH snippet
	// (Linux: /etc/profile.d/pmg.sh) with Install/Remove, and marks this
	// manager as a system-wide install: Install then also validates the pmg
	// binary for multi-user use and forces root ownership on the shim dirs.
	SystemProfile bool
}

type ShimManager struct {
	config ShimConfig
}

func NewShimManager(config ShimConfig) *ShimManager {
	return &ShimManager{config: config}
}

func NewDefaultShimManager() (*ShimManager, error) {
	homeDir, err := config.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	aliasCfg := alias.DefaultConfig()
	pmgBin, err := currentExecutable()
	if err != nil {
		return nil, err
	}

	binDir, err := UserBinDir()
	if err != nil {
		return nil, err
	}

	cleanupBinDirs, err := otherUserBinDirs(binDir)
	if err != nil {
		return nil, err
	}

	return &ShimManager{config: ShimConfig{
		BinDir:          binDir,
		HomeDir:         homeDir,
		CleanupBinDirs:  cleanupBinDirs,
		PMGBin:          pmgBin,
		PackageManagers: aliasCfg.PackageManagers,
		Shells:          aliasCfg.Shells,
	}}, nil
}

func (m *ShimManager) Install() error {
	if m.config.PMGBin == "" {
		pmgBin, err := currentExecutable()
		if err != nil {
			return err
		}
		m.config.PMGBin = pmgBin
	}

	if m.config.SystemProfile {
		// System shims hard-code this binary path for every user; validating
		// here (not at construction) keeps Remove usable when the installed
		// binary is no longer suitable.
		if err := validateSystemExecutable(m.config.PMGBin); err != nil {
			return err
		}
	}

	if err := os.MkdirAll(m.config.BinDir, 0o755); err != nil {
		return fmt.Errorf("failed to create shim directory %s: %w", m.config.BinDir, err)
	}

	if m.config.SystemProfile {
		// Both directories are pmg's own (…/pmg and …/pmg/bin): force root
		// ownership even when pre-created, so weaker modes are not inherited.
		for _, dir := range []string{filepath.Dir(m.config.BinDir), m.config.BinDir} {
			if err := fsutil.ForceRootOwned(dir, 0o755); err != nil {
				return err
			}
		}
	}

	for _, pm := range m.config.PackageManagers {
		if err := m.writeShimScript(pm); err != nil {
			return fmt.Errorf("failed to write shim for %s: %w", pm, err)
		}
	}

	if m.config.SystemProfile {
		if err := writeSystemProfile(m.config.BinDir); err != nil {
			return fmt.Errorf("failed to write system profile: %w", err)
		}
	}

	if m.config.SkipShellRc {
		return nil
	}

	if err := m.addPathToShells(); err != nil {
		return fmt.Errorf("failed to update shell configs: %w", err)
	}

	return nil
}

func (m *ShimManager) Remove() error {
	// Best-effort: a failure removing the shim directory must not skip profile
	// and rc cleanup, otherwise a rerun is needed to fully uninstall.
	var errs []error
	for _, dir := range append([]string{m.config.BinDir}, m.config.CleanupBinDirs...) {
		if dir == "" {
			continue
		}
		if err := os.RemoveAll(dir); err != nil {
			errs = append(errs, fmt.Errorf("failed to remove shim directory %s: %w", dir, err))
			continue
		}
		// Drops the now-childless wrappers pmg created (~/.pmg, and the
		// safedep/pmg tree under the data dir). Stops at the first directory
		// that still holds something, and never walks out of the home dir.
		pruneEmptyParents(dir, m.config.HomeDir)
	}

	if m.config.SystemProfile {
		if err := removeSystemProfile(); err != nil {
			errs = append(errs, fmt.Errorf("failed to remove system profile: %w", err))
		}
	}

	if !m.config.SkipShellRc {
		if err := m.removePathFromShells(); err != nil {
			errs = append(errs, fmt.Errorf("failed to clean shell configs: %w", err))
		}
	}

	return errors.Join(errs...)
}

func (m *ShimManager) IsInstalled() (bool, error) {
	for _, shell := range m.config.Shells {
		for _, configPath := range shell.CandidateRcFiles(m.config.HomeDir) {
			data, err := os.ReadFile(configPath)
			if err != nil {
				if os.IsNotExist(err) {
					continue
				}
				log.Warnf("Warning: could not read %s (%s)", configPath, err)
				continue
			}

			if strings.Contains(string(data), shimMarker) {
				return true, nil
			}
		}
	}

	return false, nil
}

func (m *ShimManager) GetBinDir() string {
	return m.config.BinDir
}

// UserBinDir returns the per-user PMG shim directory. Installs predating the
// XDG layout keep using ~/.pmg/bin for as long as their shims are there, so an
// upgrade never strands a shim outside PATH; a fresh install (or a reinstall
// after `pmg setup remove`) resolves to the data directory instead.
func UserBinDir() (string, error) {
	legacyDir, err := LegacyUserBinDir()
	if err != nil {
		return "", err
	}

	if shimsPresent(legacyDir) {
		return legacyDir, nil
	}

	return DataUserBinDir()
}

// DataUserBinDir returns the per-user shim directory under the data directory,
// ignoring any legacy install.
func DataUserBinDir() (string, error) {
	dataDir, err := config.UserDataDir()
	if err != nil {
		return "", fmt.Errorf("failed to get data directory: %w", err)
	}

	return filepath.Join(dataDir, "bin"), nil
}

// LegacyUserBinDir returns the pre-XDG shim directory (~/.pmg/bin).
func LegacyUserBinDir() (string, error) {
	homeDir, err := config.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}
	return filepath.Join(homeDir, legacyUserDirName, "bin"), nil
}

func (m *ShimManager) writeShimScript(pm string) error {
	shimPath := filepath.Join(m.config.BinDir, pm)
	pmgBin := shellQuote(m.config.PMGBin)

	content := fmt.Sprintf(`#!/bin/sh
%[1]s
%[2]s=%[3]s
if [ ! -x "$%[2]s" ]; then
  echo "[pmg] error: PMG binary not found or not executable: $%[2]s" >&2
  echo "[pmg] error: run 'pmg setup install' again or remove shims with 'pmg setup remove'" >&2
  exit 127
fi
PMG_SHIM_PATH=$(cd -- "$(dirname -- "$0")" && pwd)/$(basename -- "$0")
export PMG_SHIM_PATH
exec "$%[2]s" %[4]s "$@"
`, shimScriptMarker, shimPMGBinVar, pmgBin, pm)

	if err := os.WriteFile(shimPath, []byte(content), 0o755); err != nil {
		return err
	}

	// WriteFile honors the process umask (e.g. root umask 077 births the shim
	// as 0700); chmod so the shim stays executable by every user.
	return os.Chmod(shimPath, 0o755)
}

func currentExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to resolve pmg executable: %w", err)
	}

	return filepath.Abs(exe)
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func (m *ShimManager) addPathToShells() error {
	primary := alias.PrimaryShellName()
	for _, shell := range m.config.Shells {
		files, err := shell.InstallRcFiles(m.config.HomeDir, shell.Name() == primary)
		if err != nil {
			log.Warnf("Warning: skipping %s (%s)", shell.Name(), err)
			continue
		}

		for _, configPath := range files {
			m.addPathToFile(configPath, shell)
		}
	}

	return nil
}

// addPathToFile appends the shell's PATH export to a single config file unless
// it is already present. A missing file is a no-op.
func (m *ShimManager) addPathToFile(configPath string, shell alias.Shell) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warnf("Warning: skipping %s (%s)", configPath, err)
		}
		return
	}

	if strings.Contains(string(data), shimMarker) {
		return
	}

	f, err := os.OpenFile(configPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		log.Warnf("Warning: skipping %s (%s)", configPath, err)
		return
	}

	_, err = fmt.Fprintf(f, "\n%s", shell.PathExport(m.config.BinDir))
	if closeErr := f.Close(); closeErr != nil {
		log.Warnf("Warning: failed to close %s: %s", configPath, closeErr)
	}
	if err != nil {
		log.Warnf("Warning: failed to write PATH export to %s: %s", configPath, err)
	}
}

func (m *ShimManager) removePathFromShells() error {
	drop := func(line string) bool {
		return strings.Contains(line, shimMarker)
	}

	for _, shell := range m.config.Shells {
		for _, configPath := range shell.CandidateRcFiles(m.config.HomeDir) {
			if err := alias.RewriteFileDroppingLines(configPath, drop); err != nil {
				log.Warnf("Warning: failed to update %s: %s", configPath, err)
			}
		}
	}

	return nil
}

// otherUserBinDirs returns the per-user shim directories that are not binDir,
// so Remove can clear a layout that is populated but not currently preferred.
func otherUserBinDirs(binDir string) ([]string, error) {
	legacyBinDir, err := LegacyUserBinDir()
	if err != nil {
		return nil, err
	}

	dataBinDir, err := DataUserBinDir()
	if err != nil {
		return nil, err
	}

	var dirs []string
	for _, dir := range []string{legacyBinDir, dataBinDir} {
		if filepath.Clean(dir) != filepath.Clean(binDir) {
			dirs = append(dirs, dir)
		}
	}

	return dirs, nil
}

// pmgOwnedDirNames are the directory names pmg creates around its shim dir.
// Pruning stops as soon as it walks out of them, so shared roots such as
// ~/.local/share are never removed even when pmg left them empty.
var pmgOwnedDirNames = map[string]bool{
	legacyUserDirName: true,
	"safedep":         true,
	"pmg":             true,
}

// pruneEmptyParents removes the empty pmg-owned parent directories of dir. It
// stops at the first non-empty one, at any directory pmg did not create, and
// never at or above stopAt. A stopAt outside dir's ancestry (e.g. a system
// install) prunes nothing.
func pruneEmptyParents(dir, stopAt string) {
	if stopAt == "" {
		return
	}

	prefix := filepath.Clean(stopAt) + string(os.PathSeparator)
	for parent := filepath.Dir(dir); strings.HasPrefix(parent, prefix) && pmgOwnedDirNames[filepath.Base(parent)]; parent = filepath.Dir(parent) {
		if err := os.Remove(parent); err != nil {
			return
		}
	}
}

// UserShimsInstalled reports whether the per-user shim directory contains at
// least one shim script.
func UserShimsInstalled() bool {
	binDir, err := UserBinDir()
	if err != nil {
		return false
	}
	return shimsPresent(binDir)
}
