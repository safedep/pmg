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
	// LegacyBinDir is the pre-XDG shim directory. Remove cleans it alongside
	// BinDir so an uninstall does not strand shims from the older layout. Empty
	// for managers that own a single directory (system install, tests).
	LegacyBinDir    string
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
	homeDir, err := os.UserHomeDir()
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

	legacyBinDir, err := LegacyUserBinDir()
	if err != nil {
		return nil, err
	}

	return &ShimManager{config: ShimConfig{
		BinDir:          binDir,
		HomeDir:         homeDir,
		LegacyBinDir:    legacyBinDir,
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
	for _, dir := range []string{m.config.BinDir, m.config.LegacyBinDir} {
		if dir == "" {
			continue
		}
		if err := os.RemoveAll(dir); err != nil {
			errs = append(errs, fmt.Errorf("failed to remove shim directory %s: %w", dir, err))
		}
	}

	if m.config.LegacyBinDir != "" {
		// Drops the legacy ~/.pmg wrapper once its only child is gone. Fails
		// harmlessly while anything else still lives there.
		if err := os.Remove(filepath.Dir(m.config.LegacyBinDir)); err != nil && !os.IsNotExist(err) {
			log.Warnf("Warning: leaving %s in place (%s)", filepath.Dir(m.config.LegacyBinDir), err)
		}
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

	dataDir, err := config.UserDataDir()
	if err != nil {
		return "", fmt.Errorf("failed to get data directory: %w", err)
	}

	return filepath.Join(dataDir, "bin"), nil
}

// LegacyUserBinDir returns the pre-XDG shim directory (~/.pmg/bin).
func LegacyUserBinDir() (string, error) {
	homeDir, err := os.UserHomeDir()
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

// UserShimsInstalled reports whether the per-user shim directory contains at
// least one shim script.
func UserShimsInstalled() bool {
	binDir, err := UserBinDir()
	if err != nil {
		return false
	}
	return shimsPresent(binDir)
}
