package shim

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/internal/alias"
)

const shimMarker = "PMG shims"

type ShimConfig struct {
	BinDir          string
	HomeDir         string
	PMGBin          string
	PackageManagers []string
	Shells          []alias.Shell
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

	return &ShimManager{config: ShimConfig{
		BinDir:          filepath.Join(homeDir, ".pmg", "bin"),
		HomeDir:         homeDir,
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

	if err := os.MkdirAll(m.config.BinDir, 0o755); err != nil {
		return fmt.Errorf("failed to create shim directory %s: %w", m.config.BinDir, err)
	}

	for _, pm := range m.config.PackageManagers {
		if err := m.writeShimScript(pm); err != nil {
			return fmt.Errorf("failed to write shim for %s: %w", pm, err)
		}
	}

	if err := m.addPathToShells(); err != nil {
		return fmt.Errorf("failed to update shell configs: %w", err)
	}

	return nil
}

func (m *ShimManager) Remove() error {
	if err := os.RemoveAll(m.config.BinDir); err != nil && !os.IsNotExist(err) {
		log.Warnf("Warning: failed to remove shim directory: %v", err)
	}

	if err := m.removePathFromShells(); err != nil {
		return fmt.Errorf("failed to clean shell configs: %w", err)
	}

	return nil
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

func (m *ShimManager) writeShimScript(pm string) error {
	shimPath := filepath.Join(m.config.BinDir, pm)
	pmgBin := shellQuote(m.config.PMGBin)

	content := fmt.Sprintf(`#!/bin/sh
# PMG shim - do not edit, managed by pmg setup
PMG_BIN=%s
if [ ! -x "$PMG_BIN" ]; then
  echo "[pmg] error: PMG binary not found or not executable: $PMG_BIN" >&2
  echo "[pmg] error: run 'pmg setup install' again or remove shims with 'pmg setup remove'" >&2
  exit 127
fi
exec "$PMG_BIN" %s "$@"
`, pmgBin, pm)

	return os.WriteFile(shimPath, []byte(content), 0o755)
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
