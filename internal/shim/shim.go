package shim

import (
	"bufio"
	"bytes"
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
	return &ShimManager{config: ShimConfig{
		BinDir:          filepath.Join(homeDir, ".pmg", "bin"),
		HomeDir:         homeDir,
		PackageManagers: aliasCfg.PackageManagers,
		Shells:          aliasCfg.Shells,
	}}, nil
}

func (m *ShimManager) Install() error {
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
		configPath := filepath.Join(m.config.HomeDir, shell.Path())

		data, err := os.ReadFile(configPath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			log.Warnf("Warning: could not read %s (%s)", shell.Name(), err)
			continue
		}

		if strings.Contains(string(data), shimMarker) {
			return true, nil
		}
	}

	return false, nil
}

func (m *ShimManager) GetBinDir() string {
	return m.config.BinDir
}

func (m *ShimManager) writeShimScript(pm string) error {
	shimPath := filepath.Join(m.config.BinDir, pm)

	content := fmt.Sprintf(`#!/bin/sh
# PMG shim - do not edit, managed by pmg setup
PMG_BIN="$(command -v pmg 2>/dev/null)"
if [ -n "$PMG_BIN" ]; then
  exec pmg %s "$@"
fi
echo "[pmg] warning: pmg not found, falling back to native %s" >&2
PATH="$(echo "$PATH" | tr ':' '\n' | grep -vF "/.pmg/bin" | tr '\n' ':' | sed 's/:$//')"
export PATH
exec %s "$@"
`, pm, pm, pm)

	return os.WriteFile(shimPath, []byte(content), 0o755)
}

func (m *ShimManager) addPathToShells() error {
	for _, shell := range m.config.Shells {
		configPath := filepath.Join(m.config.HomeDir, shell.Path())

		data, err := os.ReadFile(configPath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			log.Warnf("Warning: skipping %s (%s)", shell.Name(), err)
			continue
		}

		if strings.Contains(string(data), shimMarker) {
			continue
		}

		f, err := os.OpenFile(configPath, os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			log.Warnf("Warning: skipping %s (%s)", shell.Name(), err)
			continue
		}

		_, err = fmt.Fprintf(f, "\n%s", shell.PathExport(m.config.BinDir))
		if closeErr := f.Close(); closeErr != nil {
			log.Warnf("Warning: failed to close %s: %s", shell.Name(), closeErr)
		}
		if err != nil {
			log.Warnf("Warning: failed to write PATH export to %s: %s", shell.Name(), err)
		}
	}

	return nil
}

func (m *ShimManager) removePathFromShells() error {
	for _, shell := range m.config.Shells {
		configPath := filepath.Join(m.config.HomeDir, shell.Path())

		data, err := os.ReadFile(configPath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			log.Warnf("Warning: skipping %s (%s)", shell.Name(), err)
			continue
		}

		info, err := os.Stat(configPath)
		if err != nil {
			log.Warnf("Warning: skipping %s (%s)", shell.Name(), err)
			continue
		}

		tempFile, err := os.CreateTemp(filepath.Dir(configPath), ".tmp-"+filepath.Base(configPath))
		if err != nil {
			log.Warnf("Warning: failed to create temporary file for %s: %s", configPath, err)
			continue
		}
		tempPath := tempFile.Name()

		scanner := bufio.NewScanner(bytes.NewReader(data))
		writer := bufio.NewWriter(tempFile)

		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, shimMarker) {
				continue
			}
			if _, err := writer.WriteString(line + "\n"); err != nil {
				log.Warnf("Warning: failed to write to temporary file: %s", err)
			}
		}

		if err := writer.Flush(); err != nil {
			log.Warnf("Warning: failed to flush temporary file: %s", err)
		}
		if err := tempFile.Close(); err != nil {
			log.Warnf("Warning: failed to close temporary file: %s", err)
		}

		if err := os.Chmod(tempPath, info.Mode()); err != nil {
			log.Warnf("Warning: failed to set permissions on temporary file: %s", err)
		}

		if err := os.Rename(tempPath, configPath); err != nil {
			_ = os.Remove(tempPath)
			log.Warnf("Warning: failed to update %s: %s", configPath, err)
		}
	}

	return nil
}
