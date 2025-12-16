package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// This file centralizes all path-related helpers for the config package.
// It standardizes where PMG stores configuration and related artifacts,
// so other packages (e.g., internal/alias) can rely on a single source of truth.

const (
	pmgConfigName = "config"
	pmgConfigType = "yml"
	pmgConfigPath = "safedep/pmg"
)

// defaultRcFileName is the default name for the shell RC file that contains PMG aliases.
const defaultRcFileName = ".pmg.rc"

// PmgConfigDir returns the base application config directory.
// By default, this is:
// - macOS:   ~/Library/Application Support/safedep/pmg
// - Linux:   ~/.config/safedep/pmg
// - Windows: %AppData%\safedep\pmg
func PmgConfigDir() (string, error) {
	userConfigDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("failed to retrieve user config directory: %w", err)
	}

	return filepath.Join(userConfigDir, pmgConfigPath), nil
}

// CreatePmgConfigDir ensures the application config directory exists and returns its path.
func CreatePmgConfigDir() (string, error) {
	dir, err := PmgConfigDir()
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create config directory %s: %w", dir, err)
	}
	return dir, nil
}

// ConfigFilePath returns the absolute path to the main PMG config file (e.g., config.yml),
// without creating any directories.
func ConfigFilePath() (string, error) {
	dir, err := PmgConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, fmt.Sprintf("%s.%s", pmgConfigName, pmgConfigType)), nil
}

// RcFileName returns the default RC file name used for PMG aliases.
func RcFileName() string {
	return defaultRcFileName
}

// RcFilePath returns the absolute path to the PMG RC file under the app config directory,
// without creating any directories.
func RcFilePath() (string, error) {
	dir, err := PmgConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, defaultRcFileName), nil
}
