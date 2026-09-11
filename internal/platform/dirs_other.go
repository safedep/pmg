//go:build !windows && !darwin

package platform

import (
	"fmt"
	"os"
	"path/filepath"
)

const xdgDataHomeEnvKey = "XDG_DATA_HOME"

func userDataDir() (string, error) {
	if base := os.Getenv(xdgDataHomeEnvKey); base != "" {
		return base, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to retrieve user home directory: %w", err)
	}
	return filepath.Join(home, ".local", "share"), nil
}

func homeDirs(home string) Dirs {
	return Dirs{
		Config: filepath.Join(home, ".config"),
		Cache:  filepath.Join(home, ".cache"),
		Data:   filepath.Join(home, ".local", "share"),
	}
}

func systemConfigDir() string { return "/etc/safedep/pmg" }
