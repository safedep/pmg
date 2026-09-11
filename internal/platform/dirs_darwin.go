package platform

import (
	"os"
	"path/filepath"
)

func userDataDir() (string, error) { return os.UserConfigDir() }

func homeDirs(home string) Dirs {
	support := filepath.Join(home, "Library", "Application Support")
	return Dirs{
		Config: support,
		Cache:  filepath.Join(home, "Library", "Caches"),
		Data:   support,
	}
}

func systemConfigDir() string { return "/Library/Application Support/safedep/pmg" }
