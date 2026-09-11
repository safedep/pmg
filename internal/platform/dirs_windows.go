package platform

import (
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/safedep/dry/log"
	"golang.org/x/sys/windows"
)

// APPDATA roams with the profile. LOCALAPPDATA stays on the machine.
const userConfigDirRoams = true

func localAppData() (string, error) {
	for _, key := range []string{"LOCALAPPDATA", "USERPROFILE"} {
		if dir := os.Getenv(key); dir != "" {
			return dir, nil
		}
	}
	return "", errors.New("neither LOCALAPPDATA nor USERPROFILE is set")
}

func userCacheDir() (string, error) { return localAppData() }
func userDataDir() (string, error)  { return localAppData() }

func homeDirs(home string) Dirs {
	local := filepath.Join(home, "AppData", "Local")
	return Dirs{
		Config: filepath.Join(home, "AppData", "Roaming"),
		Cache:  local,
		Data:   local,
	}
}

// The environment variable that matches a known folder is the user's to set,
// and a value of their choosing would point PMG away from the paths that
// govern them. The shell knows where the folder is. A guessed drive would
// protect the wrong tree, so an unresolved folder is "".
func knownFolder(id *windows.KNOWNFOLDERID) func() string {
	return sync.OnceValue(func() string {
		dir, err := windows.KnownFolderPath(id, 0)
		if err != nil {
			log.Warnf("failed to resolve a Windows known folder: %v", err)
			return ""
		}
		return dir
	})
}

var (
	programFiles = knownFolder(windows.FOLDERID_ProgramFiles)
	programData  = knownFolder(windows.FOLDERID_ProgramData)
)

func underKnownFolder(root string, elem ...string) string {
	if root == "" {
		return ""
	}
	return filepath.Join(append([]string{root}, elem...)...)
}

func systemConfigDir() string { return underKnownFolder(programData(), "safedep", "pmg") }
func systemBinDir() string    { return underKnownFolder(programFiles(), "safedep", "pmg", "bin") }

// Windows has no profile.d. The machine PATH carries the shim directory.
func systemProfilePath() string { return "" }
