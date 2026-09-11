// Package platform holds the directory conventions of each operating system
// that PMG runs on. It imports nothing from config, shim or cmd.
package platform

// Dirs are the base directories of one account, in the convention of the OS.
type Dirs struct {
	Config string
	Cache  string
	Data   string
}

// HomeDirs derives the base directories from a home directory alone.
// It reads no environment variable, so a HOME or XDG_* value that sudo
// preserved from another account cannot steer it.
func HomeDirs(home string) Dirs { return homeDirs(home) }

// UserCacheDir returns the base directory for the current user's cache.
func UserCacheDir() (string, error) { return userCacheDir() }

// UserDataDir returns the base directory for the current user's data that is
// neither config nor cache. Linux follows XDG_DATA_HOME. macOS and Windows
// have no separate data location.
func UserDataDir() (string, error) { return userDataDir() }

// UserConfigDirRoams reports whether the user config directory travels with a
// roaming profile. Machine-local state such as logs then belongs beside the
// data instead.
const UserConfigDirRoams = userConfigDirRoams

// SystemConfigDir returns the directory of the managed config that governs
// every user. It returns "" when the OS has no such location or the shell
// cannot resolve it.
func SystemConfigDir() string { return systemConfigDir() }

// SystemBinDir returns the directory of the system-wide shims. It returns ""
// when the shell cannot resolve it.
func SystemBinDir() string { return systemBinDir() }

// SystemProfilePath returns the login-shell snippet that puts SystemBinDir on
// PATH. It returns "" where the machine PATH carries the directory instead.
func SystemProfilePath() string { return systemProfilePath() }
