//go:build unix

package platform

import "os"

func userCacheDir() (string, error) { return os.UserCacheDir() }

const userConfigDirRoams = false

// The system install is Linux-only among the Unix platforms, enforced in
// cmd/setup. macOS has no /etc/profile.d equivalent.
func systemBinDir() string      { return "/usr/local/lib/pmg/bin" }
func systemProfilePath() string { return "/etc/profile.d/pmg.sh" }
