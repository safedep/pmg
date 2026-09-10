//go:build unix

package shim

import (
	"fmt"
	"os"
	"path/filepath"
)

// System install is Linux-only among the Unix platforms (enforced in
// cmd/setup); these are Linux paths. macOS has no /etc/profile.d equivalent.
const (
	linuxSystemBinDir      = "/usr/local/lib/pmg/bin"
	linuxSystemProfilePath = "/etc/profile.d/pmg.sh"
)

func defaultSystemBinDir() string      { return linuxSystemBinDir }
func defaultSystemProfilePath() string { return linuxSystemProfilePath }

// The login-shell PATH snippet is how the shim directory reaches every user.
// The binary sits in a directory such as /usr/local/bin that PATH already
// has.
func installSystemPath(binDir, _ string) error { return writeSystemProfile(binDir) }

func removeSystemPath(string, string) error { return removeSystemProfile() }

func systemPathInstalled(string) bool { return SystemProfileInstalled() }

// validateSystemExecutable rejects binaries unsafe for system-wide shims.
// Shims hard-code this path, so the binary must be executable by all users,
// not writable by group/others, and owned by root in a root-owned, non-world-
// writable parent.
func validateSystemExecutable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to inspect pmg executable %s: %w", path, err)
	}

	perm := info.Mode().Perm()

	// Other users must be able to exec the hard-coded pmg path from system shims.
	otherExecute := os.FileMode(0o001)
	// Group/other write would let another account replace the binary.
	groupOrOtherWrite := os.FileMode(0o022)

	if perm&otherExecute == 0 {
		return fmt.Errorf("pmg executable %s is not executable by all users", path)
	}
	if perm&groupOrOtherWrite != 0 {
		return fmt.Errorf("pmg executable %s is writable by group or others", path)
	}

	if systemExecutableOwnershipCheck {
		// Root ownership of the binary and its parent blocks non-root replacement.
		if err := requireRootOwnedPath(path, info); err != nil {
			return err
		}
		if err := requireSafeParentDir(filepath.Dir(path)); err != nil {
			return err
		}
		if err := requirePathSearchableByAll(path); err != nil {
			return err
		}
	}
	return nil
}

// requirePathSearchableByAll walks every directory from the binary's parent up
// to the filesystem root and requires the execute (search) bit for others. The
// shims exec the binary as arbitrary users, so a single non-searchable
// ancestor (e.g. /root, mode 0700) makes the path unreachable and every shim
// fail with exit 127 for non-root users, even when the binary itself is 0755.
func requirePathSearchableByAll(path string) error {
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		info, err := os.Stat(dir)
		if err != nil {
			return fmt.Errorf("failed to inspect directory %s: %w", dir, err)
		}
		if info.Mode().Perm()&0o001 == 0 {
			return fmt.Errorf("directory %s is not searchable by all users, so pmg at %s would be unreachable from other accounts", dir, path)
		}
		if dir == filepath.Dir(dir) {
			return nil
		}
	}
}

func requireRootOwnedPath(path string, info os.FileInfo) error {
	uid, ok := fileOwnerUID(info)
	if !ok {
		return fmt.Errorf("cannot determine owner of %s", path)
	}
	if uid != 0 {
		return fmt.Errorf("pmg executable %s must be owned by root", path)
	}
	return nil
}

// requireSafeParentDir requires a root-owned, non-world-writable immediate
// parent. Group-writable is allowed on purpose so Debian/Ubuntu's default
// /usr/local/bin (root:staff 2775) is not rejected; the resulting bypass on
// group-writable non-sticky dirs is covered in docs/system-install.md
// Limitations.
func requireSafeParentDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("failed to inspect directory %s: %w", dir, err)
	}

	if info.Mode().Perm()&os.FileMode(0o002) != 0 {
		return fmt.Errorf("directory %s containing pmg executable is writable by others", dir)
	}

	uid, ok := fileOwnerUID(info)
	if !ok {
		return fmt.Errorf("cannot determine owner of directory %s", dir)
	}

	if uid != 0 {
		return fmt.Errorf("directory %s containing pmg executable must be owned by root", dir)
	}

	return nil
}
