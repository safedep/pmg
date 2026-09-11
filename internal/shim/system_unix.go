//go:build unix

package shim

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/safedep/pmg/internal/fsutil"
)

const systemProfileMarker = "PMG system shims"

// systemExecutableOwnershipCheck requires root ownership of the binary and
// its parent directory. Disabled in tests that cannot create root-owned
// files.
var systemExecutableOwnershipCheck = true

// Linux accepts the binary at any root-owned path, so the layout names none.
func newSystemLayout() (systemLayout, error) {
	binDir := SystemBinDir()
	return systemLayout{
		BinDir:      binDir,
		ProductDir:  filepath.Dir(binDir),
		ProfilePath: SystemProfilePath(),
	}, nil
}

// validateConfig is a Windows check. A standard user cannot put a file
// under /etc.
func (systemLayout) validateConfig() error { return nil }

func systemInstallPresent() bool { return SystemShimsInstalled() }

// protect forces root ownership on both directories pmg owns even when
// pre-created, so weaker modes are not inherited.
func (l systemLayout) protect() error {
	for _, dir := range []string{l.ProductDir, l.BinDir} {
		if err := fsutil.SecureSystemPath(dir, 0o755); err != nil {
			return err
		}
	}
	return nil
}

// validate is a Windows check. On Linux validateBinary and the modes
// SecureSystemPath sets are the whole contract.
func (systemLayout) validate() error { return nil }

// The login-shell PATH snippet is how the shim directory reaches every user.
func (l systemLayout) installPath() error { return writeSystemProfile(l.ProfilePath, l.BinDir) }

func (l systemLayout) removePath() error { return removeSystemProfile(l.ProfilePath) }

func (l systemLayout) pathInstalled() bool { return profileInstalled(l.ProfilePath) }

// validateBinary rejects binaries unsafe for system-wide shims. Shims
// hard-code this path, so the binary must be executable by all users, not
// writable by group/others, and owned by root in a root-owned, non-world-
// writable parent.
func (systemLayout) validateBinary(path string) error {
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

// SystemProfileInstalled reports whether the system profile snippet exists and
// contains the PMG marker.
func SystemProfileInstalled() bool { return profileInstalled(SystemProfilePath()) }

func profileInstalled(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), systemProfileMarker)
}

func writeSystemProfile(path, binDir string) error {
	// Do not chown/chmod /etc/profile.d itself: it is a shared system directory
	// pmg does not own, and other packages drop snippets there. We only secure
	// the file we write, below.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("failed to create profile.d directory: %w", err)
	}

	content := fmt.Sprintf(`# %s - managed by pmg setup install --system
# remove by running: pmg setup remove --system
export PATH="%s:$PATH"
`, systemProfileMarker, binDir)

	data, err := os.ReadFile(path)
	if err == nil && string(data) == content {
		return fsutil.SecureSystemPath(path, 0o644)
	}

	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read system profile %s: %w", path, err)
	}

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("failed to write system profile %s: %w", path, err)
	}

	// The snippet must stay world-readable regardless of root's umask so every
	// user's login shell can source it.
	return fsutil.SecureSystemPath(path, 0o644)
}

func removeSystemProfile(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove system profile %s: %w", path, err)
	}
	return nil
}

// parseShimPMGBin extracts the shimPMGBinVar value from a shim script,
// reversing the shellQuote used by writeShimScript.
func parseShimPMGBin(content string) (string, bool) {
	for line := range strings.SplitSeq(content, "\n") {
		if rest, ok := strings.CutPrefix(line, shimPMGBinVar+"="); ok {
			return shellUnquote(rest), true
		}
	}
	return "", false
}

// shellUnquote reverses shellQuote for the single-quoted form it emits.
func shellUnquote(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "'")
	s = strings.TrimSuffix(s, "'")
	return strings.ReplaceAll(s, `'\''`, `'`)
}
