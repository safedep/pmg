package shim

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/safedep/pmg/internal/alias"
	"github.com/safedep/pmg/internal/fsutil"
)

// System install is Linux-only (enforced in cmd/setup); these are Linux
// paths. Supporting another OS means adding its own shim dir and login-shell
// PATH mechanism (macOS has no /etc/profile.d equivalent).
const (
	linuxSystemBinDir      = "/usr/local/lib/pmg/bin"
	linuxSystemProfilePath = "/etc/profile.d/pmg.sh"
	systemProfileMarker    = "PMG system shims"
)

// These overrides replace OS-level system install paths in tests. There is
// intentionally no env var or flag for them.
var (
	systemBinDirOverride      string
	systemProfilePathOverride string
	// systemExecutableOwnershipCheck requires root ownership of the binary and
	// its parent directory. Disabled in tests that cannot create root-owned files.
	systemExecutableOwnershipCheck = true
	// resolveExecutable resolves the running pmg binary for system install.
	// Overridable in tests so validation does not run against the go-build test
	// binary, which is group-writable under a 002 umask.
	resolveExecutable = currentExecutable
)

// SystemBinDir returns the directory for system-wide PMG shims.
func SystemBinDir() string {
	if systemBinDirOverride != "" {
		return systemBinDirOverride
	}
	return linuxSystemBinDir
}

// SystemProfilePath returns the path of the system profile.d snippet.
func SystemProfilePath() string {
	if systemProfilePathOverride != "" {
		return systemProfilePathOverride
	}
	return linuxSystemProfilePath
}

// NewSystemShimManager creates a shim manager for system-wide install: shims
// under SystemBinDir, no per-user rc edits, and system profile management.
// The executable is validated by Install (not here), so Remove works even
// when the installed binary is no longer suitable.
func NewSystemShimManager() (*ShimManager, error) {
	aliasCfg := alias.DefaultConfig()
	pmgBin, err := resolveExecutable()
	if err != nil {
		return nil, err
	}

	return &ShimManager{
		config: ShimConfig{
			BinDir:          SystemBinDir(),
			PMGBin:          pmgBin,
			PackageManagers: aliasCfg.PackageManagers,
			SkipShellRc:     true,
			SystemProfile:   true,
		},
	}, nil
}

// validateSystemExecutable rejects binaries unsafe for system-wide shims.
// Shims hard-code this path, so the binary must be executable by all users,
// not writable by group/others, and owned by root in a root-owned, non-world-
// writable parent. Permission-bit and ownership semantics are Unix-specific;
// on Windows fileOwnerUID reports unavailable so validation fails closed,
// and --system is Linux-gated at the CLI anyway.
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

// SystemShimsInstalled reports whether the system shim directory contains at
// least one shim script.
func SystemShimsInstalled() bool {
	return shimsPresent(SystemBinDir())
}

// SystemShimBinary returns the pmg binary path that installed system shims
// execute (hard-coded as PMG_BIN in every shim). ok is false when no system
// shim with a resolvable PMG_BIN is present. This is the binary every user's
// shim runs, so it is the one whose integrity matters after install. All shims
// are written from the same template in one pass, so reading one suffices.
func SystemShimBinary() (string, bool) {
	content, ok := firstShimContent(SystemBinDir())
	if !ok {
		return "", false
	}
	return parseShimPMGBin(content)
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

// ValidateSystemBinary re-runs the system-install safety checks against path.
// Used by `pmg setup doctor` to detect ownership/permission drift of the
// installed binary after setup (validation otherwise runs only at install).
func ValidateSystemBinary(path string) error {
	return validateSystemExecutable(path)
}

func shimsPresent(dir string) bool {
	_, ok := firstShimContent(dir)
	return ok
}

// firstShimContent returns the content of the first managed shim script in dir.
func firstShimContent(dir string) (string, bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", false
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		content, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err == nil && strings.Contains(string(content), shimScriptMarker) {
			return string(content), true
		}
	}
	return "", false
}

// SystemProfileInstalled reports whether the system profile snippet exists and
// contains the PMG marker.
func SystemProfileInstalled() bool {
	data, err := os.ReadFile(SystemProfilePath())
	if err != nil {
		return false
	}
	return strings.Contains(string(data), systemProfileMarker)
}

func writeSystemProfile(binDir string) error {
	path := SystemProfilePath()

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
		return fsutil.ForceRootOwned(path, 0o644)
	}

	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read system profile %s: %w", path, err)
	}

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("failed to write system profile %s: %w", path, err)
	}

	// The snippet must stay world-readable regardless of root's umask so every
	// user's login shell can source it.
	return fsutil.ForceRootOwned(path, 0o644)
}

func removeSystemProfile() error {
	path := SystemProfilePath()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove system profile %s: %w", path, err)
	}
	return nil
}
