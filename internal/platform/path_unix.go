//go:build unix

package platform

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// SystemProfileMarker tags the /etc/profile.d snippet PMG writes for a
// machine install, so a later run finds and rewrites its own snippet.
const SystemProfileMarker = "PMG system shims"

// ShellPath on Unix is just the process PATH: there is one PATH, and a shell
// started fresh gets the same one.
type ShellPath struct {
	// Entries is the PATH a new shell gets, in order.
	Entries []string
}

func NewShellPath() (ShellPath, error) {
	return ShellPath{Entries: filepath.SplitList(os.Getenv("PATH"))}, nil
}

// LookPath resolves name over the PATH. There is one PATH on Unix, so the
// resolution carries no origin.
func (p ShellPath) LookPath(name string) (string, PathOrigin, error) {
	resolved, err := exec.LookPath(name)
	if err != nil {
		return "", PathOriginUnknown, err
	}
	return resolved, PathOriginUnknown, nil
}

// WriteSystemProfile writes the login-shell snippet that puts dir on the PATH
// of every account. It rewrites the snippet in place when dir changed, and
// keeps it world-readable regardless of root's umask so every login shell can
// source it. It does not chown or chmod /etc/profile.d itself, a shared
// directory PMG does not own.
func WriteSystemProfile(path, dir string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("failed to create profile.d directory: %w", err)
	}

	content := fmt.Sprintf(`# %s - managed by pmg setup install --system
# remove by running: pmg setup remove --system
export PATH="%s:$PATH"
`, SystemProfileMarker, dir)

	data, err := os.ReadFile(path)
	if err == nil && string(data) == content {
		return ProtectSystemPath(path, 0o644)
	}
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read system profile %s: %w", path, err)
	}

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("failed to write system profile %s: %w", path, err)
	}
	return ProtectSystemPath(path, 0o644)
}

// RemoveSystemProfile deletes the snippet. A missing file is not an error.
func RemoveSystemProfile(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove system profile %s: %w", path, err)
	}
	return nil
}

// SystemProfileInstalled reports whether the snippet exists and carries the
// PMG marker.
func SystemProfileInstalled(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), SystemProfileMarker)
}
