package alias

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type Shell interface {
	Source(rcPath string) string
	PathExport(binDir string) string
	Name() string

	// InstallRcFiles returns the rc files PMG should write its source/PATH lines
	// into. Existing files are always included. When create is true (the user's
	// primary shell) and no rc file exists, it creates the canonical one so the
	// lines have somewhere to live.
	InstallRcFiles(homeDir string, create bool) ([]string, error)

	// CandidateRcFiles returns every rc file this shell might use, for removal
	// and install detection. The files need not exist.
	CandidateRcFiles(homeDir string) []string
}

var commentForRemovingShellSource = "# remove aliases by running `pmg setup remove` or deleting the line"
var commentForRemovingShellShims = "# remove PMG shims by running `pmg setup remove` or deleting the line"

func defaultPathExport(binDir string) string {
	return fmt.Sprintf("%s\nexport PATH=\"%s:$PATH\"  # PMG shims\n", commentForRemovingShellShims, binDir)
}

func defaultShellSource(rcPath string) string {
	return fmt.Sprintf("%s \n[ -f '%s' ] && source '%s'  # PMG source aliases\n", commentForRemovingShellSource, rcPath, rcPath)
}

// DetectShell attempts to detect the current shell from the SHELL environment variable.
func DetectShell() (string, error) {
	shellEnv := os.Getenv("SHELL")
	if shellEnv == "" {
		return "", fmt.Errorf("SHELL environment variable not set")
	}

	parts := strings.Split(shellEnv, "/")
	shellName := parts[len(parts)-1]

	return shellName, nil
}

// PrimaryShellName returns the user's main shell. It reads $SHELL and falls back
// to the OS default (zsh on macOS, bash elsewhere) when $SHELL is unset. The
// result decides which shell gets its rc file created when none exists yet.
func PrimaryShellName() string {
	if name, err := DetectShell(); err == nil && name != "" {
		return name
	}

	if runtime.GOOS == "darwin" {
		return "zsh"
	}

	return "bash"
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// ensureFile creates an empty file, and any missing parent directories, when it
// does not already exist.
func ensureFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("failed to create directory for %s: %w", path, err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", path, err)
	}

	return f.Close()
}

// firstExistingFile returns the first of names (joined with homeDir) that exists,
// or "" when none do.
func firstExistingFile(homeDir string, names []string) string {
	for _, name := range names {
		path := filepath.Join(homeDir, name)
		if fileExists(path) {
			return path
		}
	}

	return ""
}

// singleRcFile resolves shells that use one rc file (zsh, fish): return it when
// present, create it when create is set, otherwise skip.
func singleRcFile(path string, create bool) ([]string, error) {
	if fileExists(path) {
		return []string{path}, nil
	}

	if !create {
		return nil, nil
	}

	if err := ensureFile(path); err != nil {
		return nil, err
	}

	return []string{path}, nil
}

// RewriteFileDroppingLines rewrites path, removing every line for which drop
// returns true (the line is passed without its trailing newline). It preserves
// the rest of the file byte for byte and its permissions, replaces the file
// atomically via a temp file, and skips the write when no line is dropped. A
// missing file is a no-op. It reads the file in one shot rather than scanning,
// so it has no per-line length limit.
func RewriteFileDroppingLines(path string, drop func(line string) bool) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var b strings.Builder
	b.Grow(len(data))

	dropped := false
	for _, line := range strings.SplitAfter(string(data), "\n") {
		// SplitAfter keeps the newline on each line; the final element is the
		// empty remainder after the last newline.
		if line == "" {
			continue
		}
		if drop(strings.TrimRight(line, "\r\n")) {
			dropped = true
			continue
		}
		b.WriteString(line)
	}

	if !dropped {
		return nil
	}

	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	return writeFileAtomic(path, []byte(b.String()), info.Mode())
}

// writeFileAtomic writes data to a temp file in the target directory, then
// renames it over path so a crash never leaves a half-written file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tempFile, err := os.CreateTemp(filepath.Dir(path), ".tmp-"+filepath.Base(path))
	if err != nil {
		return err
	}
	tempPath := tempFile.Name()

	if _, err := tempFile.Write(data); err != nil {
		_ = tempFile.Close()
		_ = os.Remove(tempPath)
		return err
	}

	if err := tempFile.Close(); err != nil {
		_ = os.Remove(tempPath)
		return err
	}

	if err := os.Chmod(tempPath, perm); err != nil {
		_ = os.Remove(tempPath)
		return err
	}

	if err := os.Rename(tempPath, path); err != nil {
		_ = os.Remove(tempPath)
		return err
	}

	return nil
}
