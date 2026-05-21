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
