// Package editor resolves and launches the user's preferred text editor.
package editor

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/safedep/pmg/internal/shellwords"
)

// Resolve returns the editor command from $VISUAL, then $EDITOR, then a
// platform default (vi on Unix, notepad on Windows).
func Resolve() (string, error) {
	if v := strings.TrimSpace(os.Getenv("VISUAL")); v != "" {
		return v, nil
	}
	if v := strings.TrimSpace(os.Getenv("EDITOR")); v != "" {
		return v, nil
	}

	if runtime.GOOS == "windows" {
		return "notepad", nil
	}

	if _, err := exec.LookPath("vi"); err == nil {
		return "vi", nil
	}

	return "", fmt.Errorf("no editor found: set $VISUAL or $EDITOR")
}

// Open launches the resolved editor on path, attached to the current
// terminal, and waits for it to exit. Multi-word values like "code --wait"
// are split with POSIX-like quoting rules, never through a shell.
func Open(path string) error {
	editor, err := Resolve()
	if err != nil {
		return err
	}

	parts, err := shellwords.Split(editor)
	if err != nil {
		return fmt.Errorf("invalid editor command %q: %w", editor, err)
	}
	if len(parts) == 0 {
		return fmt.Errorf("editor command is empty")
	}

	cmd := exec.Command(parts[0], append(parts[1:], path)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("editor %q exited with error: %w", editor, err)
	}

	return nil
}
