package setup

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/safedep/pmg/config"
	"github.com/spf13/cobra"
)

func NewEditCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "edit",
		Short: "Open the PMG config file in your default editor",
		Long: `Open the PMG config file in your default editor.

The editor is resolved in this order:
  1. $VISUAL
  2. $EDITOR
  3. Platform default (vi on Unix, notepad on Windows)

If the config file does not exist, a template is created first.`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runEdit()
		},
	}
}

func runEdit() error {
	cfg := config.Get()
	path := cfg.ConfigFilePath()

	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if err := config.WriteTemplateConfig(); err != nil {
			return fmt.Errorf("failed to create config file: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to stat config file %q: %w", path, err)
	}

	editor, err := resolveEditor()
	if err != nil {
		return err
	}

	// Split editor command so $EDITOR="code --wait" works. Editors with
	// spaces in their executable path should be wrapped in a shell script.
	parts := strings.Fields(editor)
	parts = append(parts, path)

	c := exec.Command(parts[0], parts[1:]...)
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		return fmt.Errorf("editor %q exited with error: %w", editor, err)
	}

	return nil
}

func resolveEditor() (string, error) {
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
