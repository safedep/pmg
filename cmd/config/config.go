package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	appConfig "github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/shellwords"
	"github.com/spf13/cobra"
)

func NewConfigCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "View and modify PMG configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(newGetCommand())
	cmd.AddCommand(newSetCommand())
	cmd.AddCommand(newEditCommand())

	return cmd
}

func newGetCommand() *cobra.Command {
	return &cobra.Command{
		Use:          "get <key>",
		Short:        "Get a config value by dot-notation key (output is JSON)",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			value, err := appConfig.GetConfigValue(args[0])
			if err != nil {
				return err
			}

			data, err := json.Marshal(value)
			if err != nil {
				return fmt.Errorf("failed to marshal value: %w", err)
			}

			_, err = fmt.Fprintln(cmd.OutOrStdout(), string(data))
			return err
		},
	}
}

func newSetCommand() *cobra.Command {
	return &cobra.Command{
		Use:          "set <key> <value>",
		Short:        "Set a config value by dot-notation key",
		Args:         cobra.ExactArgs(2),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return appConfig.SetConfigValue(args[0], args[1])
		},
	}
}

func newEditCommand() *cobra.Command {
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
	cfg := appConfig.Get()
	path := cfg.ConfigFilePath()

	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if err := appConfig.WriteTemplateConfig(); err != nil {
			return fmt.Errorf("failed to create config file: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to stat config file %q: %w", path, err)
	}

	editor, err := resolveEditor()
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
