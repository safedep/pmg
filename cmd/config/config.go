package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	appConfig "github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/editor"
	"github.com/safedep/pmg/internal/platform"
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
	cmd.AddCommand(newPathCommand())

	return cmd
}

const systemFlagUsage = "Use the managed config that governs every user and the enforcing proxy daemon (root only)"

func newGetCommand() *cobra.Command {
	var system bool
	cmd := &cobra.Command{
		Use:          "get <key>",
		Short:        "Get a config value by dot-notation key (output is JSON)",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			value, err := getValue(args[0], system)
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
	cmd.Flags().BoolVar(&system, "system", false, systemFlagUsage)
	return cmd
}

func getValue(key string, system bool) (any, error) {
	if system {
		return appConfig.GetSystemConfigValue(key)
	}
	return appConfig.GetConfigValue(key)
}

func newSetCommand() *cobra.Command {
	var system bool
	cmd := &cobra.Command{
		Use:          "set <key> <value>",
		Short:        "Set a config value by dot-notation key",
		Args:         cobra.ExactArgs(2),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return setValue(args[0], args[1], system)
		},
	}
	cmd.Flags().BoolVar(&system, "system", false, systemFlagUsage)
	return cmd
}

func setValue(key, value string, system bool) error {
	if system {
		return appConfig.SetSystemConfigValue(key, value)
	}
	if platform.IsSudo() {
		return appConfig.NewSudoNeedsSystemError("set")
	}
	return appConfig.SetConfigValue(key, value)
}

func newEditCommand() *cobra.Command {
	var system bool
	cmd := &cobra.Command{
		Use:   "edit",
		Short: "Open the PMG config file in your default editor",
		Long: `Open the PMG config file in your default editor.

The editor is resolved in this order:
  1. $VISUAL
  2. $EDITOR
  3. Platform default (vi on Unix, notepad on Windows)

If the config file does not exist, a template is created first.

With --system the command opens the managed config instead, the file that
governs every user and that an enforcing proxy daemon reads. It needs root.`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runEdit(system)
		},
	}
	cmd.Flags().BoolVar(&system, "system", false, systemFlagUsage)
	return cmd
}

func runEdit(system bool) error {
	path, err := editPath(system)
	if err != nil {
		return err
	}
	return editor.Open(path)
}

// editPath picks the file to open and creates it when it is missing. The
// managed file needs root. Under sudo without --system the command refuses,
// because it would open root's per-user file, which no daemon is meant to
// read and which the user never sees.
func editPath(system bool) (string, error) {
	if system {
		if err := platform.RequirePrivilege("pmg config edit --system"); err != nil {
			return "", err
		}
		return appConfig.EnsureSystemConfigFile()
	}
	if platform.IsSudo() {
		return "", appConfig.NewSudoNeedsSystemError("edit")
	}

	cfg := appConfig.Get()
	if cfg.IsManaged() {
		return "", appConfig.NewManagedConfigError()
	}

	path := cfg.ConfigFilePath()
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if err := appConfig.WriteTemplateConfig(); err != nil {
			return "", fmt.Errorf("failed to create config file: %w", err)
		}
	} else if err != nil {
		return "", fmt.Errorf("failed to stat config file %q: %w", path, err)
	}
	return path, nil
}

func newPathCommand() *cobra.Command {
	return &cobra.Command{
		Use:          "path",
		Short:        "Print the active config file and why PMG chose it",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			rootPath, err := appConfig.RootUserConfigFilePath()
			if err != nil {
				rootPath = ""
			}
			_, err = fmt.Fprint(cmd.OutOrStdout(), configPathText(appConfig.Get(), rootPath, appConfig.SystemConfigFilePath()))
			return err
		},
	}
}

// configPathText renders the active file with its source. A user file gets
// a second line, because a root daemon never reads it: the daemon reads
// root's per-user file, or the managed file when that exists.
func configPathText(cfg *appConfig.RuntimeConfig, rootPath, systemPath string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s (%s", cfg.ConfigFilePath(), cfg.ConfigSource())
	if cfg.IsManaged() {
		b.WriteString(", authoritative")
		if cfg.IsLocked() {
			b.WriteString(", locked")
		}
	}
	b.WriteString(")\n")

	if cfg.ConfigSource() != appConfig.ConfigSourceUser || rootPath == "" {
		return b.String()
	}
	fmt.Fprintf(&b, "  ignored by a root daemon: it reads %s", rootPath)
	if systemPath != "" {
		fmt.Fprintf(&b, ", or %s when that exists", systemPath)
	}
	b.WriteString("\n")
	return b.String()
}
