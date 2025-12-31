package setup

import (
	"fmt"
	"os"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/alias"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/internal/version"
	"github.com/spf13/cobra"
)

var (
	setupRemoveConfigFile = false
)

func NewSetupCommand() *cobra.Command {
	setupCmd := &cobra.Command{
		Use:   "setup",
		Short: "Manage PMG shell aliases and integration",
		Long:  "Setup and manage PMG config, shell aliases that allow you to use package manager commands with security guardrails.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	setupCmd.AddCommand(NewInstallCommand())
	setupCmd.AddCommand(NewRemoveCommand())

	return setupCmd
}

func NewInstallCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "install",
		Short: "Setup PMG config and aliases for package managers (npm, pnpm, pip, and more)",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Print(ui.GeneratePMGBanner(version.Version, version.Commit))

			cfg := alias.DefaultConfig()
			rcFileManager, err := alias.NewDefaultRcFileManager(cfg.RcFileName)
			if err != nil {
				return fmt.Errorf("failed to create alias manager: %w", err)
			}

			aliasManager := alias.New(cfg, rcFileManager)
			err = aliasManager.Install()
			if err != nil {
				return fmt.Errorf("failed to install aliases: %w", err)
			}

			if err := config.WriteTemplateConfig(); err != nil {
				return fmt.Errorf("failed to write template config: %w", err)
			}

			return nil
		},
	}
}

func NewRemoveCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Removes pmg aliases from the user's shell config file.",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Print(ui.GeneratePMGBanner(version.Version, version.Commit))

			// We remove the config file only if explicitly asked to do so.
			if setupRemoveConfigFile {
				config := config.Get()
				if err := os.Remove(config.ConfigFilePath()); err != nil && !os.IsNotExist(err) {
					return fmt.Errorf("failed to remove config file %q: %w", config.ConfigFilePath(), err)
				}
			}

			cfg := alias.DefaultConfig()
			rcFileManager, err := alias.NewDefaultRcFileManager(cfg.RcFileName)
			if err != nil {
				return err
			}

			aliasManager := alias.New(cfg, rcFileManager)
			return aliasManager.Remove()
		},
	}

	cmd.Flags().BoolVar(&setupRemoveConfigFile, "config-file", false, "Remove the config file")
	return cmd
}
