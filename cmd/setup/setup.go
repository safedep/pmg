package setup

import (
	"errors"
	"fmt"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/alias"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/internal/version"
	"github.com/spf13/cobra"
)

func NewSetupCommand() *cobra.Command {
	setupCmd := &cobra.Command{
		Use:   "setup",
		Short: "Manage PMG shell aliases and integration",
		Long:  "Setup and manage PMG config, shell aliases that allow you to use package manager commands through PMG's security wrapper.",
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

			cfgPath, err := config.CreateConfig()
			if err != nil {
				if errors.Is(err, config.ErrConfigAlreadyExists) {
					msg := fmt.Sprintf("⚠️ PMG config already exists at %s\n", cfgPath)
					ui.ShowWarning(msg)
				} else {
					er := fmt.Errorf("failed to create config file: %w", err)
					ui.ErrorExit(er)
					return er
				}
			} else {
				fmt.Printf("📄 PMG config created at %s\n", cfgPath)
			}

			cfg := alias.DefaultConfig()
			rcFileManager, err := alias.NewDefaultRcFileManager(cfg.RcFileName)
			if err != nil {
				return err
			}

			aliasManager := alias.New(cfg, rcFileManager)
			return aliasManager.Install()
		},
	}
}

func NewRemoveCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "remove",
		Short: "Removes pmg aliases from the user's shell config file.",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Print(ui.GeneratePMGBanner(version.Version, version.Commit))

			err := config.RemoveConfig()
			if err != nil {
				return err
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
}
