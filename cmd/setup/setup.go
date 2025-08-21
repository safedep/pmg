package setup

import (
	"fmt"

	"github.com/safedep/pmg/internal/alias"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/internal/version"
	"github.com/spf13/cobra"
)

func NewSetupCommand() *cobra.Command {
	setupCmd := &cobra.Command{
		Use:   "setup",
		Short: "Manage PMG shell aliases and integration",
		Long:  "Setup and manage PMG shell aliases that allow you to use 'npm', 'pnpm', 'pip' commands through PMG's security wrapper.",
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
		Short: "Install PMG aliases for package managers (npm, pnpm, pip)",
		Long:  "Creates ~/.pmg.rc with package manager aliases and sources it in your shell config files (.bashrc, .zshrc, config.fish)",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Print(ui.GeneratePMGBanner(version.Version, version.Commit))

			config := alias.DefaultConfig()
			rcFileManager, err := alias.NewDefaultRcFileManager(config.RcFileName)
			if err != nil {
				return err
			}

			aliasManager := alias.New(config, rcFileManager)
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

			config := alias.DefaultConfig()
			rcFileManager, err := alias.NewDefaultRcFileManager(config.RcFileName)
			if err != nil {
				return err
			}

			aliasManager := alias.New(config, rcFileManager)
			return aliasManager.Remove()
		},
	}
}
