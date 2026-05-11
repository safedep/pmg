package setup

import (
	"fmt"
	"os"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/alias"
	"github.com/safedep/pmg/internal/shim"
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
		Short: "Manage PMG shell integration (shims and aliases)",
		Long:  "Setup and manage PMG config, shell shims or aliases that allow you to use package manager commands with security guardrails.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	setupCmd.AddCommand(NewInstallCommand())
	setupCmd.AddCommand(NewRemoveCommand())
	setupCmd.AddCommand(NewInfoCommand())
	setupCmd.AddCommand(NewEditCommand())

	return setupCmd
}

func NewInstallCommand() *cobra.Command {
	return &cobra.Command{
		Use:          "install",
		Short:        "Setup PMG config, aliases, and shims for package managers (npm, pnpm, pip, and more)",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Print(ui.GeneratePMGBanner(version.Version, version.Commit))
			return install()
		},
	}
}

func install() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	cfg := alias.DefaultConfig()
	rcFileManager, err := alias.NewDefaultRcFileManager(cfg.RcFileName)
	if err != nil {
		return fmt.Errorf("failed to create alias manager: %w", err)
	}

	aliasManager := alias.New(cfg, rcFileManager)
	if err := aliasManager.Install(); err != nil {
		return fmt.Errorf("failed to install aliases: %w", err)
	}

	shimMgr := shim.NewShimManager(shim.DefaultShimConfig(homeDir))
	if err := shimMgr.Install(); err != nil {
		return fmt.Errorf("failed to install shims: %w", err)
	}

	if err := config.WriteTemplateConfig(); err != nil {
		return fmt.Errorf("failed to write template config: %w", err)
	}

	ui.PrintSetupInstallCmdInfo(aliasManager.GetRcPath(), shimMgr.GetBinDir(), config.Get().ConfigDir())
	return nil
}

func NewRemoveCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "remove",
		Short:        "Removes pmg shims and aliases from the user's shell config.",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Print(ui.GeneratePMGBanner(version.Version, version.Commit))

			if setupRemoveConfigFile {
				config := config.Get()
				if err := os.Remove(config.ConfigFilePath()); err != nil && !os.IsNotExist(err) {
					return fmt.Errorf("failed to remove config file %q: %w", config.ConfigFilePath(), err)
				}
			}

			aliasCfg := alias.DefaultConfig()
			rcFileManager, err := alias.NewDefaultRcFileManager(aliasCfg.RcFileName)
			if err != nil {
				return err
			}

			aliasManager := alias.New(aliasCfg, rcFileManager)
			if err := aliasManager.Remove(); err != nil {
				return fmt.Errorf("failed to remove aliases: %w", err)
			}

			homeDir, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("failed to get home directory: %w", err)
			}

			shimMgr := shim.NewShimManager(shim.DefaultShimConfig(homeDir))
			if err := shimMgr.Remove(); err != nil {
				return fmt.Errorf("failed to remove shims: %w", err)
			}

			fmt.Printf("%s %s\n", ui.Colors.Green("✓"), "PMG aliases and shims removed. Restart your terminal for changes to take effect")
			return nil
		},
	}

	cmd.Flags().BoolVar(&setupRemoveConfigFile, "config-file", false, "Remove the config file")
	return cmd
}
