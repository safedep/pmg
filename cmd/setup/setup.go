package setup

import (
	"fmt"
	"os"
	"runtime"

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
		Short: "Manage PMG shell integration (aliases and shims)",
		Long:  "Setup and manage PMG config, shell aliases and PATH shims that allow you to use package manager commands with security guardrails.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	setupCmd.AddCommand(NewInstallCommand())
	setupCmd.AddCommand(NewRemoveCommand())
	setupCmd.AddCommand(NewInfoCommand())

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
	if err := config.WriteTemplateConfig(); err != nil {
		return fmt.Errorf("failed to write template config: %w", err)
	}

	if runtime.GOOS == "windows" {
		fmt.Printf("%s %s\n", ui.Colors.Green("✓"), "PMG config written successfully")
		fmt.Printf("   %s\n", ui.Colors.Dim(fmt.Sprintf("Config:  %s", config.Get().ConfigDir())))
		fmt.Printf("\n%s Shell aliases and PATH shims are not supported on Windows. Use WSL for full shell integration.\n",
			ui.Colors.Yellow("⚠"))
		return nil
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

	shimMgr, err := shim.NewDefaultShimManager()
	if err != nil {
		return fmt.Errorf("failed to create shim manager: %w", err)
	}

	if err := shimMgr.Install(); err != nil {
		return fmt.Errorf("failed to install shims: %w", err)
	}

	ui.PrintSetupInstallCmdInfo(aliasManager.GetRcPath(), shimMgr.GetBinDir(), config.Get().ConfigDir())
	return nil
}

func NewRemoveCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "remove",
		Short:        "Removes pmg aliases and shims from the user's shell config.",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Print(ui.GeneratePMGBanner(version.Version, version.Commit))

			if setupRemoveConfigFile {
				config := config.Get()
				if err := os.Remove(config.ConfigFilePath()); err != nil && !os.IsNotExist(err) {
					return fmt.Errorf("failed to remove config file %q: %w", config.ConfigFilePath(), err)
				}
			}

			if runtime.GOOS == "windows" {
				fmt.Printf("%s %s\n", ui.Colors.Green("✓"), "PMG config removed. No aliases or shims to clean up on Windows.")
				return nil
			}

			cfg := alias.DefaultConfig()
			rcFileManager, err := alias.NewDefaultRcFileManager(cfg.RcFileName)
			if err != nil {
				return err
			}

			aliasManager := alias.New(cfg, rcFileManager)
			if err := aliasManager.Remove(); err != nil {
				return fmt.Errorf("failed to remove aliases: %w", err)
			}

			shimMgr, err := shim.NewDefaultShimManager()
			if err != nil {
				return fmt.Errorf("failed to create shim manager: %w", err)
			}

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
