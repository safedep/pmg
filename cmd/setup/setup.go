package setup

import (
	"errors"
	"fmt"
	"os"
	"runtime"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/alias"
	"github.com/safedep/pmg/internal/shim"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/internal/version"
	"github.com/spf13/cobra"
)

var setupGeteuid = os.Geteuid

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
	setupCmd.AddCommand(NewDoctorCommand())
	setupCmd.AddCommand(NewCertCommand())
	setupCmd.AddCommand(NewCacheCommand())

	return setupCmd
}

func NewInstallCommand() *cobra.Command {
	var system bool
	cmd := &cobra.Command{
		Use:          "install",
		Short:        "Setup PMG config, aliases, and shims for package managers (npm, pnpm, pip, and more)",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Print(ui.GeneratePMGBanner(version.Version, version.Commit))
			return install(system)
		},
	}
	cmd.Flags().BoolVar(&system, "system", false, "Install system-wide for all users (Linux, requires root)")
	return cmd
}

func install(system bool) error {
	if system {
		return installSystem()
	}

	if setupGeteuid() == 0 {
		fmt.Printf("%s %s\n", ui.Colors.Yellow("⚠"),
			"Running as root without --system does not protect other users. Use `pmg setup install --system` so all users are covered.")
	}

	if err := config.WriteTemplateConfig(); err != nil {
		return fmt.Errorf("failed to write template config: %w", err)
	}

	if config.Get().IsManaged() {
		fmt.Printf("%s %s\n", ui.Colors.Dim("ℹ"),
			fmt.Sprintf("Using globally managed config: %s", config.Get().ConfigFilePath()))
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

func installSystem() error {
	if err := requireSystemInstallSupported(); err != nil {
		return err
	}

	shimMgr, err := shim.NewSystemShimManager()
	if err != nil {
		return fmt.Errorf("failed to create system shim manager: %w", err)
	}

	// Shims/profile first so a failed config write does not leave a managed
	// config active without interception.
	if err := shimMgr.Install(); err != nil {
		return fmt.Errorf("failed to install system shims: %w", err)
	}
	if err := config.WriteSystemTemplateConfig(); err != nil {
		return fmt.Errorf("failed to write system config: %w", err)
	}

	ui.PrintSetupSystemInstallCmdInfo(shimMgr.GetBinDir(), config.SystemConfigDir(), shim.SystemProfilePath())
	return nil
}

func NewRemoveCommand() *cobra.Command {
	var (
		removeConfig bool
		system       bool
	)
	cmd := &cobra.Command{
		Use:          "remove",
		Short:        "Removes pmg aliases and shims from the user's shell config.",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Print(ui.GeneratePMGBanner(version.Version, version.Commit))
			return remove(system, removeConfig)
		},
	}

	cmd.Flags().BoolVar(&removeConfig, "config-file", false, "Remove the config file")
	cmd.Flags().BoolVar(&system, "system", false, "Remove system-wide install (Linux, requires root)")
	return cmd
}

func remove(system, removeConfig bool) error {
	if system {
		return removeSystem(removeConfig)
	}

	// Best-effort: attempt every cleanup step so one failure does not strand the
	// other artifacts and force a rerun.
	var errs []error
	if removeConfig {
		// Only ever remove the per-user file; the globally managed
		// config is not ours to delete from a per-user uninstall.
		if err := config.RemoveUserConfigFile(); err != nil {
			errs = append(errs, err)
		}
	}

	if runtime.GOOS == "windows" {
		if len(errs) > 0 {
			return errors.Join(errs...)
		}
		fmt.Printf("%s %s\n", ui.Colors.Green("✓"), "PMG config removed. No aliases or shims to clean up on Windows.")
		return nil
	}

	cfg := alias.DefaultConfig()
	rcFileManager, err := alias.NewDefaultRcFileManager(cfg.RcFileName)
	if err != nil {
		errs = append(errs, err)
	} else if err := alias.New(cfg, rcFileManager).Remove(); err != nil {
		errs = append(errs, fmt.Errorf("failed to remove aliases: %w", err))
	}

	shimMgr, err := shim.NewDefaultShimManager()
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to create shim manager: %w", err))
	} else if err := shimMgr.Remove(); err != nil {
		errs = append(errs, fmt.Errorf("failed to remove shims: %w", err))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	fmt.Printf("%s %s\n", ui.Colors.Green("✓"), "PMG aliases and shims removed. Restart your terminal for changes to take effect")
	return nil
}

func removeSystem(removeConfig bool) error {
	if err := requireSystemInstallSupported(); err != nil {
		return err
	}

	shimMgr, err := shim.NewSystemShimManagerForRemove()
	if err != nil {
		return fmt.Errorf("failed to create system shim manager: %w", err)
	}

	// Best-effort: attempt config removal even if shim removal fails, so one
	// failed step does not strand the other artifact and force a rerun. Shims
	// are removed first so interception stops before the managed config goes.
	var errs []error
	if err := shimMgr.Remove(); err != nil {
		errs = append(errs, fmt.Errorf("failed to remove system shims: %w", err))
	}
	if removeConfig {
		if err := config.RemoveSystemConfigFile(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	fmt.Printf("%s %s\n", ui.Colors.Green("✓"), "PMG system install removed")
	return nil
}

func requireSystemInstallSupported() error {
	if runtime.GOOS != "linux" {
		return usefulerror.NewUsefulError().
			WithCode(errcodes.UnsupportedPlatform).
			WithHumanError("system install is only supported on Linux").
			WithHelp("Use `pmg setup install` without --system for per-user setup, or run on Linux").
			Wrap(errors.New("unsupported platform for --system"))
	}
	if setupGeteuid() != 0 {
		return usefulerror.NewUsefulError().
			WithCode(errcodes.PermissionDenied).
			WithHumanError("system install requires root").
			WithHelp("Re-run as root, e.g. `sudo pmg setup install --system`").
			Wrap(errors.New("not root"))
	}
	return nil
}
