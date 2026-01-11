package setup

import (
	"fmt"
	"strconv"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/alias"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/internal/version"
	"github.com/spf13/cobra"
)

func NewInfoCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "info",
		Short: "Show information about PMG setup and configuration.",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := execueSetupInfo()
			if err != nil {
				ui.ErrorExit(fmt.Errorf("failed to execute setup info: %w", err))
			}

			return nil
		},
	}

	return cmd
}

func execueSetupInfo() error {
	fmt.Print(ui.GeneratePMGBanner(version.Version, version.Commit))

	// Configuration section
	cfg := config.Get()
	configEntries := make(map[string]string)
	configEntries["Config File"] = cfg.ConfigFilePath()
	configEntries["Proxy Mode"] = strconv.FormatBool(cfg.Config.ExperimentalProxyMode)
	ui.PrintInfoSection("Configuration", configEntries)

	// Shell Integration section
	aliasCfg := alias.DefaultConfig()
	rcFileManager, err := alias.NewDefaultRcFileManager(aliasCfg.RcFileName)
	if err != nil {
		return fmt.Errorf("failed to create alias manager: %w", err)
	}

	aliasManager := alias.New(aliasCfg, rcFileManager)
	isInstalled, err := aliasManager.IsInstalled()
	if err != nil {
		isInstalled = false
	}

	shellEntries := make(map[string]string)
	shell, err := alias.DetectShell()
	if err != nil {
		shell = "unknown"
	}

	shellEntries["Detected Shell"] = shell
	shellEntries["Alias Installed"] = strconv.FormatBool(isInstalled)
	ui.PrintInfoSection("Shell Integration", shellEntries)

	// Security section
	securityEntries := make(map[string]string)
	trustedPackages := cfg.Config.TrustedPackages
	trustedPackagesCount := len(trustedPackages)

	if trustedPackagesCount > 3 {
		purls := []string{}
		for _, p := range trustedPackages[0:3] {
			purls = append(purls, p.Purl)
		}

		trustedPackagesValue := fmt.Sprintf("%v ...and %d more", purls, trustedPackagesCount-3)
		securityEntries["Trusted Packages"] = trustedPackagesValue
	} else if trustedPackagesCount > 0 {
		purls := []string{}
		for _, p := range trustedPackages {
			purls = append(purls, p.Purl)
		}

		securityEntries["Trusted Packages"] = fmt.Sprintf("%v", purls)
	} else {
		securityEntries["Trusted Packages"] = "None"
	}

	ui.PrintInfoSection("Security", securityEntries)

	return nil
}
