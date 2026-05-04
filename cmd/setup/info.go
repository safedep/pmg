package setup

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/safedep/dry/cloud"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/alias"
	"github.com/safedep/pmg/internal/analytics"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/internal/version"
	"github.com/spf13/cobra"
)

func NewInfoCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "info",
		Short: "Show information about PMG setup and configuration.",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := executeSetupInfo()
			if err != nil {
				ui.ErrorExit(fmt.Errorf("failed to execute setup info: %w", err))
			}

			return nil
		},
	}

	return cmd
}

func executeSetupInfo() error {
	fmt.Print(ui.GeneratePMGBanner(version.Version, version.Commit))

	// Configuration section
	cfg := config.Get()
	configEntries := make(map[string]string)
	configEntries["Config File"] = cfg.ConfigFilePath()
	configEntries["Proxy Mode"] = strconv.FormatBool(cfg.IsProxyModeEnabled())
	configEntries["Proxy Install Only"] = strconv.FormatBool(cfg.Config.ProxyInstallOnly)
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

	securityEntries["Dependency Cooldown"] = strconv.FormatBool(cfg.Config.DependencyCooldown.Enabled)
	securityEntries["Dependency Cooldown Days"] = strconv.Itoa(cfg.Config.DependencyCooldown.Days)
	securityEntries["Telemetry"] = strconv.FormatBool(!analytics.IsDisabled())
	securityEntries["Event Logging"] = strconv.FormatBool(!cfg.Config.SkipEventLogging)
	securityEntries["Event Log Directory"] = cfg.EventLogDir()

	ui.PrintInfoSection("Security", securityEntries)

	// Sandbox section
	sandboxCfg := cfg.Config.Sandbox
	sandboxEntries := make(map[string]string)
	sandboxEntries["Enabled"] = strconv.FormatBool(sandboxCfg.Enabled)
	sandboxEntries["Enforce Always"] = strconv.FormatBool(sandboxCfg.EnforceAlways)

	if len(sandboxCfg.Policies) > 0 {
		pmNames := make([]string, 0, len(sandboxCfg.Policies))
		for name := range sandboxCfg.Policies {
			pmNames = append(pmNames, name)
		}

		sort.Strings(pmNames)

		policyParts := make([]string, 0, len(pmNames))
		for _, name := range pmNames {
			ref := sandboxCfg.Policies[name]
			status := "disabled"
			if ref.Enabled {
				status = ref.Profile
			}

			policyParts = append(policyParts, fmt.Sprintf("%s(%s)", name, status))
		}

		sandboxEntries["Policies"] = strings.Join(policyParts, ", ")
	} else {
		sandboxEntries["Policies"] = "None"
	}

	ui.PrintInfoSection("Sandbox", sandboxEntries)

	if cfg.Config.Cloud.Enabled {
		cloudEntries := make(map[string]string)
		cloudEntries["Enabled"] = "true"
		cloudEntries["Sync DB"] = cfg.CloudSyncDBPath()
		if cfg.Config.Cloud.EndpointID != "" {
			cloudEntries["Endpoint ID"] = cfg.Config.Cloud.EndpointID
		}
		cloudEntries["Credentials"] = describeCloudCredentials()
		ui.PrintInfoSection("Cloud Sync", cloudEntries)
	}

	return nil
}

// describeCloudCredentials reports whether SafeDep Cloud credentials can be
// resolved, and from where. The resolution order matches NewSyncClientBundle:
// keychain first, then environment variables. No network calls are made.
func describeCloudCredentials() string {
	if source, ok := tryResolveKeychainCredentials(); ok {
		return source
	}
	if source, ok := tryResolveEnvCredentials(); ok {
		return source
	}
	return "not configured (run 'pmg cloud login' or set SAFEDEP_API_KEY and SAFEDEP_TENANT_ID)"
}

func tryResolveKeychainCredentials() (string, bool) {
	resolver, err := cloud.NewKeychainCredentialResolver(cloud.CredentialTypeAPIKey)
	if err != nil {
		log.Debugf("keychain credential resolver unavailable: %v", err)
		return "", false
	}
	defer func() {
		if err := resolver.Close(); err != nil {
			log.Warnf("failed to close keychain resolver: %v", err)
		}
	}()

	if _, err := resolver.Resolve(); err != nil {
		log.Debugf("no keychain credentials: %v", err)
		return "", false
	}
	return "keychain", true
}

func tryResolveEnvCredentials() (string, bool) {
	resolver, err := cloud.NewEnvCredentialResolver()
	if err != nil {
		log.Debugf("env credential resolver unavailable: %v", err)
		return "", false
	}
	if _, err := resolver.Resolve(); err != nil {
		log.Debugf("no env credentials: %v", err)
		return "", false
	}
	return "environment (SAFEDEP_API_KEY, SAFEDEP_TENANT_ID)", true
}
