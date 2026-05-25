package setup

import (
	"fmt"
	"os"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/alias"
	"github.com/safedep/pmg/internal/doctor"
	"github.com/safedep/pmg/internal/shim"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/internal/version"
	"github.com/safedep/pmg/sandbox/platform"
	"github.com/spf13/cobra"
)

const (
	checkConfigFile         = "config-file"
	checkEventLogDir        = "event-log-dir"
	checkShellAliases       = "shell-aliases"
	checkShimDirectory      = "shim-directory"
	checkShimInPath         = "shim-in-path"
	checkProxyMode          = "proxy-mode"
	checkDependencyCooldown = "dependency-cooldown"
	checkEventLogging       = "event-logging"
	checkSandbox            = "sandbox"
	checkProtectionNpm      = "protection-npm"
	checkProtectionPip      = "protection-pip"
)

func NewDoctorCommand() *cobra.Command {
	return &cobra.Command{
		Use:          "doctor",
		Short:        "Validate PMG installation and protection",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Print(ui.GeneratePMGBanner(version.Version, version.Commit))
			err := executeDoctorChecks()
			if _, ok := err.(*doctorFailError); ok {
				cmd.SilenceErrors = true
			}
			return err
		},
	}
}

type doctorFailError struct{}

func (e *doctorFailError) Error() string { return "" }
func (e *doctorFailError) ExitCode() int { return 1 }

func executeDoctorChecks() error {
	cfg := config.Get()

	coreResults := runCoreChecks(cfg)
	protectionResults := runProtectionChecks()
	allResults := append(coreResults, protectionResults...)

	printResults(allResults)

	if doctor.HasFailures(allResults) {
		return &doctorFailError{}
	}
	return nil
}

func runCoreChecks(cfg *config.RuntimeConfig) []doctor.CheckResult {
	checks := []doctor.Check{
		{
			Name:     checkConfigFile,
			Category: "Configuration",
			Run: func() doctor.CheckResult {
				return doctor.CheckFileExists(cfg.ConfigFilePath(), "Config file")
			},
		},
		{
			Name:     checkEventLogDir,
			Category: "Configuration",
			Run: func() doctor.CheckResult {
				return doctor.CheckDirectoryExists(cfg.EventLogDir(), "Event log")
			},
		},
		{
			Name:     checkShellAliases,
			Category: "Shell Integration",
			Run: func() doctor.CheckResult {
				aliasCfg := alias.DefaultConfig()
				rcFileManager, err := alias.NewDefaultRcFileManager(aliasCfg.RcFileName)
				if err != nil {
					return doctor.CheckResult{
						Status:  doctor.StatusWarn,
						Message: fmt.Sprintf("Could not check aliases: %v", err),
					}
				}
				aliasManager := alias.New(aliasCfg, rcFileManager)
				installed, err := aliasManager.IsInstalled()
				return doctor.CheckAliasInstalled(installed, err)
			},
		},
		{
			Name:     checkShimDirectory,
			Category: "Shell Integration",
			Run: func() doctor.CheckResult {
				sm, err := shim.NewDefaultShimManager()
				if err != nil {
					return doctor.CheckResult{
						Status:  doctor.StatusWarn,
						Message: fmt.Sprintf("Could not check shims: %v", err),
					}
				}
				return doctor.CheckShimDirectory(sm.GetBinDir())
			},
		},
		{
			Name:     checkShimInPath,
			Category: "Shell Integration",
			Run: func() doctor.CheckResult {
				sm, err := shim.NewDefaultShimManager()
				if err != nil {
					return doctor.CheckResult{
						Status:  doctor.StatusWarn,
						Message: fmt.Sprintf("Could not check shims: %v", err),
					}
				}
				return doctor.CheckShimInPath(sm.GetBinDir(), os.Getenv("PATH"))
			},
		},
		{
			Name:     checkProxyMode,
			Category: "Security",
			Run: func() doctor.CheckResult {
				if cfg.IsProxyModeEnabled() {
					return doctor.CheckResult{
						Status:  doctor.StatusPass,
						Message: "Proxy mode is enabled",
					}
				}
				return doctor.CheckResult{
					Status:  doctor.StatusFail,
					Message: "Proxy mode is disabled → required for package interception",
				}
			},
		},
		{
			Name:     checkDependencyCooldown,
			Category: "Security",
			Run: func() doctor.CheckResult {
				if cfg.Config.DependencyCooldown.Enabled {
					return doctor.CheckResult{
						Status:  doctor.StatusPass,
						Message: "Dependency cooldown is enabled",
					}
				}
				return doctor.CheckResult{
					Status:  doctor.StatusWarn,
					Message: "Dependency cooldown is disabled",
				}
			},
		},
		{
			Name:     checkEventLogging,
			Category: "Security",
			Run: func() doctor.CheckResult {
				if !cfg.Config.SkipEventLogging {
					return doctor.CheckResult{
						Status:  doctor.StatusPass,
						Message: "Event logging is enabled",
					}
				}
				return doctor.CheckResult{
					Status:  doctor.StatusWarn,
					Message: "Event logging is disabled",
				}
			},
		},
		{
			Name:     checkSandbox,
			Category: "Security",
			Run: func() doctor.CheckResult {
				sb, err := platform.NewSandbox()
				available := err == nil && sb != nil && sb.IsAvailable()
				if !cfg.Config.Sandbox.Enabled {
					return doctor.CheckResult{
						Status:  doctor.StatusWarn,
						Message: "Sandbox disabled → enable in config for defense-in-depth",
					}
				}
				if !available {
					return doctor.CheckResult{
						Status:  doctor.StatusFail,
						Message: "Sandbox enabled but no driver available on this platform",
					}
				}
				return doctor.CheckResult{
					Status:  doctor.StatusPass,
					Message: fmt.Sprintf("Sandbox enabled (%s)", sb.Name()),
				}
			},
		},
	}
	return doctor.RunChecks(checks)
}

func runProtectionChecks() []doctor.CheckResult {
	pmgBinary, err := os.Executable()
	if err != nil {
		pmgBinary = "pmg"
	}

	var results []doctor.CheckResult
	for _, tc := range doctor.ProtectionTestCases() {
		result := doctor.RunProtectionCheck(tc, pmgBinary)
		result.Category = "Protection"
		result.Name = fmt.Sprintf("protection-%s", tc.PackageManager)
		results = append(results, result)
	}
	return results
}

var checkDisplayNames = map[string]string{
	checkConfigFile:         "Config file",
	checkEventLogDir:        "Event log directory",
	checkShellAliases:       "Shell aliases",
	checkShimDirectory:      "Shim directory",
	checkShimInPath:         "Shim in PATH",
	checkProxyMode:          "Proxy mode",
	checkDependencyCooldown: "Dependency cooldown",
	checkEventLogging:       "Event logging",
	checkSandbox:            "Sandbox",
	checkProtectionNpm:      "npm protection",
	checkProtectionPip:      "pip protection",
}

var checkFixes = map[string]string{
	checkConfigFile:         "pmg setup install",
	checkEventLogDir:        "pmg setup install",
	checkShellAliases:       "pmg setup install",
	checkShimDirectory:      "pmg setup install",
	checkShimInPath:         "Restart shell or source config",
	checkProxyMode:          "Set proxy.enabled: true in config",
	checkSandbox:            "Set sandbox.enabled: true in config",
	checkDependencyCooldown: "Set dependency_cooldown.enabled: true in config",
	checkEventLogging:       "Set skip_event_logging: false in config",
	checkProtectionNpm:      "Ensure proxy mode is enabled",
	checkProtectionPip:      "Ensure proxy mode is enabled",
}

func printResults(results []doctor.CheckResult) {
	fmt.Println()
	fmt.Println(ui.Colors.Cyan("Setup Diagnostics"))
	fmt.Println(ui.Colors.Normal("--------------------"))

	rows := [][]string{{
		ui.Colors.Bold("STATUS"),
		ui.Colors.Bold("CHECK"),
		ui.Colors.Bold("SUMMARY"),
		ui.Colors.Bold("FIX"),
	}}
	for _, r := range results {
		fix := ui.Colors.Dim("—")
		if r.Status != doctor.StatusPass {
			fix = fixHint(r.Name)
		}
		rows = append(rows, []string{
			statusBadge(r.Status),
			displayName(r.Name),
			ui.Truncate(r.Message, 60),
			fix,
		})
	}

	if err := ui.RenderTable(os.Stdout, rows, nil); err != nil {
		fmt.Fprintf(os.Stderr, "render error: %v\n", err)
	}

	fmt.Println()
	printSummaryLine(results)
}

func statusBadge(s doctor.CheckStatus) string {
	switch s {
	case doctor.StatusPass:
		return ui.Colors.Green("OK")
	case doctor.StatusWarn:
		return ui.Colors.Yellow("WARN")
	case doctor.StatusFail:
		return ui.Colors.Red("FAIL")
	default:
		return "?"
	}
}

func displayName(name string) string {
	if dn, ok := checkDisplayNames[name]; ok {
		return dn
	}
	return name
}

func fixHint(name string) string {
	if fix, ok := checkFixes[name]; ok {
		return fix
	}
	return ui.Colors.Dim("—")
}

func printSummaryLine(results []doctor.CheckResult) {
	passCount, warnCount, failCount := 0, 0, 0
	for _, r := range results {
		switch r.Status {
		case doctor.StatusPass:
			passCount++
		case doctor.StatusWarn:
			warnCount++
		case doctor.StatusFail:
			failCount++
		}
	}

	summary := fmt.Sprintf("%d passed", passCount)
	if warnCount > 0 {
		summary += fmt.Sprintf(", %d warnings", warnCount)
	}
	if failCount > 0 {
		summary += fmt.Sprintf(", %d failed", failCount)
		fmt.Printf("%s  %s\n", ui.Colors.Red("FAIL"), ui.Colors.Red(summary))
	} else if warnCount > 0 {
		fmt.Printf("%s  %s\n", ui.Colors.Yellow("WARN"), ui.Colors.Yellow(summary))
	} else {
		fmt.Printf("%s  %s\n", ui.Colors.Green("OK"), ui.Colors.Green(summary))
	}
}
