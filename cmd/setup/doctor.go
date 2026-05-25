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
			Name:     "config-file",
			Category: "Configuration",
			Run: func() doctor.CheckResult {
				return doctor.CheckConfigFile(cfg.ConfigFilePath())
			},
		},
		{
			Name:     "event-log-dir",
			Category: "Configuration",
			Run: func() doctor.CheckResult {
				return doctor.CheckDirectoryWritable(cfg.EventLogDir(), "Event Log")
			},
		},
		{
			Name:     "shell-aliases",
			Category: "Shell Integration",
			Run: func() doctor.CheckResult {
				aliasCfg := alias.DefaultConfig()
				rcFileManager, err := alias.NewDefaultRcFileManager(aliasCfg.RcFileName)
				if err != nil {
					return doctor.CheckResult{
						Status:  doctor.StatusWarn,
						Message: fmt.Sprintf("could not check aliases: %v", err),
					}
				}
				aliasManager := alias.New(aliasCfg, rcFileManager)
				installed, err := aliasManager.IsInstalled()
				return doctor.CheckAliasInstalled(installed, err)
			},
		},
		{
			Name:     "shim-directory",
			Category: "Shell Integration",
			Run: func() doctor.CheckResult {
				sm, err := shim.NewDefaultShimManager()
				if err != nil {
					return doctor.CheckResult{
						Status:  doctor.StatusWarn,
						Message: fmt.Sprintf("could not check shims: %v", err),
					}
				}
				return doctor.CheckShimDirectory(sm.GetBinDir())
			},
		},
		{
			Name:     "shim-in-path",
			Category: "Shell Integration",
			Run: func() doctor.CheckResult {
				sm, err := shim.NewDefaultShimManager()
				if err != nil {
					return doctor.CheckResult{
						Status:  doctor.StatusWarn,
						Message: fmt.Sprintf("could not check shims: %v", err),
					}
				}
				return doctor.CheckShimInPath(sm.GetBinDir(), os.Getenv("PATH"))
			},
		},
		{
			Name:     "proxy-mode",
			Category: "Security",
			Run: func() doctor.CheckResult {
				return doctor.CheckProxyMode(cfg.IsProxyModeEnabled())
			},
		},
		{
			Name:     "dependency-cooldown",
			Category: "Security",
			Run: func() doctor.CheckResult {
				return doctor.CheckSecurityFeature("Dependency Cooldown", cfg.Config.DependencyCooldown.Enabled)
			},
		},
		{
			Name:     "event-logging",
			Category: "Security",
			Run: func() doctor.CheckResult {
				return doctor.CheckSecurityFeature("Event Logging", !cfg.Config.SkipEventLogging)
			},
		},
		{
			Name:     "sandbox",
			Category: "Security",
			Run: func() doctor.CheckResult {
				sb, err := platform.NewSandbox()
				available := err == nil && sb != nil && sb.IsAvailable()
				driverName := ""
				if available {
					driverName = string(sb.Name())
				}
				return doctor.CheckSandbox(cfg.Config.Sandbox.Enabled, available, driverName)
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
	"config-file":       "Config file",
	"event-log-dir":     "Event log directory",
	"shell-aliases":     "Shell aliases",
	"shim-directory":    "Shim directory",
	"shim-in-path":      "Shim in PATH",
	"proxy-mode":        "Proxy mode",
	"dependency-cooldown": "Dependency cooldown",
	"event-logging":     "Event logging",
	"sandbox":           "Sandbox",
	"protection-npm":    "npm protection",
	"protection-pip":    "pip protection",
}

var checkFixes = map[string]string{
	"config-file":    "pmg setup install",
	"shell-aliases":  "pmg setup install",
	"shim-directory": "pmg setup install",
	"shim-in-path":   "Restart shell or source config",
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
