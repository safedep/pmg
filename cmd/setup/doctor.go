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

	printCompactResults(coreResults, protectionResults)

	if doctor.HasFailures(coreResults) || doctor.HasFailures(protectionResults) {
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

func printCompactResults(coreResults []doctor.CheckResult, protectionResults []doctor.CheckResult) {
	allResults := append(coreResults, protectionResults...)
	categorySummary := doctor.CategorySummary(coreResults)

	categoryOrder := []string{"Configuration", "Shell Integration", "Security"}
	for _, cat := range categoryOrder {
		status, exists := categorySummary[cat]
		if !exists {
			continue
		}

		catResults := filterByCategory(coreResults, cat)
		if status == doctor.StatusPass {
			fmt.Printf("%s %s\n", cat, ui.Colors.Green("✓"))
		} else {
			icon := ui.Colors.Yellow("!")
			if status == doctor.StatusFail {
				icon = ui.Colors.Red("✗")
			}
			fmt.Printf("%s %s\n", cat, icon)
			for _, r := range catResults {
				printCheckLine(r)
			}
		}
	}

	fmt.Printf("Protection %s\n", categoryIcon(protectionResults))
	for _, r := range protectionResults {
		printCheckLine(r)
	}

	fmt.Println()
	printSummaryLine(allResults)
}

func printCheckLine(r doctor.CheckResult) {
	switch r.Status {
	case doctor.StatusPass:
		fmt.Printf("  %s %s\n", ui.Colors.Green("✓"), ui.Colors.Dim(r.Message))
	case doctor.StatusWarn:
		fmt.Printf("  %s %s\n", ui.Colors.Yellow("!"), ui.Colors.Yellow(r.Message))
	case doctor.StatusFail:
		fmt.Printf("  %s %s\n", ui.Colors.Red("✗"), ui.Colors.Red(r.Message))
	}
}

func categoryIcon(results []doctor.CheckResult) string {
	worst := doctor.StatusPass
	for _, r := range results {
		if r.Status > worst {
			worst = r.Status
		}
	}
	switch worst {
	case doctor.StatusPass:
		return ui.Colors.Green("✓")
	case doctor.StatusWarn:
		return ui.Colors.Yellow("!")
	default:
		return ui.Colors.Red("✗")
	}
}

func filterByCategory(results []doctor.CheckResult, category string) []doctor.CheckResult {
	var filtered []doctor.CheckResult
	for _, r := range results {
		if r.Category == category {
			filtered = append(filtered, r)
		}
	}
	return filtered
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
		fmt.Printf("%s  %s\n", ui.Colors.Red("✗"), ui.Colors.Red(summary))
	} else if warnCount > 0 {
		fmt.Printf("%s  %s\n", ui.Colors.Yellow("!"), ui.Colors.Yellow(summary))
	} else {
		fmt.Printf("%s  %s\n", ui.Colors.Green("✓"), ui.Colors.Green(summary))
	}
}
