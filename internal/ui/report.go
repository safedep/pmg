package ui

import (
	"fmt"
	"time"

	"github.com/safedep/pmg/analyzer"
)

// FlowType indicates which execution flow was used
type FlowType int

const (
	FlowTypeGuard FlowType = iota
	FlowTypeProxy
)

func (f FlowType) String() string {
	switch f {
	case FlowTypeGuard:
		return "guard"
	case FlowTypeProxy:
		return "proxy"
	default:
		return "unknown"
	}
}

// ExecutionOutcome represents the final result of the PMG execution
type ExecutionOutcome int

const (
	OutcomeSuccess ExecutionOutcome = iota
	OutcomeBlocked
	OutcomeUserCancelled
	OutcomeDryRun
	OutcomeError
	OutcomeInsecureBypass
)

func (o ExecutionOutcome) String() string {
	switch o {
	case OutcomeSuccess:
		return "success"
	case OutcomeBlocked:
		return "blocked"
	case OutcomeUserCancelled:
		return "user_cancelled"
	case OutcomeDryRun:
		return "dry_run"
	case OutcomeError:
		return "error"
	case OutcomeInsecureBypass:
		return "insecure_bypass"
	default:
		return "unknown"
	}
}

// ReportData captures execution statistics for the post-execution report.
// This is a pure data model with no rendering logic.
type ReportData struct {
	// Execution metadata
	PackageManagerName string
	StartTime          time.Time
	Duration           time.Duration

	// Package statistics (consistent across guard and proxy flows)
	TotalAnalyzed  int
	TrustedSkipped int

	// Analysis breakdown
	AllowedCount   int
	ConfirmedCount int
	BlockedCount   int

	// Details for verbose mode
	BlockedPackages   []*analyzer.PackageVersionAnalysisResult
	ConfirmedPackages []*analyzer.PackageVersionAnalysisResult

	// Configuration context
	FlowType          FlowType
	DryRun            bool
	InsecureMode      bool
	TransitiveEnabled bool
	ParanoidMode      bool
	SandboxEnabled    bool
	SandboxProfile    string

	// Outcome
	Outcome ExecutionOutcome
}

// NewReportData creates a new ReportData with sensible defaults
func NewReportData() *ReportData {
	return &ReportData{
		StartTime: time.Now(),
		Outcome:   OutcomeSuccess,
	}
}

// Finalize sets the duration based on start time
func (r *ReportData) Finalize() {
	r.Duration = time.Since(r.StartTime)
}

// HasIssues returns true if any packages were blocked or required confirmation
func (r *ReportData) HasIssues() bool {
	return r.BlockedCount > 0 || r.ConfirmedCount > 0
}

// WasSuccessful returns true if execution completed without blocks or errors
func (r *ReportData) WasSuccessful() bool {
	return r.Outcome == OutcomeSuccess || r.Outcome == OutcomeDryRun
}

// Report renders the execution report based on verbosity level.
// This is the public API - flows call this with collected data.
func Report(data *ReportData) {
	data.Finalize()

	switch verbosityLevel {
	case VerbosityLevelSilent:
		reportSilent(data)
	case VerbosityLevelNormal:
		reportNormal(data)
	case VerbosityLevelVerbose:
		reportVerbose(data)
	}
}

// reportSilent only shows output on errors or blocks
// Normal successful execution produces no output
func reportSilent(data *ReportData) {
	// Silent mode: no report output
	// Block messages and errors are already shown via ui.Block() and ui.ErrorExit()
}

// reportNormal shows minimal, assuring output
func reportNormal(data *ReportData) {
	if data.Outcome == OutcomeDryRun {
		return // Dry run already shows its own message
	}

	if data.Outcome == OutcomeError {
		return // Error handling done elsewhere
	}

	if data.Outcome == OutcomeInsecureBypass {
		// Security-sensitive: Always show warning when protection is bypassed
		icon := Colors.Red("⚠")
		message := "INSECURE MODE - Malware protection bypassed"

		if data.TotalAnalyzed > 0 {
			fmt.Printf("%s %s (%d packages installed without analysis)\n",
				icon, Colors.Red(message), data.TotalAnalyzed)
		} else {
			fmt.Printf("%s %s\n", icon, Colors.Red(message))
		}

		return
	}

	if data.TotalAnalyzed == 0 {
		// No packages analyzed (e.g., npm install with no new packages)
		return
	}

	var icon string
	var message string

	switch data.Outcome {
	case OutcomeBlocked:
		icon = Colors.Red("✗")
		message = fmt.Sprintf("PMG: %d packages analyzed, %d blocked",
			data.TotalAnalyzed, data.BlockedCount)
	case OutcomeUserCancelled:
		icon = Colors.Yellow("✗")
		message = fmt.Sprintf("PMG: %d packages analyzed, installation cancelled",
			data.TotalAnalyzed)
	default:
		// Success case
		if data.HasIssues() {
			icon = Colors.Yellow("!")
			message = fmt.Sprintf("PMG: %d packages analyzed (%d confirmed)",
				data.TotalAnalyzed, data.ConfirmedCount)
		} else {
			icon = Colors.Green("✓")
			message = fmt.Sprintf("PMG: %d packages analyzed", data.TotalAnalyzed)
		}
	}

	fmt.Printf("%s %s\n", icon, Colors.Dim(message))
}

// reportVerbose shows detailed debugging information
func reportVerbose(data *ReportData) {
	fmt.Println()
	fmt.Println(Colors.Cyan("PMG Execution Report"))
	fmt.Println(Colors.Normal("────────────────────────────────────────"))

	// Outcome summary line
	printOutcomeLine(data)

	// Statistics section
	fmt.Println()
	if data.TrustedSkipped > 0 {
		fmt.Printf("  %s %d analyzed (%d trusted skipped)\n",
			Colors.Bold("Packages:"),
			data.TotalAnalyzed,
			data.TrustedSkipped)
	} else {
		fmt.Printf("  %s %d analyzed\n",
			Colors.Bold("Packages:"),
			data.TotalAnalyzed)
	}

	fmt.Printf("  %s %s (allowed: %d, confirmed: %d, blocked: %d)\n",
		Colors.Bold("Analysis:"),
		formatDuration(data.Duration),
		data.AllowedCount,
		data.ConfirmedCount,
		data.BlockedCount)

	// Configuration section
	fmt.Println()
	fmt.Printf("  %s %s | %s flow | transitive: %s | paranoid: %s\n",
		Colors.Bold("Config:"),
		data.PackageManagerName,
		data.FlowType.String(),
		boolToOnOff(data.TransitiveEnabled),
		boolToOnOff(data.ParanoidMode))

	if data.SandboxEnabled {
		profile := data.SandboxProfile
		if profile == "" {
			profile = "default"
		}
		fmt.Printf("  %s enabled (%s)\n",
			Colors.Bold("Sandbox:"),
			profile)
	}

	// Show blocked/confirmed package details in verbose mode
	if len(data.BlockedPackages) > 0 {
		fmt.Println()
		fmt.Println(Colors.Red("  Blocked packages:"))
		for _, pkg := range data.BlockedPackages {
			printPackageDetail(pkg)
		}
	}

	if len(data.ConfirmedPackages) > 0 {
		fmt.Println()
		fmt.Println(Colors.Yellow("  User-confirmed packages:"))
		for _, pkg := range data.ConfirmedPackages {
			printPackageDetail(pkg)
		}
	}

	fmt.Println()
}

func printOutcomeLine(data *ReportData) {
	switch data.Outcome {
	case OutcomeSuccess:
		fmt.Printf("  %s %s\n", Colors.Green("✓"), Colors.Green("Installation completed successfully"))
	case OutcomeBlocked:
		fmt.Printf("  %s %s\n", Colors.Red("✗"), Colors.Red("Installation blocked - malicious package detected"))
	case OutcomeUserCancelled:
		fmt.Printf("  %s %s\n", Colors.Yellow("✗"), Colors.Yellow("Installation cancelled by user"))
	case OutcomeDryRun:
		fmt.Printf("  %s %s\n", Colors.Cyan("○"), Colors.Cyan("Dry run completed - no packages installed"))
	case OutcomeError:
		fmt.Printf("  %s %s\n", Colors.Red("✗"), Colors.Red("Execution failed with error"))
	case OutcomeInsecureBypass:
		fmt.Printf("  %s %s\n", Colors.Yellow("⚠"), Colors.Yellow("Installation completed (insecure mode - protection bypassed)"))
	}
}

func printPackageDetail(pkg *analyzer.PackageVersionAnalysisResult) {
	if pkg == nil || pkg.PackageVersion == nil {
		return
	}

	name := pkg.PackageVersion.GetPackage().GetName()
	version := pkg.PackageVersion.GetVersion()
	fmt.Printf("    - %s@%s\n", name, version)

	if pkg.ReferenceURL != "" {
		fmt.Printf("      %s\n", Colors.Dim(pkg.ReferenceURL))
	}
}

func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}

func boolToOnOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}
