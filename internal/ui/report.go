package ui

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/internal/models"
	"github.com/safedep/pmg/proxy/netpolicy"
)

// FlowType indicates which execution flow was used
type FlowType int

const (
	FlowTypeProxy FlowType = iota
)

func (f FlowType) String() string {
	switch f {
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

	// Package statistics
	TotalAnalyzed  int
	TrustedSkipped int

	// Analysis breakdown
	AllowedCount   int
	ConfirmedCount int
	BlockedCount   int

	// Details for verbose mode
	BlockedPackages   []*analyzer.PackageVersionAnalysisResult
	ConfirmedPackages []*analyzer.PackageVersionAnalysisResult

	// Packages blocked by the dependency cooldown policy (proxy mode only)
	CooldownBlockedPackages []models.CooldownBlock

	// Versions stripped by cooldown while eligible versions remained (proxy
	// mode only). Not blocks: the resolver usually falls back, but an install
	// can still fail when a dependency requires exactly a withheld version.
	// Rendered as a hint when the install fails.
	CooldownWithheldPackages []models.CooldownWithheld

	// NetworkPolicy holds the connections a deny rule matched. nil when no
	// policy ran.
	NetworkPolicy *netpolicy.Report

	// NetworkRunID names the run in the event log and ObservedDestinations
	// is how many destinations the proxy saw, so the report can point at
	// `pmg sandbox profile propose`.
	NetworkRunID         string
	ObservedDestinations int

	// AdvisoryMessage is the optional org-configured message appended to block
	// output regardless of which control blocked. Set from advisory_message.
	AdvisoryMessage string

	// Configuration context
	FlowType       FlowType
	DryRun         bool
	InsecureMode   bool
	ParanoidMode   bool
	SandboxEnabled bool
	SandboxProfile string

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
	return r.BlockedCount > 0 || r.ConfirmedCount > 0 || len(r.CooldownBlockedPackages) > 0
}

// WasSuccessful returns true if execution completed without blocks or errors
func (r *ReportData) WasSuccessful() bool {
	return r.Outcome == OutcomeSuccess || r.Outcome == OutcomeDryRun
}

// Report renders the execution report based on verbosity level.
// This is the public API - flows call this with collected data.
func Report(data *ReportData) {
	data.Finalize()

	StopSpinner()

	switch verbosityLevel {
	case VerbosityLevelSilent:
		reportSilent(data)
	case VerbosityLevelNormal:
		reportNormal(data)
	case VerbosityLevelVerbose:
		reportVerbose(data)
	}
}

// MalwareBlockedHeadline is the headline printed when a malicious package is
// blocked. Exported so out-of-process consumers (e.g. `pmg setup doctor`) can
// detect a genuine block from captured output instead of inferring it from a
// non-zero exit code, which any failure would also produce.
const MalwareBlockedHeadline = "Malicious package blocked"

func printMalwareBlockSection(data *ReportData) {
	if len(data.BlockedPackages) == 0 {
		return
	}

	fmt.Println()
	fmt.Printf("%s %s\n", Colors.Red("✗"), Colors.Red(MalwareBlockedHeadline))
	printMaliciousPackagesList(data.BlockedPackages)
	fmt.Println()
}

// reportSilent shows output only when the install was blocked: silent mode
// hides PMG except for errors and malicious package detection. Cooldown-only
// blocks stay hidden, matching the documented silent contract.
func reportSilent(data *ReportData) {
	if data.Outcome != OutcomeBlocked || len(data.BlockedPackages) == 0 {
		return
	}

	printMalwareBlockSection(data)
	printAdvisoryMessage(data.AdvisoryMessage)
}

// reportNormal shows minimal, assuring output
func reportNormal(data *ReportData) {
	if data.Outcome == OutcomeDryRun {
		return // Dry run already shows its own message
	}

	printNetworkPolicy(data.NetworkPolicy)
	printNetworkObservation(data)

	if data.Outcome == OutcomeError {
		// The child's own error output and PMG's exit line render elsewhere.
		// Withheld versions are the one PMG-side fact that can explain a
		// resolution failure, so surface them here.
		printCooldownWithheldHint(data.CooldownWithheldPackages)
		return
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
		printMalwareBlockSection(data)

		if len(data.CooldownBlockedPackages) > 0 {
			fmt.Println()
			n := len(data.CooldownBlockedPackages)
			fmt.Printf("%s %s\n",
				Colors.Yellow("⊘"),
				Colors.Yellow(fmt.Sprintf("Dependency cooldown — %s blocked", pluralizePackages(n))))
			printCooldownPackagesList(data.CooldownBlockedPackages)
			fmt.Println()
		}

		if data.AdvisoryMessage != "" {
			printAdvisoryMessage(data.AdvisoryMessage)
			fmt.Println()
		}

		onlyCooldown := len(data.BlockedPackages) == 0 && len(data.CooldownBlockedPackages) > 0
		if onlyCooldown {
			icon = Colors.Yellow("⊘")
			message = fmt.Sprintf("PMG: %s analyzed, %s blocked by cooldown",
				pluralizePackages(data.TotalAnalyzed), pluralizePackages(data.BlockedCount))
		} else {
			icon = Colors.Red("✗")
			message = fmt.Sprintf("PMG: %d packages analyzed, %d blocked",
				data.TotalAnalyzed, data.BlockedCount)
		}
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
	fmt.Printf("  %s %s | %s flow | paranoid: %s\n",
		Colors.Bold("Config:"),
		data.PackageManagerName,
		data.FlowType.String(),
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

	if len(data.CooldownBlockedPackages) > 0 {
		fmt.Println()
		fmt.Println(Colors.Yellow("  Blocked by dependency cooldown:"))
		for _, pkg := range data.CooldownBlockedPackages {
			dateStr := ""
			if !pkg.PublishDate.IsZero() {
				dateStr = fmt.Sprintf(" (%s)", pkg.PublishDate.Format("2006-01-02"))
			}
			fmt.Printf("    %s %s\n", Colors.Yellow("⊘"), Colors.Yellow(fmt.Sprintf("%s@%s", pkg.Name, pkg.Version)))
			fmt.Printf("      %s\n", Colors.Dim(fmt.Sprintf(
				"Published %s ago%s — cooldown: %d days, available in %s",
				pluralizeDays(pkg.DaysAgo), dateStr, pkg.CooldownDays, pluralizeDays(pkg.DaysLeft),
			)))
			fmt.Printf("      %s\n", Colors.Dim(fmt.Sprintf(
				"Tip: wait %s for cooldown to expire",
				pluralizeDays(pkg.DaysLeft),
			)))
		}
	}

	if len(data.CooldownWithheldPackages) > 0 {
		fmt.Println()
		fmt.Println(Colors.Yellow("  Versions withheld by dependency cooldown:"))
		for _, pkg := range data.CooldownWithheldPackages {
			fmt.Printf("    %s %s\n", Colors.Yellow("⊘"), Colors.Yellow(pkg.Name))
			fmt.Printf("      %s\n", Colors.Dim(termWidthFormatTextIndent(withheldVersionsLine(pkg, 0), 76, "      ")))
		}
	}

	if data.Outcome == OutcomeBlocked && data.AdvisoryMessage != "" {
		fmt.Println()
		printAdvisoryMessage(data.AdvisoryMessage)
	}

	printNetworkPolicy(data.NetworkPolicy)
	printNetworkObservation(data)

	fmt.Println()
}

func printNetworkObservation(data *ReportData) {
	if err := PrintNetworkObservation(os.Stdout, data.ObservedDestinations, data.NetworkRunID); err != nil {
		log.Warnf("failed to write the network observation: %v", err)
	}
}

// PrintNetworkObservation points at the proposal command when the run
// reached a destination and the run has an id in the event log.
func PrintNetworkObservation(w io.Writer, observed int, runID string) error {
	if observed == 0 || runID == "" {
		return nil
	}
	_, err := fmt.Fprintf(w, "\n  %s\n", Colors.Dim(fmt.Sprintf("Network: %d destination(s) observed. Propose a profile with: pmg sandbox profile propose --run %s", observed, runID)))
	return err
}

func printNetworkPolicy(report *netpolicy.Report) {
	if err := PrintNetworkPolicy(os.Stdout, report); err != nil {
		log.Warnf("failed to write the network policy report: %v", err)
	}
}

// PrintNetworkPolicy lists the destinations a deny rule matched. Under
// enforce the proxy refused them. Under audit they went through. A report
// with no denial writes nothing. One denial takes two lines, so a short
// command keeps its own output in view. The one-run override prints under
// --verbose only, because the durable fix is the one most users need.
func PrintNetworkPolicy(w io.Writer, report *netpolicy.Report) error {
	if report == nil || len(report.Denials) == 0 {
		return nil
	}

	verb := "would deny"
	if report.Enforced {
		verb = "denied"
	}

	var b strings.Builder
	b.WriteString("\n")
	if len(report.Denials) == 1 {
		fmt.Fprintf(&b, "%s %s\n", Colors.Yellow("⊘"), Colors.Yellow(fmt.Sprintf("Network policy %s %s", verb, networkDenialLine(report.Denials[0]))))
	} else {
		fmt.Fprintf(&b, "%s %s\n", Colors.Yellow("⊘"), Colors.Yellow(fmt.Sprintf("Network policy %s %d destinations:", verb, len(report.Denials))))
		for _, d := range report.Denials {
			fmt.Fprintf(&b, "    %s\n", Colors.Yellow(networkDenialLine(d)))
		}
	}
	fmt.Fprintf(&b, "  %s\n", Colors.Dim(networkDenialHelp(report)))
	_, err := io.WriteString(w, b.String())
	return err
}

func networkDenialLine(d netpolicy.Denial) string {
	line := fmt.Sprintf("%s  rule %s", d.Destination, d.Rule)
	if d.Client != "" {
		line += "  " + d.Client
	}
	if d.Count > 1 {
		line += fmt.Sprintf("  (%d)", d.Count)
	}
	return line
}

func networkDenialHelp(report *netpolicy.Report) string {
	one := len(report.Denials) == 1
	if !report.Enforced {
		if one {
			return "Set sandbox.network_mode: enforce to deny it."
		}
		return "Set sandbox.network_mode: enforce to deny them."
	}
	target := "<host>:<port>"
	if one {
		target = report.Denials[0].Destination
	}
	help := fmt.Sprintf("Allow it with pmg sandbox allow net-connect=%s.", target)
	if !one {
		help = fmt.Sprintf("Allow one with pmg sandbox allow net-connect=%s.", target)
	}
	if Verbose() {
		help += fmt.Sprintf(" For one run, pass --sandbox-allow net-connect=%s.", target)
	}
	return help
}

// cooldownWithheldHintMaxVersions bounds how many withheld versions are listed
// per package in the detailed failure hint. Packages with frequent releases can
// have many versions inside the window; the hint must stay short.
const cooldownWithheldHintMaxVersions = 3

// cooldownWithheldHintDetailMaxPackages is the package count up to which the
// failure hint lists versions per package. Above it, the hint collapses to a
// name list: a large install can withhold versions of dozens of transitive
// dependencies, and per-version detail would drown the package manager error
// the hint annotates.
const cooldownWithheldHintDetailMaxPackages = 3

// cooldownWithheldHintMaxPackageNames bounds how many package names the
// collapsed hint lists before "and N more".
const cooldownWithheldHintMaxPackageNames = 5

// printCooldownWithheldHint explains a failed install that may have been caused
// by cooldown stripping. PMG cannot know whether the resolver failed because of
// the withheld versions, so this renders as a hint, not a block report.
func printCooldownWithheldHint(packages []models.CooldownWithheld) {
	if len(packages) == 0 {
		return
	}

	fmt.Println()
	if len(packages) <= cooldownWithheldHintDetailMaxPackages {
		printCooldownWithheldDetail(packages)
	} else {
		printCooldownWithheldSummary(packages)
	}
	fmt.Println()
}

func printCooldownWithheldDetail(packages []models.CooldownWithheld) {
	total := 0
	for _, pkg := range packages {
		total += len(pkg.Versions)
	}

	fmt.Printf("%s %s\n",
		Colors.Yellow("⊘"),
		Colors.Yellow(fmt.Sprintf("Dependency cooldown withheld %s during version resolution", pluralizeVersions(total))))

	for _, pkg := range packages {
		fmt.Printf("    %s\n", Colors.Yellow(pkg.Name))
		fmt.Printf("      %s\n", Colors.Dim(withheldVersionsLine(pkg, cooldownWithheldHintMaxVersions)))
	}

	fmt.Printf("  %s\n", Colors.Dim("If the install failed because a version was not found, this is the likely cause."))
}

// withheldVersionsLine formats a package's withheld versions as one
// comma-separated line. maxVersions caps the list ("and N more" for the rest);
// 0 lists every version.
func withheldVersionsLine(pkg models.CooldownWithheld, maxVersions int) string {
	shown := pkg.Versions
	hidden := 0
	if maxVersions > 0 && len(shown) > maxVersions {
		hidden = len(shown) - maxVersions
		shown = shown[:maxVersions]
	}

	parts := make([]string, 0, len(shown)+1)
	for _, v := range shown {
		parts = append(parts, fmt.Sprintf("%s (available in %s)", v.Version, pluralizeDays(v.DaysLeft)))
	}
	if hidden > 0 {
		parts = append(parts, fmt.Sprintf("and %d more", hidden))
	}
	return strings.Join(parts, ", ")
}

func printCooldownWithheldSummary(packages []models.CooldownWithheld) {
	fmt.Printf("%s %s\n",
		Colors.Yellow("⊘"),
		Colors.Yellow(fmt.Sprintf("Dependency cooldown withheld versions of %s during resolution", pluralizePackages(len(packages)))))

	shown := packages[:min(len(packages), cooldownWithheldHintMaxPackageNames)]
	for _, pkg := range shown {
		fmt.Printf("    %s\n", Colors.Dim(pkg.Name))
	}
	if hidden := len(packages) - len(shown); hidden > 0 {
		fmt.Printf("    %s\n", Colors.Dim(fmt.Sprintf("and %d more...", hidden)))
	}
	fmt.Printf("  %s\n", Colors.Dim("If the install failed because a version was not found, this is the likely cause. Run with --verbose to list all withheld versions."))
}

func printOutcomeLine(data *ReportData) {
	switch data.Outcome {
	case OutcomeSuccess:
		fmt.Printf("  %s %s\n", Colors.Green("✓"), Colors.Green("Installation completed successfully"))
	case OutcomeBlocked:
		hasMalware := len(data.BlockedPackages) > 0
		hasCooldown := len(data.CooldownBlockedPackages) > 0
		switch {
		case hasMalware && hasCooldown:
			fmt.Printf("  %s %s\n", Colors.Red("✗"), Colors.Red("Installation blocked — malicious package detected + cooldown policy"))
		case hasCooldown:
			fmt.Printf("  %s %s\n", Colors.Yellow("⊘"), Colors.Yellow("Installation blocked — dependency cooldown policy"))
		default:
			fmt.Printf("  %s %s\n", Colors.Red("✗"), Colors.Red("Installation blocked — malicious package detected"))
		}
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
