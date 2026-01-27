package flows

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/guard"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/packagemanager"
)

type commonFlow struct {
	pm              packagemanager.PackageManager
	packageResolver packagemanager.PackageResolver
}

// Creates a common flow of execution for all package managers. This should work for most
// of the cases unless a package manager has its own unique requirements. Configuration
// should be passed through the context (Global Config)
func Common(pm packagemanager.PackageManager, pkgResolver packagemanager.PackageResolver) *commonFlow {
	return &commonFlow{
		pm:              pm,
		packageResolver: pkgResolver,
	}
}

func (f *commonFlow) Run(ctx context.Context, args []string, parsedCmd *packagemanager.ParsedCommand) error {
	var analyzers []analyzer.PackageVersionAnalyzer

	// Configure sandbox based on command type and enforcement policy
	config.ConfigureSandbox(parsedCmd.IsInstallationCommand())

	cfg := config.Get()

	// Initialize report data at the start
	reportData := ui.NewReportData()
	reportData.PackageManagerName = f.pm.Name()
	reportData.FlowType = ui.FlowTypeGuard
	reportData.DryRun = cfg.DryRun
	reportData.InsecureMode = cfg.InsecureInstallation
	reportData.TransitiveEnabled = cfg.Config.Transitive
	reportData.ParanoidMode = cfg.Config.Paranoid
	reportData.SandboxEnabled = cfg.Config.Sandbox.Enabled

	if cfg.Config.Sandbox.Enabled {
		if policyRef, exists := cfg.Config.Sandbox.Policies[f.pm.Name()]; exists {
			reportData.SandboxProfile = policyRef.Profile
		}
	}
	if cfg.SandboxProfileOverride != "" {
		reportData.SandboxProfile = cfg.SandboxProfileOverride
	}

	startTime := time.Now()

	if cfg.Config.Paranoid {
		malysisActiveScanAnalyzer, err := analyzer.NewMalysisActiveScanAnalyzer(analyzer.DefaultMalysisActiveScanAnalyzerConfig())
		if err != nil {
			return fmt.Errorf("failed to create malware analyzer: %s", err)
		}

		analyzers = append(analyzers, malysisActiveScanAnalyzer)
	} else {
		malysisQueryAnalyzer, err := analyzer.NewMalysisQueryAnalyzer(analyzer.MalysisQueryAnalyzerConfig{})
		if err != nil {
			return fmt.Errorf("failed to create malware analyzer: %s", err)
		}

		analyzers = append(analyzers, malysisQueryAnalyzer)
	}

	interaction := guard.PackageManagerGuardInteraction{
		SetStatus:                ui.SetStatus,
		ClearStatus:              ui.ClearStatus,
		ShowWarning:              ui.ShowWarning,
		GetConfirmationOnMalware: ui.GetConfirmationOnMalware,
		Block:                    ui.BlockNoExit,
	}

	guardConfig := guard.DefaultPackageManagerGuardConfig()
	guardConfig.DryRun = cfg.DryRun
	guardConfig.InsecureInstallation = cfg.InsecureInstallation

	guardManager, err := guard.NewPackageManagerGuard(guardConfig, f.pm, f.packageResolver, analyzers, interaction)
	if err != nil {
		return fmt.Errorf("failed to create package manager guard: %s", err)
	}

	guardResult, err := guardManager.Run(ctx, args, parsedCmd)

	// Populate report data from guard result
	reportData.StartTime = startTime
	if guardResult != nil {
		reportData.TotalAnalyzed = guardResult.TotalAnalyzed
		reportData.TrustedSkipped = guardResult.TrustedSkipped
		reportData.AllowedCount = guardResult.AllowedCount
		reportData.ConfirmedCount = guardResult.ConfirmedCount
		reportData.BlockedCount = guardResult.BlockedCount
		reportData.BlockedPackages = guardResult.BlockedPackages
		reportData.ConfirmedPackages = guardResult.ConfirmedPackages
	}

	// Infer outcome from data and config using shared inference logic
	blockedCount := 0
	userCancelledCount := 0

	if guardResult != nil {
		blockedCount = guardResult.BlockedCount
		// In guard flow, if user cancelled, all blocked packages are due to user cancellation
		// (guard returns immediately on ActionBlock, so we can't have both types)
		if guardResult.WasUserCancelled {
			userCancelledCount = guardResult.BlockedCount
		}
	}

	reportData.Outcome = inferOutcome(cfg.InsecureInstallation, cfg.DryRun, blockedCount, userCancelledCount, err)

	// Show the report
	ui.Report(reportData)

	// Exit after report for blocked/cancelled outcomes
	if reportData.Outcome == ui.OutcomeBlocked || reportData.Outcome == ui.OutcomeUserCancelled {
		os.Exit(1)
	}

	if err != nil {
		return fmt.Errorf("failed to run package manager guard: %w", err)
	}

	return nil
}
