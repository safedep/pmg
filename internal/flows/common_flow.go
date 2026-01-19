package flows

import (
	"context"
	"fmt"

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
		Block:                    ui.Block,
	}

	guardConfig := guard.DefaultPackageManagerGuardConfig()
	guardConfig.DryRun = cfg.DryRun
	guardConfig.InsecureInstallation = cfg.InsecureInstallation

	guardManager, err := guard.NewPackageManagerGuard(guardConfig, f.pm, f.packageResolver, analyzers, interaction)
	if err != nil {
		return fmt.Errorf("failed to create package manager guard: %s", err)
	}

	err = guardManager.Run(ctx, args, parsedCmd)
	if err != nil {
		return fmt.Errorf("failed to run package manager guard: %w", err)
	}

	return err
}
