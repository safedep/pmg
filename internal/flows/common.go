package flows

import (
	"context"

	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/guard"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/packagemanager"
)

type commonFlow struct {
	pm              packagemanager.PackageManager
	packageResolver packagemanager.PackageResolver
	config          config.Config
}

// Creates a common flow of execution for all package managers. This should work for most
// of the cases unless a package manager has its own unique requirements. Configuration
// should be passed through the context (Global Config)
func Common(pm packagemanager.PackageManager, pkgResolver packagemanager.PackageResolver, config config.Config) *commonFlow {
	return &commonFlow{
		pm:              pm,
		packageResolver: pkgResolver,
		config:          config,
	}
}

func (f *commonFlow) Run(ctx context.Context, args []string) error {
	var analyzers []analyzer.PackageVersionAnalyzer

	if f.config.Paranoid {
		malysisActiveScanAnalyzer, err := analyzer.NewMalysisActiveScanAnalyzer(analyzer.DefaultMalysisActiveScanAnalyzerConfig())
		if err != nil {
			ui.Fatalf("Failed to create malware analyzer: %s", err)
		}

		analyzers = append(analyzers, malysisActiveScanAnalyzer)
	} else {
		malysisQueryAnalyzer, err := analyzer.NewMalysisQueryAnalyzer(analyzer.MalysisQueryAnalyzerConfig{})
		if err != nil {
			ui.Fatalf("Failed to create malware analyzer: %s", err)
		}

		analyzers = append(analyzers, malysisQueryAnalyzer)
	}

	interaction := guard.PackageManagerGuardInteraction{
		SetStatus:                ui.SetStatus,
		ClearStatus:              ui.ClearStatus,
		GetConfirmationOnMalware: ui.GetConfirmationOnMalware,
		Block:                    ui.Block,
	}

	guardConfig := guard.DefaultPackageManagerGuardConfig()
	guardConfig.DryRun = f.config.DryRun

	proxy, err := guard.NewPackageManagerGuard(guardConfig, f.pm, f.packageResolver, analyzers, interaction)
	if err != nil {
		ui.Fatalf("Failed to create package manager guard: %s", err)
	}

	err = proxy.Run(ctx, args)
	if err != nil {
		ui.Fatalf("pmg: failed to execute command: %s", err)
	}

	return err
}
