package flows

import (
	"context"
	"fmt"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/guard"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/packagemanager"
)

type commonFlow struct {
	pm              packagemanager.PackageManager
	packageResolver packagemanager.PackageResolver
	hooks           []Hook
}

// Creates a common flow of execution for all package managers. This should work for most
// of the cases unless a package manager has its own unique requirements. Configuration
// should be passed through the context (Global Config)
func Common(pm packagemanager.PackageManager, pkgResolver packagemanager.PackageResolver, hooks []Hook) *commonFlow {
	return &commonFlow{
		pm:              pm,
		packageResolver: pkgResolver,
		hooks:           hooks,
	}
}

func (f *commonFlow) Run(ctx context.Context, args []string, parsedCmd *packagemanager.ParsedCommand) error {
	var analyzers []analyzer.PackageVersionAnalyzer

	for _, h := range f.hooks {
		if h == nil {
			continue
		}

		newCtx, err := h.BeforeFlow(ctx, parsedCmd)
		if err != nil {
			log.Errorf(
				"Error before flow hook for command %s: %v",
				parsedCmd.Command.Exe,
				err,
			)
		}

		if newCtx != nil {
			ctx = newCtx
		}
	}

	config := config.Get()

	if config.Config.Paranoid {
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
	guardConfig.DryRun = config.DryRun
	guardConfig.InsecureInstallation = config.InsecureInstallation

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
