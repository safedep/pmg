package guard

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/packagemanager"
)

type PackageManagerGuardConfig struct{}

type packageManagerGuard struct {
	config          PackageManagerGuardConfig
	analyzers       []analyzer.Analyzer
	packageManager  packagemanager.PackageManager
	packageResolver packagemanager.PackageResolver
}

func NewPackageManagerGuard(config PackageManagerGuardConfig,
	packageManager packagemanager.PackageManager,
	packageResolver packagemanager.PackageResolver,
	analyzers []analyzer.Analyzer) (*packageManagerGuard, error) {
	return &packageManagerGuard{
		analyzers:       analyzers,
		packageManager:  packageManager,
		packageResolver: packageResolver,
		config:          config,
	}, nil
}

func (g *packageManagerGuard) Run(ctx context.Context, args []string) error {
	log.Debugf("Running package manager guard with args: %v", args)

	parsedCommand, err := g.packageManager.ParseCommand(args)
	if err != nil {
		return fmt.Errorf("failed to parse command: %w", err)
	}

	if !parsedCommand.HasInstallTarget() {
		log.Debugf("No install target found, continuing execution")
		return g.continueExecution(ctx, parsedCommand)
	}

	log.Debugf("Install targets: %v", parsedCommand.InstallTargets)

	return nil
}

func (g *packageManagerGuard) continueExecution(ctx context.Context, pc *packagemanager.ParsedCommand) error {
	if len(pc.Command.Exe) == 0 {
		return fmt.Errorf("no command to execute")
	}

	cmd := exec.CommandContext(ctx, pc.Command.Exe, pc.Command.Args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}
