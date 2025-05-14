package guard

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/packagemanager"
)

type PackageManagerGuardInteraction struct {
	SetStatus                func(status string)
	ClearStatus              func()
	GetConfirmationOnMalware func(malwarePackages []*analyzer.PackageVersionAnalysisResult) (bool, error)
	Block                    func() error
}

type PackageManagerGuardConfig struct {
	ResolveDependencies   bool
	MaxConcurrentAnalyzes int
	AnalysisTimeout       time.Duration
}

func DefaultPackageManagerGuardConfig() PackageManagerGuardConfig {
	return PackageManagerGuardConfig{
		ResolveDependencies:   true,
		MaxConcurrentAnalyzes: 10,
		AnalysisTimeout:       5 * time.Minute,
	}
}

type packageManagerGuard struct {
	config          PackageManagerGuardConfig
	interaction     PackageManagerGuardInteraction
	analyzers       []analyzer.PackageVersionAnalyzer
	packageManager  packagemanager.PackageManager
	packageResolver packagemanager.PackageResolver
}

func NewPackageManagerGuard(config PackageManagerGuardConfig,
	packageManager packagemanager.PackageManager,
	packageResolver packagemanager.PackageResolver,
	analyzers []analyzer.PackageVersionAnalyzer,
	interaction PackageManagerGuardInteraction,
) (*packageManagerGuard, error) {
	return &packageManagerGuard{
		interaction:     interaction,
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

	// TODO: We should track the dependency tree here so that we can trace a
	// dependency to one of the parent packages from install targets

	packagesToAnalyze := []*packagev1.PackageVersion{}
	for _, installTarget := range parsedCommand.InstallTargets {
		packagesToAnalyze = append(packagesToAnalyze, installTarget.PackageVersion)
	}

	log.Debugf("Found %d install targets", len(parsedCommand.InstallTargets))

	g.setStatus(fmt.Sprintf("Resolving dependencies for %d packages", len(parsedCommand.InstallTargets)))

	if g.config.ResolveDependencies {
		for _, pkg := range parsedCommand.InstallTargets {
			if pkg.PackageVersion.GetVersion() == "" {
				log.Debugf("Resolving latest version for package: %s", pkg.PackageVersion.Package.Name)
				latestVersion, err := g.packageResolver.ResolveLatestVersion(ctx, pkg.PackageVersion.GetPackage())
				if err != nil {
					return fmt.Errorf("failed to resolve latest version: %w", err)
				}

				pkg.PackageVersion.Version = latestVersion.GetVersion()
			}

			log.Debugf("Resolving dependencies for package: %s@%s", pkg.PackageVersion.Package.Name, pkg.PackageVersion.Version)

			dependencies, err := g.packageResolver.ResolveDependencies(ctx, pkg.PackageVersion)
			if err != nil {
				return fmt.Errorf("failed to resolve dependencies: %w", err)
			}

			log.Debugf("Resolved %d dependencies for package: %s@%s", len(dependencies),
				pkg.PackageVersion.Package.Name, pkg.PackageVersion.Version)

			packagesToAnalyze = append(packagesToAnalyze, dependencies...)
		}
	}

	log.Debugf("Checking %d packages for malware", len(packagesToAnalyze))

	g.setStatus(fmt.Sprintf("Analyzing %d packages for malware", len(packagesToAnalyze)))

	analysisResults, err := g.concurrentAnalyzePackages(ctx, packagesToAnalyze)
	if err != nil {
		return fmt.Errorf("failed to analyze packages: %w", err)
	}

	confirmableMalwarePackages := []*analyzer.PackageVersionAnalysisResult{}
	for _, result := range analysisResults {
		if result.Action == analyzer.ActionBlock {
			_ = g.blockInstallation()
			return fmt.Errorf("malicious packages detected, installation aborted")
		}

		if result.Action == analyzer.ActionConfirm {
			confirmableMalwarePackages = append(confirmableMalwarePackages, result)
		}
	}

	if len(confirmableMalwarePackages) > 0 {
		confirmed, err := g.getConfirmationOnMalware(ctx, confirmableMalwarePackages)
		if err != nil {
			return fmt.Errorf("failed to get confirmation on malware: %w", err)
		}

		if !confirmed {
			_ = g.blockInstallation()
			return fmt.Errorf("malicious packages detected, installation aborted")
		}
	}

	log.Debugf("No malicious packages found, continuing execution")

	g.clearStatus()
	return g.continueExecution(ctx, parsedCommand)
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

func (g *packageManagerGuard) concurrentAnalyzePackages(ctx context.Context,
	packages []*packagev1.PackageVersion) ([]*analyzer.PackageVersionAnalysisResult, error) {

	ctx, cancel := context.WithTimeout(ctx, g.config.AnalysisTimeout)
	defer cancel()

	wg := sync.WaitGroup{}
	jobs := make(chan *packagev1.PackageVersion, len(packages))
	results := make(chan *analyzer.PackageVersionAnalysisResult, len(packages))

	for i := 0; i < g.config.MaxConcurrentAnalyzes; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pkg := range jobs {
				for _, analyzer := range g.analyzers {
					analysisResult, err := analyzer.Analyze(ctx, pkg)
					if err != nil {
						// This is not an error because we may not have results for all packages
						log.Debugf("failed to analyze package: %v", err)
						continue
					}

					results <- analysisResult
				}
			}
		}()
	}

	for _, pkg := range packages {
		jobs <- pkg
	}
	close(jobs)

	analysisResults := []*analyzer.PackageVersionAnalysisResult{}
	go func() {
		for result := range results {
			analysisResults = append(analysisResults, result)
		}
	}()

	waiter := make(chan struct{})
	go func() {
		wg.Wait()
		close(waiter)
		close(results)
	}()

	select {
	case <-waiter:
	case <-ctx.Done():
		return nil, fmt.Errorf("analysis timed out")
	}

	return analysisResults, nil
}

func (g *packageManagerGuard) getConfirmationOnMalware(ctx context.Context, malwarePackages []*analyzer.PackageVersionAnalysisResult) (bool, error) {
	if g.interaction.GetConfirmationOnMalware == nil {
		return false, nil
	}

	return g.interaction.GetConfirmationOnMalware(malwarePackages)
}

func (g *packageManagerGuard) setStatus(status string) {
	if g.interaction.SetStatus == nil {
		return
	}

	g.interaction.SetStatus(status)
}

func (g *packageManagerGuard) blockInstallation() error {
	if g.interaction.Block == nil {
		return nil
	}

	return g.interaction.Block()
}

func (g *packageManagerGuard) clearStatus() {
	if g.interaction.ClearStatus == nil {
		return
	}

	g.interaction.ClearStatus()
}
