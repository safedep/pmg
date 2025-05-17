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
	// SetStatus is called to set the status of the guard in the UI
	SetStatus func(status string)

	// ClearStatus is called to clear the status of the guard in the UI
	ClearStatus func()

	// GetConfirmationOnMalware is called to get the confirmation of the user on the malware packages
	GetConfirmationOnMalware func(malwarePackages []*analyzer.PackageVersionAnalysisResult) (bool, error)

	// Block is called to block the installation of the malware packages. One or more malicious
	// packages are passed as arguments. These are the packages that were detected as malicious.
	// Client code must perform the necessary error handling and termination of the process.
	Block func(...*analyzer.PackageVersionAnalysisResult) error
}

type PackageManagerGuardConfig struct {
	ResolveDependencies   bool
	MaxConcurrentAnalyzes int
	AnalysisTimeout       time.Duration
	DryRun                bool
}

func DefaultPackageManagerGuardConfig() PackageManagerGuardConfig {
	return PackageManagerGuardConfig{
		ResolveDependencies:   true,
		MaxConcurrentAnalyzes: 10,
		AnalysisTimeout:       5 * time.Minute,
		DryRun:                false,
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
			return g.blockInstallation(result)
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
			return g.blockInstallation(confirmableMalwarePackages...)
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

	if g.config.DryRun {
		log.Debugf("Dry run, skipping command execution")
		return nil
	}

	cmd := exec.CommandContext(ctx, pc.Command.Exe, pc.Command.Args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// We will fail based on executed command's exit code. This is important
	// because other tools (scripts, CI etc.) may depend on this exit code.
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

	// Queue all packages for analysis
	for _, pkg := range packages {
		jobs <- pkg
	}
	close(jobs)

	analysisResults := []*analyzer.PackageVersionAnalysisResult{}

	// We must wait for the results go routine to collect all results
	rwg := sync.WaitGroup{}
	rwg.Add(1)
	go func() {
		defer rwg.Done()
		for result := range results {
			analysisResults = append(analysisResults, result)
		}
	}()

	waiter := make(chan struct{})
	go func() {
		wg.Wait()
		close(results)

		rwg.Wait()
		close(waiter)
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

func (g *packageManagerGuard) blockInstallation(malwarePackages ...*analyzer.PackageVersionAnalysisResult) error {
	if g.interaction.Block == nil {
		return nil
	}

	return g.interaction.Block(malwarePackages...)
}

func (g *packageManagerGuard) clearStatus() {
	if g.interaction.ClearStatus == nil {
		return
	}

	g.interaction.ClearStatus()
}
