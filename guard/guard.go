package guard

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"sync"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/extractor"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/packagemanager"
)

type PackageManagerGuardInteraction struct {
	// SetStatus is called to set the status of the guard in the UI
	SetStatus func(status string)

	// ClearStatus is called to clear the status of the guard in the UI
	ClearStatus func()

	// ShowWarning is called to show a warning message to the user
	ShowWarning func(message string)

	// GetConfirmationOnMalware is called to get the confirmation of the user on the malware packages
	GetConfirmationOnMalware func(malwarePackages []*analyzer.PackageVersionAnalysisResult) (bool, error)

	// Block is called to block the installation of the malware packages. One or more malicious
	// packages are passed as arguments. These are the packages that were detected as malicious.
	// Client code must perform the necessary error handling and termination of the process.
	Block func(config *ui.BlockConfig) error
}

type PackageManagerGuardConfig struct {
	ResolveDependencies   bool
	MaxConcurrentAnalyzes int
	AnalysisTimeout       time.Duration
	DryRun                bool
	InsecureInstallation  bool
}

func DefaultPackageManagerGuardConfig() PackageManagerGuardConfig {
	return PackageManagerGuardConfig{
		ResolveDependencies:   true,
		MaxConcurrentAnalyzes: 10,
		AnalysisTimeout:       5 * time.Minute,
		DryRun:                false,
		InsecureInstallation:  false,
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

func (g *packageManagerGuard) Run(ctx context.Context, args []string, parsedCommand *packagemanager.ParsedCommand) error {
	log.Debugf("Running package manager guard with args: %v", args)

	if g.config.InsecureInstallation {
		log.Debugf("Bypassing block for unconfirmed malicious packages due to PMG_INSECURE_INSTALLATION")
		g.showWarning("⚠️  WARNING: INSECURE INSTALLATION MODE - Malware protection bypassed!")
		return g.continueExecution(ctx, parsedCommand)
	}

	if !parsedCommand.HasInstallTarget() {
		// Check if this is a manifest-based installation
		if parsedCommand.ShouldExtractFromManifest() {
			log.Debugf("Detected manifest-based installation, extracting packages from manifest files")
			return g.handleManifestInstallation(ctx, parsedCommand)
		}

		log.Debugf("No install target found, continuing execution")
		return g.continueExecution(ctx, parsedCommand)
	}

	blockConfig := ui.NewDefaultBlockConfig()

	// TODO: We should track the dependency tree here so that we can trace a
	// dependency to one of the parent packages from install targets

	packagesToAnalyze := []*packagev1.PackageVersion{}
	for _, installTarget := range parsedCommand.InstallTargets {
		packagesToAnalyze = append(packagesToAnalyze, installTarget.PackageVersion)
	}

	log.Debugf("Found %d install targets", len(parsedCommand.InstallTargets))

	g.setStatus(fmt.Sprintf("Resolving dependencies for %d package(s)", len(parsedCommand.InstallTargets)))

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

	g.setStatus(fmt.Sprintf("Analyzing %d dependencies for malware", len(packagesToAnalyze)))

	analysisResults, err := g.concurrentAnalyzePackages(ctx, packagesToAnalyze)
	if err != nil {
		return fmt.Errorf("failed to analyze packages: %w", err)
	}

	confirmableMalwarePackages := []*analyzer.PackageVersionAnalysisResult{}
	for _, result := range analysisResults {
		if result.Action == analyzer.ActionBlock {
			blockConfig.MalwarePackages = append(blockConfig.MalwarePackages, result)
			return g.blockInstallation(blockConfig)
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
			blockConfig.ShowReference = false
			blockConfig.MalwarePackages = confirmableMalwarePackages
			return g.blockInstallation(blockConfig)
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

func (g *packageManagerGuard) blockInstallation(config *ui.BlockConfig) error {
	if g.interaction.Block == nil {
		return nil
	}

	return g.interaction.Block(config)
}

func (g *packageManagerGuard) clearStatus() {
	if g.interaction.ClearStatus == nil {
		return
	}

	g.interaction.ClearStatus()
}

func (g *packageManagerGuard) showWarning(message string) {
	if g.interaction.ShowWarning == nil {
		return
	}

	g.interaction.ShowWarning(message)
}

func (g *packageManagerGuard) handleManifestInstallation(ctx context.Context, parsedCommand *packagemanager.ParsedCommand) error {
	extractorConfig := extractor.NewDefaultExtractorConfig()
	extractorConfig.ExtractorPackageManager = extractor.PackageManagerName(g.packageManager.Name())
	extractorConfig.ManifestFiles = parsedCommand.ManifestFiles

	packageExtractor := extractor.New(*extractorConfig)

	packages, err := packageExtractor.ExtractManifest()
	if err != nil {
		return fmt.Errorf("failed to extract packages from manifest files: %w", err)
	}

	blockConfig := ui.NewDefaultBlockConfig()

	if len(packages) == 0 {
		log.Debugf("No packages found in manifest files, continuing execution")
		return g.continueExecution(ctx, parsedCommand)
	}

	log.Debugf("Extracted %d packages from manifest files", len(packages))

	packagesToAnalyze := []*packagev1.PackageVersion{}
	for _, pkg := range packages {
		packagesToAnalyze = append(packagesToAnalyze, pkg)
	}

	// Only resolve dependencies for requirements.txt because other lockfiles dependencies are already resolved
	if g.config.ResolveDependencies && slices.Contains(parsedCommand.ManifestFiles, "requirements.txt") {

		g.setStatus(fmt.Sprintf("Resolving dependencies for %d package(s)", len(packages)))

		for _, pkg := range packages {
			if pkg.GetVersion() == "" {
				log.Debugf("Resolving latest version for package: %s", pkg.Package.Name)
				latestVersion, err := g.packageResolver.ResolveLatestVersion(ctx, pkg.GetPackage())
				if err != nil {
					return fmt.Errorf("failed to resolve latest version: %w", err)
				}

				pkg.Version = latestVersion.GetVersion()
			}

			log.Debugf("Resolving dependencies for package: %s@%s", pkg.Package.Name, pkg.Version)

			dependencies, err := g.packageResolver.ResolveDependencies(ctx, pkg)
			if err != nil {
				return fmt.Errorf("failed to resolve dependencies: %w", err)
			}

			log.Debugf("Resolved %d dependencies for package: %s@%s", len(dependencies),
				pkg.Package.Name, pkg.Version)

			packagesToAnalyze = append(packagesToAnalyze, dependencies...)
		}
	}

	log.Debugf("Checking %d packages for malware", len(packagesToAnalyze))

	g.setStatus(fmt.Sprintf("Analyzing %d dependencies from manifest files", len(packagesToAnalyze)))

	analysisResults, err := g.concurrentAnalyzePackages(ctx, packagesToAnalyze)
	if err != nil {
		return fmt.Errorf("failed to analyze packages: %w", err)
	}

	confirmableMalwarePackages := []*analyzer.PackageVersionAnalysisResult{}
	for _, result := range analysisResults {
		if result.Action == analyzer.ActionBlock {
			blockConfig.MalwarePackages = append(blockConfig.MalwarePackages, result)
			return g.blockInstallation(blockConfig)
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
			blockConfig.ShowReference = false
			blockConfig.MalwarePackages = confirmableMalwarePackages
			return g.blockInstallation(blockConfig)
		}
	}

	log.Debugf("No malicious packages found in manifest files, continuing execution")

	g.clearStatus()
	return g.continueExecution(ctx, parsedCommand)
}
