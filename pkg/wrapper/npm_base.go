package wrapper

import (
	"context"
	"errors"
	"fmt"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/fatih/color"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/pkg/analyser"
	"github.com/safedep/pmg/pkg/common/utils"
	"github.com/safedep/pmg/pkg/models"
	"github.com/safedep/pmg/pkg/registry"
	vetUtils "github.com/safedep/vet/pkg/common/utils"
)

type PackageManagerWrapper struct {
	RegistryType      registry.RegistryType
	Flags             []string
	Action            string
	PackageNames      []string
	currentPackage    string
	PackagesToInstall []string
}

func NewPackageManagerWrapper(registryType registry.RegistryType, flags []string, packageNames []string, action string) *PackageManagerWrapper {
	return &PackageManagerWrapper{
		RegistryType: registryType,
		PackageNames: packageNames,
		Flags:        flags,
		Action:       action,
	}
}

func (pmw *PackageManagerWrapper) Wrap() error {
	if len(pmw.PackageNames) == 0 {
		return fmt.Errorf("no packages specified")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// Scan all packages first
	for _, pkg := range pmw.PackageNames {
		ui.StartProgressWriter()
		var DefaultProgressTotal = 1
		pmw.currentPackage = pkg
		progressTracker := ui.TrackProgress(fmt.Sprintf("Scanning %s", pkg), DefaultProgressTotal)

		if err := pmw.scanAndInstall(ctx, progressTracker); err != nil {
			if errors.Is(err, ErrPackageInstall) {
				log.Warnf("Skipping package %s due to ErrPackageInstall: %v", pkg, err)
				continue
			}
			return err
		}
		pmw.PackagesToInstall = append(pmw.PackagesToInstall, pkg)

		ui.StopProgressWriter()
	}

	// Execute installation after all scans complete
	if err := pmw.executeInstallation(); err != nil {
		return err
	}

	log.Infof("Successfully installed all packages")
	return nil
}

func (pmw *PackageManagerWrapper) scanAndInstall(ctx context.Context, progressTracker ui.ProgressTracker) error {
	factory := registry.NewFetcherFactory(10 * time.Second)
	fetcher, err := factory.CreateFetcher(pmw.RegistryType)
	if err != nil {
		return err
	}

	name, version, err := utils.ParsePackageInfo(pmw.currentPackage)
	if err != nil {
		return err
	}

	if version == "" {
		version, err = pmw.resolveLatestVersion(ctx, fetcher, name)
		if err != nil {
			return err
		}
		pmw.currentPackage = fmt.Sprintf("%s@%s", name, version)
	}

	// Get dependencies with progress tracking
	npmFetcher := fetcher.(*registry.NpmFetcher)
	npmFetcher.SetProgressTracker(progressTracker)

	deps, err := npmFetcher.GetFlattenedDependencies(ctx, name, version)
	if err != nil {
		return err
	}

	// Set progress for analysis phase
	ui.IncrementTrackerTotal(progressTracker, int64(len(deps)))
	if err := pmw.analyzeDependencies(ctx, deps, progressTracker); err != nil {
		return err
	}

	return nil
}

func (pmw *PackageManagerWrapper) resolveLatestVersion(ctx context.Context, fetcher registry.Fetcher, name string) (string, error) {
	log.Infof("No version specified for %s, fetching latest version...", name)
	version, err := fetcher.(*registry.NpmFetcher).ResolveVersion(ctx, name, "")
	if err != nil {
		return "", err
	}
	log.Infof("Latest version of %s is %s", name, version)
	return version, nil
}

func (pmw *PackageManagerWrapper) analyzeDependencies(ctx context.Context, deps []string, progressTracker ui.ProgressTracker) error {
	client, err := analyser.GetMalwareAnalysisClient()
	if err != nil {
		return fmt.Errorf("error while creating a malware analysis client: %w", err)
	}

	pkgAnalyser := analyser.New(client, ctx, packagev1.Ecosystem_ECOSYSTEM_NPM)
	pkgAnalyser.ProgressTracker = progressTracker
	handler := pkgAnalyser.Handler()

	queue := vetUtils.NewWorkQueue[models.Package](100, 10, handler)
	queue.Start()
	defer queue.Stop()

	for _, dep := range deps {
		name, version, err := utils.ParsePackageInfo(dep)
		if err != nil {
			log.Errorf("Error while parsing info of package %s", name)
			continue
		}
		queue.Add(models.Package{
			Name:    name,
			Version: version,
		})
	}

	queue.Wait()
	ui.MarkTrackerAsDone(progressTracker)
	ui.StopProgressWriter()

	if len(pkgAnalyser.MaliciousPkgs) > 0 {
		if !utils.ConfirmInstallation(pkgAnalyser.MaliciousPkgs) {
			log.Infof("Installation canceled due to security concerns")
			return ErrPackageInstall
		}
		yellow := color.New(color.FgYellow, color.Bold).SprintfFunc()
		log.Warnf(yellow("Continuing installation despite security warnings..."))
	}

	return nil
}

func (pmw *PackageManagerWrapper) executeInstallation() error {
	execPath, err := utils.GetExecutablePath(string(pmw.RegistryType))
	if err != nil {
		return fmt.Errorf("%s not found: %w", pmw.RegistryType, err)
	}

	cmdArgs := []string{pmw.Action}
	cmdArgs = append(cmdArgs, pmw.Flags...)
	cmdArgs = append(cmdArgs, pmw.PackagesToInstall...)
	if err = utils.ExecCmd(execPath, cmdArgs, []string{}); err != nil {
		return fmt.Errorf("failed to execute %s command: %w", pmw.RegistryType, err)
	}

	return nil
}
