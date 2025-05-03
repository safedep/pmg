package wrapper

import (
	"context"
	"fmt"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/pkg/analyser"
	"github.com/safedep/pmg/pkg/common/utils"
	"github.com/safedep/pmg/pkg/models"
	"github.com/safedep/pmg/pkg/registry"
	vetUtils "github.com/safedep/vet/pkg/common/utils"
)

type PackageManagerWrapper struct {
	RegistryType registry.RegistryType
	Action       string
	PackageName  string
}

func NewPackageManagerWrapper(registryType registry.RegistryType) *PackageManagerWrapper {
	return &PackageManagerWrapper{
		RegistryType: registryType,
	}
}

func (pmw *PackageManagerWrapper) Wrap() error {
	ui.StartProgressWriter()

	progressTracker := ui.TrackProgress(fmt.Sprintf("Scanning %s ", pmw.PackageName), 5)
	if pmw.PackageName == "" {
		return fmt.Errorf("package name cannot be empty")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	if err := pmw.scanAndInstall(ctx, progressTracker); err != nil {
		return err
	}

	log.Infof("Successfully installed %s", pmw.PackageName)
	return nil
}

func (pmw *PackageManagerWrapper) scanAndInstall(ctx context.Context, progressTracker ui.ProgressTracker) error {
	factory := registry.NewFetcherFactory(10 * time.Second)
	fetcher, err := factory.CreateFetcher(pmw.RegistryType)
	if err != nil {
		return err
	}

	name, version, err := utils.ParsePackageInfo(pmw.PackageName)
	if err != nil {
		return err
	}

	if version == "" {
		version, err = pmw.resolveLatestVersion(ctx, fetcher, name)
		if err != nil {
			return err
		}
		pmw.PackageName = fmt.Sprintf("%s@%s", name, version)
	}

	// Get dependencies with progress tracking
	npmFetcher, ok := fetcher.(*registry.NpmFetcher)
	if !ok {
		return fmt.Errorf("fetcher is not of type *registry.NpmFetcher")
	}
	ui.IncrementTrackerTotal(progressTracker, 0)
	npmFetcher.SetProgressTracker(progressTracker)

	deps, err := npmFetcher.GetFlattenedDependencies(ctx, name, version)
	if err != nil {
		return err
	}

	// We know the total deps, set progress for analysis phase
	ui.IncrementTrackerTotal(progressTracker, int64(len(deps)))
	if err := pmw.analyzeDependencies(ctx, deps, progressTracker); err != nil {
		return err
	}

	return pmw.executeInstallation()
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

	pkgAnalyser := analyser.New(client, ctx)
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
			return fmt.Errorf("installation canceled")
		}
		log.Warnf("Continuing installation despite security warnings...")
	}

	return nil
}

func (pmw *PackageManagerWrapper) executeInstallation() error {
	execPath, err := utils.GetExecutablePath(string(pmw.RegistryType))
	if err != nil {
		return fmt.Errorf("%s not found: %w", pmw.RegistryType, err)
	}

	cmdArgs := []string{pmw.Action, pmw.PackageName}
	if err = utils.ExecCmd(execPath, cmdArgs, []string{}); err != nil {
		return fmt.Errorf("failed to execute %s command: %w", pmw.RegistryType, err)
	}

	return nil
}
