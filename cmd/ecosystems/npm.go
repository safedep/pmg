package ecosystems

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/pkg/analyser"
	"github.com/safedep/pmg/pkg/common/utils"
	"github.com/safedep/pmg/pkg/models"
	"github.com/safedep/pmg/pkg/registry"
	vetUtils "github.com/safedep/vet/pkg/common/utils"
	"github.com/spf13/cobra"
)

var (
	packageName string
	action      string
	silentScan  bool
)

func NewNpmCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "npm [action] [package]",
		Short: "Scan packages from npm registry",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			action = args[0]
			packageName = args[1]

			validActions := map[string]bool{"install": true, "i": true, "add": true}
			if validActions[action] {
				err := wrapNpm()
				if err != nil {
					log.Errorf("Failed to wrap npm: %v", err)
					os.Exit(1)
				}
				return nil
			}

			// For non-install actions, just pass through to npm
			npmPath, err := utils.GetExecutablePath("npm")
			if err != nil {
				return fmt.Errorf("npm not found: %w", err)
			}

			return utils.ExecCmd(npmPath, args, []string{})
		},
	}
	cmd.Flags().BoolVarP(&silentScan, "silent", "s", false,
		"Silent scan to prevent rendering UI")
	return cmd
}

func wrapNpm() error {
	if !silentScan {
		ui.StartProgressWriter()
	}
	var progressTracker ui.ProgressTracker

	progressTracker = ui.TrackProgress(fmt.Sprintf("Scanning %s ", packageName), 1)
	if packageName == "" {
		return fmt.Errorf("package name cannot be empty")
	}

	// Setup context with timeout for API calls
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	factory := registry.NewFetcherFactory(10 * time.Second)

	// Get an NPM fetcher
	npmFetcher, err := factory.CreateFetcher(registry.RegistryNPM)
	if err != nil {
		return err
	}
	name, version, err := utils.ParsePackageInfo(packageName)

	// If version is empty, get the latest version
	if version == "" {
		log.Infof("No version specified for %s, fetching latest version...", name)
		version, err = npmFetcher.(*registry.NpmFetcher).ResolveVersion(ctx, name, version)
		if err != nil {
			return err
		}
		log.Infof("Latest version of %s is %s", name, version)
		// Update packageName with resolved version for npm installation
		packageName = fmt.Sprintf("%s@%s", name, version)
	}
	ui.IncrementProgress(progressTracker, 1)

	deps, err := npmFetcher.GetFlattenedDependencies(ctx, name, version)
	ui.IncrementProgress(progressTracker, 1)
	if err != nil {
		return err
	}
	ui.IncrementTrackerTotal(progressTracker, int64(len(deps)))
	client, err := analyser.GetMalwareAnalysisClient()
	if err != nil {
		return fmt.Errorf("error while creating a malware analysis client: %w", err)
	}
	pkgAnalyser := analyser.New(client, ctx)

	pkgAnalyser.ProgressTracker = progressTracker
	handler := pkgAnalyser.Handler()

	// Create work queue with appropriate buffer size and concurrency
	queue := vetUtils.NewWorkQueue[models.Package](100, 10, handler)
	queue.Start()
	defer queue.Stop()

	// Add packages to the queue
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

	// Wait for all analysis to complete
	queue.Wait()
	ui.MarkTrackerAsDone(progressTracker)
	ui.StopProgressWriter()

	// Get the npm PATH and continue with installation
	npmPath, err := utils.GetExecutablePath("npm")
	if err != nil {
		return fmt.Errorf("npm not found: %w", err)
	}

	if len(pkgAnalyser.MaliciousPkgs) > 0 {
		if !utils.ConfirmInstallation(pkgAnalyser.MaliciousPkgs) {
			log.Infof("Installation canceled due to security concerns")
			return nil
		}
		log.Warnf("Continuing installation despite security warnings...")
	}

	cmdArgs := []string{action, packageName}
	if err = utils.ExecCmd(npmPath, cmdArgs, []string{}); err != nil {
		return fmt.Errorf("failed to execute npm command: %w", err)
	}

	log.Infof("Successfully installed %s", packageName)
	return nil
}
