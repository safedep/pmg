package ecosystems

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/pkg/analyser"
	"github.com/safedep/pmg/pkg/common"
	"github.com/safedep/pmg/pkg/common/utils"
	"github.com/safedep/pmg/pkg/models"
	vetUtils "github.com/safedep/vet/pkg/common/utils"
	"github.com/spf13/cobra"
)

var (
	packageName string
	action      string
)

//go:embed tree/arborist-bundle.js
var arboristJs string

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
					return err
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
	return cmd
}

func wrapNpm() error {
	if packageName == "" {
		return fmt.Errorf("package name cannot be empty")
	}

	// Setup context with timeout for API calls
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// Extract package information
	outputFile, err := common.RunPkgExtractor(common.ExtractorOptions{
		PackageName:   packageName,
		ScriptContent: arboristJs,
		Interpreter:   "node",
		ScriptType:    "js",
		Args:          []string{},
		Env: map[string]string{
			"NPM_AUTH_TOKEN": utils.NpmAuthToken(),
		},
	})

	if err != nil {
		return fmt.Errorf("failed to extract package info: %w", err)
	}
	// Clean up the temporary file when done
	defer os.Remove(outputFile)

	data, err := os.ReadFile(outputFile)
	if err != nil {
		return fmt.Errorf("error while reading package output file: %w", err)
	}

	maliciousPkgs := make(map[string]string)

	client, err := analyser.GetMalwareAnalysisClient()
	if err != nil {
		return fmt.Errorf("error while creating a malware analysis client: %w", err)
	}

	handler := analyser.AnalysePackage(maliciousPkgs, client, ctx)

	// Create work queue with appropriate buffer size and concurrency
	queue := vetUtils.NewWorkQueue[models.PackageAnalysisItem](100, 10, handler)
	queue.Start()
	defer queue.Stop()

	// Add packages to the queue
	lines := strings.SplitSeq(string(data), "\n")
	for line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "@") {
			continue
		}

		idx := strings.LastIndex(line, "@")
		if idx <= 0 {
			log.Debugf("Invalid package line: %s", line)
			continue
		}

		name := line[:idx]
		version := line[idx+1:]

		queue.Add(models.PackageAnalysisItem{
			Name:    name,
			Version: version,
		})
	}

	// Wait for all analysis to complete
	queue.Wait()

	// Get the npm PATH and continue with installation
	npmPath, err := utils.GetExecutablePath("npm")
	if err != nil {
		return fmt.Errorf("npm not found: %w", err)
	}

	if len(maliciousPkgs) > 0 {
		if !utils.ConfirmInstallation(maliciousPkgs) {
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
