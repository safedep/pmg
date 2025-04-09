package ecosystems

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"strings"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/pkg/analyser"
	"github.com/safedep/pmg/pkg/common"
	"github.com/safedep/pmg/pkg/common/utils"
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
			npmPath, err := utils.GetInterpreterPath("npm")
			if err != nil {
				return fmt.Errorf("npm not found: %w", err)
			}

			return utils.ExecCmd(npmPath, args)
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

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
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

		resp, err := analyser.SubmitPackageForAnalysis(ctx, client, packagev1.Ecosystem_ECOSYSTEM_NPM, name, version)
		if err != nil {
			log.Debugf("Failed to analyze %s@%s: %v", name, version, err)
			continue
		}

		reportResp, err := analyser.GetAnalysisReport(ctx, client, resp.GetAnalysisId())
		if err != nil {
			log.Debugf("Failed to get analysis report for %s:%s %v", name, resp.GetAnalysisId(), err)
			continue
		}

		report := reportResp.GetReport()
		if report == nil {
			log.Debugf("Empty report received for %s", name)
			continue
		}

		inference := report.GetInference()
		if inference == nil {
			log.Debugf("No inference data for %s", name)
			continue
		}

		log.Infof("Inference for %s: isMalware=%v", name, inference.GetIsMalware())

		if inference.GetIsMalware() {
			maliciousPkgs[line] = inference.GetSummary()
		}
	}

	// Get the npm PATH
	npmPath, err := utils.GetInterpreterPath("npm")
	if err != nil {
		return fmt.Errorf("npm not found: %w", err)
	}

	// Check if any malicious package exists
	if len(maliciousPkgs) > 0 {
		if !utils.ConfirmInstallation(maliciousPkgs) {
			log.Infof("Installation canceled due to security concerns")
			return nil
		}
		log.Warnf("Continuing installation despite security warnings...")
	}

	// Install the package and return
	cmdArgs := []string{action, packageName}
	if err = utils.ExecCmd(npmPath, cmdArgs); err != nil {
		return fmt.Errorf("failed to execute npm command: %w", err)
	}

	log.Infof("Successfully installed %s", packageName)
	return nil
}
