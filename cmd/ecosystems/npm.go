package ecosystems

import (
	_ "embed"
	"fmt"
	"os"
	"strings"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/pkg/analyser"
	"github.com/safedep/pmg/pkg/common"
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
		Use:   "npm",
		Short: "Scan packages from npm registry",
		RunE: func(cmd *cobra.Command, args []string) error {
			action = args[0]
			packageName = args[1]
			if action == "install" {
				err := wrapNpm()
				if err != nil {
					// TODO
					log.Fatalf("wrapNpm: ", err.Error())
				}
			}
			return nil
		},
	}
	return cmd
}

func wrapNpm() error {
	outputFile, err := common.RunPkgExtractor(common.ExtractorOptions{
		PackageName:   packageName,
		ScriptContent: arboristJs,
		Interpreter:   "node",
		ScriptType:    "js",
		Args:          []string{},
	})
	if err != nil {
		return err
	}

	data, err := os.ReadFile(outputFile)
	if err != nil {
		return fmt.Errorf("Error while reading package output file: %s", err.Error())
	}

	lines := strings.SplitSeq(string(data), "\n")
	for line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "@") {
			continue
		}

		parts := strings.SplitN(line, "@", 2)
		if len(parts) != 2 {
			log.Debugf("Invalid package line:", line)
			continue
		}

		name := parts[0]
		version := parts[1]

		client, err := analyser.GetMalwareAnalysisClient()
		if err != nil {
			return fmt.Errorf("Error while creating a malware analysis client: %s", err.Error())
		}

		resp, err := analyser.SubmitPackageForAnalysis(client, packagev1.Ecosystem_ECOSYSTEM_NPM, name, version)
		if err != nil {
			log.Debugf("Failed to analyze %s@%s: %v\n", name, version, err)
			continue
		}
		log.Debugf("Submitted %s@%s | Analysis ID: %s\n", name, version, resp.GetAnalysisId())

		reportResp, err := analyser.GetAnalysisReport(client, resp.GetAnalysisId())
		if err != nil {
			log.Debugf("Failed to get analysis report for %s:%s %v\n", name, resp.GetAnalysisId(), err)
			continue
		}

		_ = reportResp.GetReport()
	}

	// TODO:
	// Get the npm PATH
	// Check if any vulnerable package exists?
	// If yes - Confirm with user to continue or not
	// If no - Install the pkg & return
	// If continue - Install the pkg
	return nil
}
