package ecosystems

import (
	"context"
	_ "embed"
	"fmt"
	"net/http"
	"os"
	"strings"

	"buf.build/gen/go/safedep/api/grpc/go/safedep/services/malysis/v1/malysisv1grpc"
	malysisv1pb "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/malysis/v1"
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	malysisv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/malysis/v1"
	drygrpc "github.com/safedep/dry/adapters/grpc"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/pkg/common"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
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

		tok := os.Getenv("SAFEDEP_API_KEY")
		tenantId := os.Getenv("SAFEDEP_TENANT_ID")

		if tok == "" || tenantId == "" {
			return fmt.Errorf("SAFEDEP_API_KEY and SAFEDEP_TENANT_ID must be set")
		}

		headers := http.Header{}
		headers.Set("x-tenant-id", tenantId)
		cc, err := drygrpc.GrpcClient("pmg-pkg-scan", "api.safedep.io", "443",
			tok, headers, []grpc.DialOption{})
		client := malysisv1grpc.NewMalwareAnalysisServiceClient(cc)

		req := &malysisv1.AnalyzePackageRequest{
			Target: &malysisv1pb.PackageAnalysisTarget{
				PackageVersion: &packagev1.PackageVersion{
					Package: &packagev1.Package{
						Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
						Name:      name,
					},
					Version: version,
				},
			},
		}

		resp, err := client.AnalyzePackage(context.Background(), req)
		if err != nil {
			log.Debugf("Failed to analyze %s@%s: %v\n", name, version, err)
			continue
		}
		log.Debugf("Submitted %s@%s | Analysis ID: %s\n", name, version, resp.GetAnalysisId())

		analysisReportReq := &malysisv1.GetAnalysisReportRequest{
			AnalysisId: resp.GetAnalysisId(),
		}

		reportResp, err := client.GetAnalysisReport(context.Background(), analysisReportReq)
		report := reportResp.GetReport()

		log.Debugf("Report: ", report.GetWarnings())

	}

	// TODO:
	// Get the npm PATH
	// Check if any vulnerable package exists?
	// If yes - Confirm with user to continue or not
	// If no - Install the pkg & return
	// If continue - Install the pkg
	return nil
}
