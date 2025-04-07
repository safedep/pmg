package ecosystems

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"buf.build/gen/go/safedep/api/grpc/go/safedep/services/malysis/v1/malysisv1grpc"
	malysisv1pb "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/malysis/v1"
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	malysisv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/malysis/v1"
	drygrpc "github.com/safedep/dry/adapters/grpc"
	"github.com/safedep/dry/crypto"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
)

var (
	packageName string
	action      string
)

func NewNpmCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "npm",
		Short: "Scan packages from npm registry",
		RunE: func(cmd *cobra.Command, args []string) error {
			action = args[0]
			packageName = args[1]
			if action == "install" {
				wrapNpm()
			}
			return nil
		},
	}
	return cmd
}

func wrapNpm() {
	// Create a file with random name which will contain the dependency tree
	randomFileName, err := crypto.RandomString(12, "abcdefghijklmnopqrstuvwxyz0123456789")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate random string: %v\n", err)
		os.Exit(1)
	}
	outputFile := filepath.Join(os.TempDir(), randomFileName+".txt")

	// Fetch the dependency tree using arborist
	cmd := exec.Command("node", "pkg/tree/arborist.js", packageName, outputFile).Run()
	if cmd != nil {
		fmt.Println("Error while getting dependency tree: ", cmd.Error())
		return
	}

	// Get the extracted packages
	data, err := os.ReadFile(outputFile)
	if err != nil {
		fmt.Println("Error while reading dependency tree: ", err)
		return
	}

	lines := strings.SplitSeq(string(data), "\n")
	for line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "@") {
			continue
		}

		parts := strings.SplitN(line, "@", 2)
		if len(parts) != 2 {
			fmt.Println("Invalid package line:", line)
			continue
		}

		name := parts[0]
		version := parts[1]

		tok := os.Getenv("SAFEDEP_API_KEY")
		tenantId := os.Getenv("SAFEDEP_TENANT_ID")

		if tok == "" || tenantId == "" {
			panic("SAFEDEP_API_KEY and SAFEDEP_TENANT_ID must be set")
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
			fmt.Printf("Failed to analyze %s@%s: %v\n", name, version, err)
			continue
		}
		fmt.Printf("Submitted %s@%s | Analysis ID: %s\n", name, version, resp.GetAnalysisId())

		analysisReportReq := &malysisv1.GetAnalysisReportRequest{
			AnalysisId: resp.GetAnalysisId(),
		}

		reportResp, err := client.GetAnalysisReport(context.Background(), analysisReportReq)
		_ = reportResp.GetReport()

	}

	// Get the npm PATH (using exec.LookPath)

	// Check if any vulnerable package exists?
	// If yes - Confirm with user to continue or not
	// If no - Install the pkg & return

	//  If continue - Install the pkg

}
