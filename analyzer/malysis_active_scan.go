package analyzer

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"buf.build/gen/go/safedep/api/grpc/go/safedep/services/malysis/v1/malysisv1grpc"
	malysisv1pb "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/malysis/v1"
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	malysisv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/malysis/v1"
	drygrpc "github.com/safedep/dry/adapters/grpc"
	"github.com/safedep/dry/log"
	"google.golang.org/grpc"
)

type MalysisActiveScanAnalyzerConfig struct {
	Timeout  time.Duration
	TenantId string
	ApiKey   string
}

func DefaultMalysisActiveScanAnalyzerConfig() MalysisActiveScanAnalyzerConfig {
	return MalysisActiveScanAnalyzerConfig{
		Timeout:  5 * time.Minute,
		TenantId: os.Getenv("SAFEDEP_TENANT_ID"),
		ApiKey:   os.Getenv("SAFEDEP_API_KEY"),
	}
}

type malysisActiveScanAnalyzer struct {
	config MalysisActiveScanAnalyzerConfig
	client malysisv1grpc.MalwareAnalysisServiceClient
}

var _ Analyzer = &malysisActiveScanAnalyzer{}

func NewMalysisActiveScanAnalyzer(config MalysisActiveScanAnalyzerConfig) (*malysisActiveScanAnalyzer, error) {
	if config.TenantId == "" || config.ApiKey == "" {
		return nil, fmt.Errorf("active scanning requires SafeDep Cloud credentials (https://docs.safedep.io/cloud/malware-analysis)")
	}

	headers := http.Header{}
	headers.Set("x-tenant-id", config.TenantId)

	client, err := drygrpc.GrpcClient("pmg-malysis-active-scan",
		"api.safedep.io", "443", config.ApiKey, headers, []grpc.DialOption{})
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client: %w", err)
	}

	return &malysisActiveScanAnalyzer{
		config: config,
		client: malysisv1grpc.NewMalwareAnalysisServiceClient(client),
	}, nil
}

func (a *malysisActiveScanAnalyzer) Name() string {
	return "malysis-active-scan"
}

func (a *malysisActiveScanAnalyzer) Analyze(ctx context.Context,
	packageVersion *packagev1.PackageVersion) (*PackageVersionAnalysisResult, error) {

	log.Debugf("Running active analysis on package %s@%s", packageVersion.Package.Name, packageVersion.Version)

	ctx, cancel := context.WithTimeout(ctx, a.config.Timeout)
	defer cancel()

	scanResponse, err := a.client.AnalyzePackage(ctx, &malysisv1.AnalyzePackageRequest{
		Target: &malysisv1pb.PackageAnalysisTarget{
			PackageVersion: packageVersion,
		},
	})

	if err != nil {
		return nil, fmt.Errorf("failed to submit package for active scanning: %w", err)
	}

	var res *malysisv1.GetAnalysisReportResponse
	for {
		select {
		case <-ctx.Done():
			log.Debugf("Active analysis on package %s@%s timed out", packageVersion.Package.Name, packageVersion.Version)
			return nil, fmt.Errorf("active scanning timed out")
		case <-time.After(1 * time.Second):
		}

		res, err = a.client.GetAnalysisReport(ctx, &malysisv1.GetAnalysisReportRequest{
			AnalysisId: scanResponse.AnalysisId,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to get analysis report: %w", err)
		}

		if res.Status == malysisv1.AnalysisStatus_ANALYSIS_STATUS_COMPLETED {
			log.Debugf("Active analysis on package %s@%s completed", packageVersion.Package.Name, packageVersion.Version)
			break
		}
	}

	pvr := &PackageVersionAnalysisResult{
		PackageVersion: packageVersion,
		AnalysisID:     scanResponse.AnalysisId,
		ReferenceURL:   malysisReportUrl(scanResponse.AnalysisId),
		Action:         ActionAllow,
		Summary:        res.GetReport().GetInference().GetSummary(),
		Data:           res.GetReport(),
	}

	if res.GetReport().GetInference().GetIsMalware() {
		pvr.Action = ActionConfirm
	}

	if res.GetVerificationRecord().GetIsMalware() {
		pvr.Action = ActionBlock
	}

	return pvr, nil
}
