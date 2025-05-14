package analyzer

import (
	"context"
	"fmt"
	"net/http"

	"buf.build/gen/go/safedep/api/grpc/go/safedep/services/malysis/v1/malysisv1grpc"
	malysisv1pb "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/malysis/v1"
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	malysisv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/malysis/v1"
	drygrpc "github.com/safedep/dry/adapters/grpc"
	"google.golang.org/grpc"
)

type MalysisQueryAnalyzerConfig struct{}

type malysisQueryAnalyzer struct {
	client malysisv1grpc.MalwareAnalysisServiceClient
	Config MalysisQueryAnalyzerConfig
}

var _ Analyzer = &malysisQueryAnalyzer{}
var _ PackageVersionAnalyzer = &malysisQueryAnalyzer{}

func NewMalysisQueryAnalyzer(config MalysisQueryAnalyzerConfig) (*malysisQueryAnalyzer, error) {
	client, err := drygrpc.GrpcClient("pmg-malysis-query",
		"community-api.safedep.io", "443", "", http.Header{}, []grpc.DialOption{})
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client: %w", err)
	}

	return &malysisQueryAnalyzer{
		client: malysisv1grpc.NewMalwareAnalysisServiceClient(client),
		Config: config,
	}, nil
}

func (a *malysisQueryAnalyzer) Name() string {
	return "malysis-query"
}

func (a *malysisQueryAnalyzer) Analyze(ctx context.Context,
	packageVersion *packagev1.PackageVersion) (*PackageVersionAnalysisResult, error) {

	res, err := a.client.QueryPackageAnalysis(ctx, &malysisv1.QueryPackageAnalysisRequest{
		Target: &malysisv1pb.PackageAnalysisTarget{
			PackageVersion: packageVersion,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query package analysis: %w", err)
	}

	// By default, the analyzer allows the package version
	analysisResult := &PackageVersionAnalysisResult{
		PackageVersion: packageVersion,
		Action:         ActionAllow,
		AnalysisID:     res.GetAnalysisId(),
		Summary:        res.GetReport().GetInference().GetSummary(),
		Data:           res.GetReport(),
	}

	// Mark the package version to be confirmed if it is malicious (not confirmed)
	if res.GetReport().GetInference().GetIsMalware() {
		analysisResult.Action = ActionConfirm
	}

	// This is a confirmed malicious package, we must always block it
	if res.GetVerificationRecord().GetIsMalware() {
		analysisResult.Action = ActionBlock
	}

	return analysisResult, nil
}
