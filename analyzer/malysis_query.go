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
var _ MalysisAnalyzer = &malysisQueryAnalyzer{}

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
	packageVersion *packagev1.PackageVersion) (*MalysisResult, error) {

	res, err := a.client.QueryPackageAnalysis(ctx, &malysisv1.QueryPackageAnalysisRequest{
		Target: &malysisv1pb.PackageAnalysisTarget{
			PackageVersion: packageVersion,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query package analysis: %w", err)
	}

	return &MalysisResult{
		Report: res.GetReport(),
	}, nil
}
