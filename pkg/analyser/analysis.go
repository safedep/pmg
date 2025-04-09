package analyser

import (
	"context"
	"fmt"

	"buf.build/gen/go/safedep/api/grpc/go/safedep/services/malysis/v1/malysisv1grpc"
	malysisv1pb "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/malysis/v1"
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	malysisv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/malysis/v1"
)

func SubmitPackageForAnalysis(ctx context.Context, client malysisv1grpc.MalwareAnalysisServiceClient,
	ecosystem packagev1.Ecosystem, name string,
	version string) (*malysisv1.AnalyzePackageResponse, error) {
	req := &malysisv1.AnalyzePackageRequest{
		Target: &malysisv1pb.PackageAnalysisTarget{
			PackageVersion: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Ecosystem: ecosystem,
					Name:      name,
				},
				Version: version,
			},
		},
	}
	resp, err := client.AnalyzePackage(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to analyze %s@%s: %w", name, version, err)
	}
	return resp, nil
}

func GetAnalysisReport(ctx context.Context, client malysisv1grpc.MalwareAnalysisServiceClient,
	analysisId string) (*malysisv1.GetAnalysisReportResponse, error) {
	analysisReportReq := &malysisv1.GetAnalysisReportRequest{
		AnalysisId: analysisId,
	}
	reportResp, err := client.GetAnalysisReport(ctx, analysisReportReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get analysis report: %w", err)
	}
	return reportResp, nil
}
