package analyser

import (
	"context"
	"fmt"

	"buf.build/gen/go/safedep/api/grpc/go/safedep/services/malysis/v1/malysisv1grpc"
	malysisv1pb "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/malysis/v1"
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	malysisv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/malysis/v1"
)

func SubmitPackageForAnalysis(client malysisv1grpc.MalwareAnalysisServiceClient,
	ecosystem packagev1.Ecosystem, name string,
	version string) (string, error) {
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
	resp, err := client.AnalyzePackage(context.Background(), req)
	if err != nil {
		return "", fmt.Errorf("failed to analyze %s@%s: %v", name, version, err)
	}
	return resp.GetAnalysisId(), nil
}
func GetAnalysisReport(client malysisv1grpc.MalwareAnalysisServiceClient,
	analysisId string) (*malysisv1pb.Report, error) {
	analysisReportReq := &malysisv1.GetAnalysisReportRequest{
		AnalysisId: analysisId,
	}
	reportResp, err := client.GetAnalysisReport(context.Background(), analysisReportReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get analysis report: %v", err)
	}
	return reportResp.GetReport(), nil
}
