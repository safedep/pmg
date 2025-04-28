package analyser

import (
	"context"
	"fmt"
	"sync"

	"buf.build/gen/go/safedep/api/grpc/go/safedep/services/malysis/v1/malysisv1grpc"
	malysisv1pb "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/malysis/v1"
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	malysisv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/malysis/v1"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/pkg/models"
	vetUtils "github.com/safedep/vet/pkg/common/utils"
)

type PackageAnalyser struct {
	MaliciousPkgs      map[string]string
	Client             malysisv1grpc.MalwareAnalysisServiceClient
	Ctx                context.Context
	MaliciousPkgsMutex sync.Mutex
}

func New(client malysisv1grpc.MalwareAnalysisServiceClient, ctx context.Context) *PackageAnalyser {
	return &PackageAnalyser{
		MaliciousPkgs:      make(map[string]string),
		Client:             client,
		Ctx:                ctx,
		MaliciousPkgsMutex: sync.Mutex{},
	}
}

func (ap *PackageAnalyser) Handler() vetUtils.WorkQueueFn[models.Package] {
	return func(q *vetUtils.WorkQueue[models.Package], item models.Package) error {
		resp, err := SubmitPackageForAnalysis(ap.Ctx, ap.Client,
			packagev1.Ecosystem_ECOSYSTEM_NPM, item.Name, item.Version)
		if err != nil {
			log.Debugf("Failed to analyze %s@%s: %v", item.Name, item.Version, err)
			return err
		}

		reportResp, err := GetAnalysisReport(ap.Ctx, ap.Client, resp.GetAnalysisId())
		if err != nil {
			log.Debugf("Failed to get analysis report for %s:%s %v",
				item.Name, resp.GetAnalysisId(), err)
			return err
		}

		report := reportResp.GetReport()
		if report == nil {
			log.Debugf("Empty report received for %s", item.Name)
			return nil
		}

		inference := report.GetInference()
		if inference == nil {
			log.Debugf("No inference data for %s", item.Name)
			return nil
		}

		log.Infof("Inference for %s: isMalware=%v", item.Name, inference.GetIsMalware())

		if inference.GetIsMalware() {
			ap.MaliciousPkgsMutex.Lock()
			ap.MaliciousPkgs[fmt.Sprintf("%s@%s", item.Name, item.Version)] = inference.GetSummary()
			ap.MaliciousPkgsMutex.Unlock()
		}

		return nil
	}
}

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
