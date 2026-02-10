package analyzer

import (
	"context"
	"testing"

	malysisv1pb "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/malysis/v1"
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	malysisv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/malysis/v1"
	"github.com/safedep/pmg/config"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
)

// stubMalwareAnalysisServiceClient is a minimal stub implementing the Malysis gRPC client interface,
// returning a preconfigured response for testing.
type stubMalwareAnalysisServiceClient struct {
	resp *malysisv1.QueryPackageAnalysisResponse
	err  error
}

func (s *stubMalwareAnalysisServiceClient) QueryPackageAnalysis(ctx context.Context, req *malysisv1.QueryPackageAnalysisRequest, opts ...grpc.CallOption) (*malysisv1.QueryPackageAnalysisResponse, error) {
	return s.resp, s.err
}

// helper to make a basic PackageVersion for tests
func makePkgVersion(name, version string) *packagev1.PackageVersion {
	return &packagev1.PackageVersion{
		Package: &packagev1.Package{
			Name: name,
		},
		Version: version,
	}
}

func TestMalysisQueryAnalyzer_DefaultAllowWhenNotMalicious(t *testing.T) {
	resp := &malysisv1.QueryPackageAnalysisResponse{
		AnalysisId: "analysis-1",
		Report: &malysisv1pb.Report{
			Inference: &malysisv1pb.Report_Inference{
				IsMalware: false,
				Summary:   "No indicators of compromise",
			},
		},
		VerificationRecord: &malysisv1pb.VerificationRecord{
			IsMalware: false,
		},
	}
	an := &malysisQueryAnalyzer{
		client: &stubMalwareAnalysisServiceClient{resp: resp},
	}

	pv := makePkgVersion("safe-pkg", "1.0.0")
	result, err := an.Analyze(context.Background(), pv)
	assert.NoError(t, err)
	assert.Equal(t, ActionAllow, result.Action)
	assert.Equal(t, "analysis-1", result.AnalysisID)
	assert.Equal(t, pv, result.PackageVersion)
	assert.NotEmpty(t, result.ReferenceURL)
	assert.Equal(t, "No indicators of compromise", result.Summary)
}

func TestMalysisQueryAnalyzer_ConfirmOnSuspiciousWhenNotParanoid(t *testing.T) {
	// Ensure paranoid is disabled
	cfg := config.Get()
	origParanoid := cfg.Config.Paranoid
	cfg.Config.Paranoid = false
	defer func() { cfg.Config.Paranoid = origParanoid }()

	// Setup: inference says suspicious/malicious (unverified)
	resp := &malysisv1.QueryPackageAnalysisResponse{
		AnalysisId: "analysis-2",
		Report: &malysisv1pb.Report{
			Inference: &malysisv1pb.Report_Inference{
				IsMalware: true,
				Summary:   "Suspicious patterns detected",
			},
		},
		VerificationRecord: &malysisv1pb.VerificationRecord{
			IsMalware: false,
		},
	}
	an := &malysisQueryAnalyzer{
		client: &stubMalwareAnalysisServiceClient{resp: resp},
	}

	pv := makePkgVersion("suspicious-pkg", "2.0.0")
	result, err := an.Analyze(context.Background(), pv)
	assert.NoError(t, err)
	assert.Equal(t, ActionConfirm, result.Action)
	assert.Equal(t, "analysis-2", result.AnalysisID)
}

func TestMalysisQueryAnalyzer_BlockOnSuspiciousWhenParanoid(t *testing.T) {
	// Enable paranoid mode
	cfg := config.Get()
	origParanoid := cfg.Config.Paranoid
	cfg.Config.Paranoid = true
	defer func() { cfg.Config.Paranoid = origParanoid }()

	// Setup: inference says suspicious/malicious (unverified)
	resp := &malysisv1.QueryPackageAnalysisResponse{
		AnalysisId: "analysis-3",
		Report: &malysisv1pb.Report{
			Inference: &malysisv1pb.Report_Inference{
				IsMalware: true,
				Summary:   "Suspicious patterns detected",
			},
		},
		VerificationRecord: &malysisv1pb.VerificationRecord{
			IsMalware: false,
		},
	}
	an := &malysisQueryAnalyzer{
		client: &stubMalwareAnalysisServiceClient{resp: resp},
	}

	pv := makePkgVersion("suspicious-pkg", "3.0.0")
	result, err := an.Analyze(context.Background(), pv)
	assert.NoError(t, err)
	assert.Equal(t, ActionBlock, result.Action, "Paranoid mode should block suspicious packages")
}

func TestMalysisQueryAnalyzer_AlwaysBlockOnVerifiedMalware(t *testing.T) {
	// Paranoid on/off should not matter
	cfg := config.Get()
	origParanoid := cfg.Config.Paranoid
	cfg.Config.Paranoid = false
	defer func() { cfg.Config.Paranoid = origParanoid }()

	resp := &malysisv1.QueryPackageAnalysisResponse{
		AnalysisId: "analysis-4",
		Report: &malysisv1pb.Report{
			Inference: &malysisv1pb.Report_Inference{
				IsMalware: false,
				Summary:   "Inference not malicious, but verification is",
			},
		},
		VerificationRecord: &malysisv1pb.VerificationRecord{
			IsMalware: true,
		},
	}
	an := &malysisQueryAnalyzer{
		client: &stubMalwareAnalysisServiceClient{resp: resp},
	}

	pv := makePkgVersion("verified-malware", "9.9.9")
	result, err := an.Analyze(context.Background(), pv)
	assert.NoError(t, err)
	assert.Equal(t, ActionBlock, result.Action, "Verified malware must be blocked always")
}

// Implement the full client interface surface expected by malysisv1grpc.MalwareAnalysisServiceClient
func (s *stubMalwareAnalysisServiceClient) AnalyzePackage(ctx context.Context, req *malysisv1.AnalyzePackageRequest, opts ...grpc.CallOption) (*malysisv1.AnalyzePackageResponse, error) {
	// Not used in these tests; return a nil response with no error
	return nil, nil
}
func (s *stubMalwareAnalysisServiceClient) GetAnalysisReport(ctx context.Context, req *malysisv1.GetAnalysisReportRequest, opts ...grpc.CallOption) (*malysisv1.GetAnalysisReportResponse, error) {
	// Not used in these tests
	return nil, nil
}
func (s *stubMalwareAnalysisServiceClient) InternalAnalyzePackage(ctx context.Context, req *malysisv1.InternalAnalyzePackageRequest, opts ...grpc.CallOption) (*malysisv1.InternalAnalyzePackageResponse, error) {
	// Not used in these tests
	return nil, nil
}
func (s *stubMalwareAnalysisServiceClient) ListPackageAnalysisRecords(ctx context.Context, req *malysisv1.ListPackageAnalysisRecordsRequest, opts ...grpc.CallOption) (*malysisv1.ListPackageAnalysisRecordsResponse, error) {
	// Not used in these tests
	return nil, nil
}
