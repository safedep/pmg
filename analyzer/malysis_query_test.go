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

func TestMalysisQueryAnalyzer_HonorsExclusionForFlaggedPackage(t *testing.T) {
	cfg := config.Get()
	origParanoid := cfg.Config.Paranoid
	cfg.Config.Paranoid = false
	defer func() { cfg.Config.Paranoid = origParanoid }()

	// Verified malware that would normally be blocked, but the tenant has an
	// exclusion trusting this exact package version.
	resp := &malysisv1.QueryPackageAnalysisResponse{
		AnalysisId: "analysis-excl",
		Report: &malysisv1pb.Report{
			Inference: &malysisv1pb.Report_Inference{
				IsMalware: true,
				Summary:   "Suspicious patterns detected",
			},
		},
		VerificationRecord: &malysisv1pb.VerificationRecord{
			IsMalware: true,
		},
		MaliciousPackageExclusion: &malysisv1.QueryPackageAnalysisResponse_MaliciousPackageExclusion{
			ExclusionId: "excl-1",
			Reason:      "Reviewed and trusted internally",
		},
	}

	an := &malysisQueryAnalyzer{
		client:          &stubMalwareAnalysisServiceClient{resp: resp},
		honorExclusions: true,
	}

	pv := makePkgVersion("trusted-internal-pkg", "1.2.3")
	result, err := an.Analyze(context.Background(), pv)
	assert.NoError(t, err)
	assert.Equal(t, ActionAllow, result.Action, "Exclusion should downgrade a flagged package to allow")
	assert.True(t, result.IsExcluded)
	assert.Equal(t, "excl-1", result.ExclusionID)
	assert.Equal(t, "Reviewed and trusted internally", result.ExclusionReason)
	// Inference flags are retained for reporting/audit
	assert.True(t, result.IsMalware)
	assert.True(t, result.IsVerified)
}

func TestMalysisQueryAnalyzer_IgnoresExclusionWhenNotEnabled(t *testing.T) {
	// Community analyzer must never honor exclusions even if one is present.
	resp := &malysisv1.QueryPackageAnalysisResponse{
		AnalysisId: "analysis-excl-2",
		Report: &malysisv1pb.Report{
			Inference: &malysisv1pb.Report_Inference{IsMalware: true},
		},
		VerificationRecord: &malysisv1pb.VerificationRecord{IsMalware: true},
		MaliciousPackageExclusion: &malysisv1.QueryPackageAnalysisResponse_MaliciousPackageExclusion{
			ExclusionId: "excl-2",
			Reason:      "Should be ignored",
		},
	}

	an := &malysisQueryAnalyzer{
		client:          &stubMalwareAnalysisServiceClient{resp: resp},
		honorExclusions: false,
	}

	pv := makePkgVersion("verified-malware", "9.9.9")
	result, err := an.Analyze(context.Background(), pv)
	assert.NoError(t, err)
	assert.Equal(t, ActionBlock, result.Action, "Exclusions must be ignored when not enabled")
	assert.False(t, result.IsExcluded)
}

func TestMalysisQueryAnalyzer_IgnoresEmptyExclusionId(t *testing.T) {
	// An exclusion with no ID is not a concrete, exact match and must be ignored.
	resp := &malysisv1.QueryPackageAnalysisResponse{
		AnalysisId: "analysis-excl-3",
		Report: &malysisv1pb.Report{
			Inference: &malysisv1pb.Report_Inference{IsMalware: true},
		},
		VerificationRecord: &malysisv1pb.VerificationRecord{IsMalware: true},
		MaliciousPackageExclusion: &malysisv1.QueryPackageAnalysisResponse_MaliciousPackageExclusion{
			ExclusionId: "",
			Reason:      "No id",
		},
	}

	an := &malysisQueryAnalyzer{
		client:          &stubMalwareAnalysisServiceClient{resp: resp},
		honorExclusions: true,
	}

	pv := makePkgVersion("verified-malware", "9.9.9")
	result, err := an.Analyze(context.Background(), pv)
	assert.NoError(t, err)
	assert.Equal(t, ActionBlock, result.Action)
	assert.False(t, result.IsExcluded)
}

func TestMalysisQueryAnalyzer_ExclusionDoesNotAffectCleanPackage(t *testing.T) {
	// A non-malware package with a spurious exclusion stays allowed and is not
	// marked as excluded (nothing to trust).
	resp := &malysisv1.QueryPackageAnalysisResponse{
		AnalysisId: "analysis-excl-4",
		Report: &malysisv1pb.Report{
			Inference: &malysisv1pb.Report_Inference{IsMalware: false},
		},
		VerificationRecord: &malysisv1pb.VerificationRecord{IsMalware: false},
		MaliciousPackageExclusion: &malysisv1.QueryPackageAnalysisResponse_MaliciousPackageExclusion{
			ExclusionId: "excl-4",
			Reason:      "Stale exclusion",
		},
	}

	an := &malysisQueryAnalyzer{
		client:          &stubMalwareAnalysisServiceClient{resp: resp},
		honorExclusions: true,
	}

	pv := makePkgVersion("clean-pkg", "1.0.0")
	result, err := an.Analyze(context.Background(), pv)
	assert.NoError(t, err)
	assert.Equal(t, ActionAllow, result.Action)
	assert.False(t, result.IsExcluded)
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
	return nil, nil
}
func (s *stubMalwareAnalysisServiceClient) InternalAgenticAnalyzePackage(ctx context.Context, req *malysisv1.InternalAgenticAnalyzePackageRequest, opts ...grpc.CallOption) (*malysisv1.InternalAgenticAnalyzePackageResponse, error) {
	return nil, nil
}
func (s *stubMalwareAnalysisServiceClient) InternalPublishDomainEvent(ctx context.Context, req *malysisv1.InternalPublishDomainEventRequest, opts ...grpc.CallOption) (*malysisv1.InternalPublishDomainEventResponse, error) {
	return nil, nil
}
