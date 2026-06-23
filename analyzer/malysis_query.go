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
	"github.com/safedep/dry/cloud"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"google.golang.org/grpc"
)

const (
	communityMalysisHost = "community-api.safedep.io"
	communityMalysisPort = "443"
)

type MalysisQueryAnalyzerConfig struct {
	// Cache, when non-nil, enables a persistent read-through verdict cache
	// applied as a decorator by newMalysisAnalyzer. nil = no caching.
	Cache MalysisCache
}

type malysisQueryAnalyzer struct {
	client malysisv1grpc.MalwareAnalysisServiceClient
	Config MalysisQueryAnalyzerConfig

	// honorExclusions enables honoring tenant-specific malicious package
	// exclusions returned by authenticated queries. Exclusions are never
	// returned for unauthenticated (community) queries.
	honorExclusions bool
}

var _ Analyzer = &malysisQueryAnalyzer{}
var _ PackageVersionAnalyzer = &malysisQueryAnalyzer{}

// NewMalysisQueryAnalyzer creates an unauthenticated analyzer that queries the
// SafeDep community malware analysis service.
func NewMalysisQueryAnalyzer(config MalysisQueryAnalyzerConfig) (*malysisQueryAnalyzer, error) {
	client, err := drygrpc.GrpcClient("pmg-malysis-query",
		communityMalysisHost, communityMalysisPort, "", http.Header{}, []grpc.DialOption{})
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client: %w", err)
	}

	return NewMalysisQueryAnalyzerWithClient(malysisv1grpc.NewMalwareAnalysisServiceClient(client), config, false)
}

// NewMalysisQueryAnalyzerWithClient builds an analyzer over a caller-supplied
// gRPC client. It is the shared constructor behind the community and
// authenticated variants, and the injection seam used by tests to drive the
// real verdict-mapping path over a stub client. honorExclusions mirrors the
// authenticated analyzer's tenant-exclusion behavior.
func NewMalysisQueryAnalyzerWithClient(client malysisv1grpc.MalwareAnalysisServiceClient,
	config MalysisQueryAnalyzerConfig, honorExclusions bool) (*malysisQueryAnalyzer, error) {
	if client == nil {
		return nil, fmt.Errorf("malysis client must not be nil")
	}

	return &malysisQueryAnalyzer{
		client:          client,
		Config:          config,
		honorExclusions: honorExclusions,
	}, nil
}

// NewMalysisAuthenticatedQueryAnalyzer creates an analyzer that queries the
// authenticated SafeDep Cloud malware analysis service (api.safedep.io) using
// the provided API key credentials. The analysis behavior is identical to the
// community analyzer except that it additionally honors tenant-specific
// malicious package exclusions returned in the response.
func NewMalysisAuthenticatedQueryAnalyzer(config MalysisQueryAnalyzerConfig,
	creds *cloud.Credentials) (*malysisQueryAnalyzer, error) {
	cloudClient, err := cloud.NewDataPlaneClient("pmg-malysis-query", creds)
	if err != nil {
		return nil, fmt.Errorf("failed to create authenticated gRPC client: %w", err)
	}

	return NewMalysisQueryAnalyzerWithClient(
		malysisv1grpc.NewMalwareAnalysisServiceClient(cloudClient.Connection()), config, true)
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
		ReferenceURL:   malysisReportUrl(res.GetAnalysisId()),
		Action:         ActionAllow,
		AnalysisID:     res.GetAnalysisId(),
		Summary:        res.GetReport().GetInference().GetSummary(),
		Data:           res.GetReport(),
	}

	cfg := config.Get()
	// Mark the package version to be confirmed if it is malicious (not confirmed)
	if res.GetReport().GetInference().GetIsMalware() {
		analysisResult.IsMalware = true
		analysisResult.Action = ActionConfirm

		// Treat suspicious package as malicious when `--paranoid` flag is set to true
		if cfg.Config.Paranoid {
			analysisResult.Action = ActionBlock
		}
	}

	// A confirmed malicious package is blocked here, unless a tenant exclusion
	// downgrades it to allow in applyExclusion below.
	if res.GetVerificationRecord().GetIsMalware() {
		analysisResult.IsMalware = true
		analysisResult.IsVerified = true
		analysisResult.Action = ActionBlock
	}

	// Honor tenant-specific exclusion as an opt-in trust signal. This is only
	// applied for authenticated queries and only when the package was actually
	// flagged. The exclusion in the response is scoped by the server to the
	// exact package version we queried, so it is an exact match by construction.
	a.applyExclusion(analysisResult, res)

	return analysisResult, nil
}

// applyExclusion downgrades a flagged package to ActionAllow when the
// authenticated response carries a tenant-specific malicious package exclusion.
// The exclusion is honored only when the package was flagged as malware, so it
// never weakens the verdict for packages that were already allowed.
func (a *malysisQueryAnalyzer) applyExclusion(result *PackageVersionAnalysisResult,
	res *malysisv1.QueryPackageAnalysisResponse) {
	if !a.honorExclusions {
		return
	}

	exclusion := res.GetMaliciousPackageExclusion()
	if exclusion == nil || exclusion.GetExclusionId() == "" {
		return
	}

	if !result.IsMalware {
		return
	}

	log.Debugf("Honoring tenant exclusion %q for package %s@%s: %s",
		exclusion.GetExclusionId(),
		result.PackageVersion.GetPackage().GetName(),
		result.PackageVersion.GetVersion(),
		exclusion.GetReason())

	result.IsExcluded = true
	result.ExclusionID = exclusion.GetExclusionId()
	result.ExclusionReason = exclusion.GetReason()
	result.Action = ActionAllow
}

func malysisReportUrl(analysisId string) string {
	return fmt.Sprintf("https://app.safedep.io/community/malysis/%s", analysisId)
}
