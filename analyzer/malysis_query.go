package analyzer

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"

	"buf.build/gen/go/safedep/api/grpc/go/safedep/services/malysis/v1/malysisv1grpc"
	malysisv1pb "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/malysis/v1"
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	malysisv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/malysis/v1"
	drygrpc "github.com/safedep/dry/adapters/grpc"
	"github.com/safedep/dry/cloud"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/analytics"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	communityMalysisHost = "community-api.safedep.io"
	communityMalysisPort = "443"

	malysisMaxAttempts = 3
	malysisRetryMargin = 100 * time.Millisecond

	// grpc-go reports an HTTP 429 from a proxy as Unavailable with this message.
	grpcHTTP429 = "status code received from server: 429"
)

type MalysisQueryAnalyzerConfig struct {
	// Cache, when non-nil, enables a persistent read-through verdict cache
	// applied as a decorator by newMalysisAnalyzer. nil = no caching.
	Cache MalysisCache

	// RetryWait maps the base wait of a retry to the real wait. Nil adds jitter.
	RetryWait func(base time.Duration) time.Duration
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
	conn, err := newReconnectingConn(func() (closableConn, error) {
		return drygrpc.GrpcClient("pmg-malysis-query",
			communityMalysisHost, communityMalysisPort, "", http.Header{}, []grpc.DialOption{malysisKeepalive})
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client: %w", err)
	}

	return NewMalysisQueryAnalyzerWithClient(malysisv1grpc.NewMalwareAnalysisServiceClient(conn), config, false)
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
	conn, err := newReconnectingConn(func() (closableConn, error) {
		cloudClient, err := cloud.NewDataPlaneClient("pmg-malysis-query", creds)
		if err != nil {
			return nil, err
		}
		return cloudClient.Connection(), nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create authenticated gRPC client: %w", err)
	}

	return NewMalysisQueryAnalyzerWithClient(malysisv1grpc.NewMalwareAnalysisServiceClient(conn), config, true)
}

func (a *malysisQueryAnalyzer) Name() string {
	return "malysis-query"
}

func (a *malysisQueryAnalyzer) Analyze(ctx context.Context,
	packageVersion *packagev1.PackageVersion) (*PackageVersionAnalysisResult, error) {

	res, err := a.query(ctx, &malysisv1.QueryPackageAnalysisRequest{
		Target: &malysisv1pb.PackageAnalysisTarget{
			PackageVersion: packageVersion,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query package analysis: %w", err)
	}

	analytics.TrackMalysisQuery()

	cfg := config.Get()
	dropExclusionUnderCloudPolicy(cfg, packageVersion, res)

	// By default, the analyzer allows the package version
	analysisResult := &PackageVersionAnalysisResult{
		PackageVersion: packageVersion,
		ReferenceURL:   malysisReportUrl(res.GetAnalysisId()),
		Action:         ActionAllow,
		AnalysisID:     res.GetAnalysisId(),
		Summary:        res.GetReport().GetInference().GetSummary(),
		Data:           res.GetReport(),
	}

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

// query retries only in paranoid mode. Default mode allows the package on a
// failure, so a retry would only add load to an outage.
func (a *malysisQueryAnalyzer) query(ctx context.Context,
	req *malysisv1.QueryPackageAnalysisRequest) (*malysisv1.QueryPackageAnalysisResponse, error) {
	if !config.Get().FailClosed() {
		return a.client.QueryPackageAnalysis(ctx, req)
	}

	jitter := a.Config.RetryWait
	if jitter == nil {
		jitter = malysisJitter
	}

	attemptCtx := ctx
	for attempt := 1; ; attempt++ {
		res, err := a.client.QueryPackageAnalysis(attemptCtx, req)
		if err == nil || attempt == malysisMaxAttempts {
			return res, err
		}

		base, ok := malysisRetryBase(err, attempt)
		if !ok {
			return nil, err
		}
		wait := jitter(base)
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < wait+malysisRetryMargin {
			return nil, err
		}

		log.Debugf("Malysis query failed with %s, retrying in %s", status.Code(err), wait)
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, err
		case <-timer.C:
		}
		attemptCtx = withoutHedge(ctx)
	}
}

// malysisRetryBase gives the wait before the next attempt, or false for an
// error that a retry cannot fix, such as Internal from a backend bug.
func malysisRetryBase(err error, attempt int) (time.Duration, bool) {
	s := status.Convert(err)
	var base time.Duration
	switch {
	case s.Code() == codes.ResourceExhausted,
		s.Code() == codes.Unavailable && strings.Contains(s.Message(), grpcHTTP429):
		base = time.Second
	case s.Code() == codes.Unavailable:
		base = 200 * time.Millisecond
	default:
		return 0, false
	}
	for range attempt - 1 {
		base *= 3
	}
	return base, true
}

func malysisJitter(base time.Duration) time.Duration {
	return base/2 + rand.N(base)
}

// dropExclusionUnderCloudPolicy removes the tenant exclusion from the reply
// when the cloud policy applies. Trust entries with scope MALWARE replace
// exclusions, and pmg never honors a server-side exclusion then. The drop
// happens before the result exists, so no verdict cache holds tenant data.
func dropExclusionUnderCloudPolicy(cfg *config.RuntimeConfig, packageVersion *packagev1.PackageVersion,
	res *malysisv1.QueryPackageAnalysisResponse) {
	if !cfg.CloudPolicyEnabled() || res.GetMaliciousPackageExclusion() == nil {
		return
	}

	log.Debugf("Dropping tenant exclusion %q for package %s@%s: cloud.policy is on",
		res.GetMaliciousPackageExclusion().GetExclusionId(),
		packageVersion.GetPackage().GetName(),
		packageVersion.GetVersion())
	res.ClearMaliciousPackageExclusion()
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
