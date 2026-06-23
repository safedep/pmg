package proxye2e

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"buf.build/gen/go/safedep/api/grpc/go/safedep/services/malysis/v1/malysisv1grpc"
	malysisv1pb "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/malysis/v1"
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	malysisv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/malysis/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Verdict is a programmable malysis response for a package version. It is the
// raw upstream signal: the real analyzer's verdict-mapping (suspicious→confirm,
// paranoid upgrade, verified→block, exclusion→allow) runs on top of it.
type Verdict struct {
	resp *malysisv1.QueryPackageAnalysisResponse
	err  error
}

// Clean reports no malware (allow).
func Clean() Verdict {
	return Verdict{resp: &malysisv1.QueryPackageAnalysisResponse{
		Report:             &malysisv1pb.Report{Inference: &malysisv1pb.Report_Inference{IsMalware: false, Summary: "no indicators"}},
		VerificationRecord: &malysisv1pb.VerificationRecord{IsMalware: false},
	}}
}

// Suspicious reports inference-only malware (unverified). Maps to confirm, or to
// block under paranoid mode.
func Suspicious() Verdict {
	return Verdict{resp: &malysisv1.QueryPackageAnalysisResponse{
		Report:             &malysisv1pb.Report{Inference: &malysisv1pb.Report_Inference{IsMalware: true, Summary: "suspicious patterns detected"}},
		VerificationRecord: &malysisv1pb.VerificationRecord{IsMalware: false},
	}}
}

// VerifiedMalware reports verified malware (always block).
func VerifiedMalware() Verdict {
	return Verdict{resp: &malysisv1.QueryPackageAnalysisResponse{
		Report:             &malysisv1pb.Report{Inference: &malysisv1pb.Report_Inference{IsMalware: true, Summary: "verified malware"}},
		VerificationRecord: &malysisv1pb.VerificationRecord{IsMalware: true},
	}}
}

// Excluded reports verified malware carrying a tenant exclusion. With an
// exclusion-honoring analyzer it downgrades to allow.
func Excluded(reason string) Verdict {
	v := VerifiedMalware()
	v.resp.MaliciousPackageExclusion = &malysisv1.QueryPackageAnalysisResponse_MaliciousPackageExclusion{
		ExclusionId: "e2e-exclusion",
		Reason:      reason,
	}
	return v
}

// NotFound reports the package is absent from the analysis DB (treated as allow,
// not a failure).
func NotFound() Verdict {
	return Verdict{err: status.Error(codes.NotFound, "package not found")}
}

// ServerError reports an upstream failure, exercising the fail-open path.
func ServerError() Verdict {
	return Verdict{err: status.Error(codes.Unavailable, "analysis service unavailable")}
}

type AnalyzedPackage struct {
	Ecosystem packagev1.Ecosystem
	Name      string
	Version   string
}

// AnalyzerRecorder holds programmable verdicts and records every query the real
// analyzer issues to the stub gRPC client.
type AnalyzerRecorder struct {
	mu       sync.Mutex
	verdicts map[string]Verdict
	calls    []AnalyzedPackage
}

func newAnalyzerRecorder() *AnalyzerRecorder {
	return &AnalyzerRecorder{verdicts: map[string]Verdict{}}
}

func verdictKey(eco packagev1.Ecosystem, name, version string) string {
	if eco == packagev1.Ecosystem_ECOSYSTEM_PYPI {
		name = normalizePypiName(name)
	}
	return fmt.Sprintf("%s|%s|%s", eco.String(), name, version)
}

func (r *AnalyzerRecorder) SetNpm(name, version string, v Verdict) {
	r.set(packagev1.Ecosystem_ECOSYSTEM_NPM, name, version, v)
}

func (r *AnalyzerRecorder) SetPypi(name, version string, v Verdict) {
	r.set(packagev1.Ecosystem_ECOSYSTEM_PYPI, name, version, v)
}

func (r *AnalyzerRecorder) set(eco packagev1.Ecosystem, name, version string, v Verdict) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.verdicts[verdictKey(eco, name, version)] = v
}

// Calls returns every package the analyzer was queried for, in order.
func (r *AnalyzerRecorder) Calls() []AnalyzedPackage {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]AnalyzedPackage, len(r.calls))
	copy(out, r.calls)
	return out
}

// AnalyzedCount reports how many times a specific package version was queried.
func (r *AnalyzerRecorder) AnalyzedCount(name, version string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, c := range r.calls {
		if c.Name == name && c.Version == version {
			n++
		}
	}
	return n
}

func (r *AnalyzerRecorder) handle(req *malysisv1.QueryPackageAnalysisRequest) (*malysisv1.QueryPackageAnalysisResponse, error) {
	pv := req.GetTarget().GetPackageVersion()
	eco := pv.GetPackage().GetEcosystem()
	name := pv.GetPackage().GetName()
	version := pv.GetVersion()

	r.mu.Lock()
	r.calls = append(r.calls, AnalyzedPackage{Ecosystem: eco, Name: name, Version: version})
	v, ok := r.verdicts[verdictKey(eco, name, version)]
	r.mu.Unlock()

	if !ok {
		v = Clean()
	}
	if v.err != nil {
		return nil, v.err
	}

	resp := v.resp
	if resp.GetAnalysisId() == "" {
		resp.AnalysisId = fmt.Sprintf("e2e-%s-%s", name, version)
	}
	return resp, nil
}

// stubAnalyzerClient implements the malysis gRPC client by delegating to the
// recorder. The embedded interface satisfies the full method set; only
// QueryPackageAnalysis is exercised by the analyzer.
type stubAnalyzerClient struct {
	malysisv1grpc.MalwareAnalysisServiceClient
	rec *AnalyzerRecorder
}

func (s *stubAnalyzerClient) QueryPackageAnalysis(_ context.Context,
	req *malysisv1.QueryPackageAnalysisRequest, _ ...grpc.CallOption) (*malysisv1.QueryPackageAnalysisResponse, error) {
	return s.rec.handle(req)
}

// normalizePypiName mirrors the interceptor's PyPI name canonicalization so
// programmed verdicts key match the name the analyzer is queried with.
func normalizePypiName(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "_", "-")
	name = strings.ReplaceAll(name, ".", "-")
	return name
}
