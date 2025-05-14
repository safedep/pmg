package analyzer

import (
	"context"

	malysisv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/malysis/v1"
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
)

// A base interface for all analyzers
type Analyzer interface {
	Name() string
}

type MalysisResult struct {
	AnalysisID string
	Report     *malysisv1.Report
}

func (m *MalysisResult) IsMalware() bool {
	return m.Report.GetInference().GetIsMalware()
}

func (m *MalysisResult) Summary() string {
	return m.Report.GetInference().GetSummary()
}

type MalysisAnalyzer interface {
	Analyzer

	Analyze(ctx context.Context, packageVersion *packagev1.PackageVersion) (*MalysisResult, error)
}
