package guard

import (
	"context"
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/analyzer"
	"github.com/stretchr/testify/assert"
)

func TestGuardConcurrentlyAnalyzePackagesMalwareQueryService(t *testing.T) {
	mq, err := analyzer.NewMalysisQueryAnalyzer(analyzer.MalysisQueryAnalyzerConfig{})
	if err != nil {
		t.Fatalf("failed to create mq: %v", err)
	}

	pg, err := NewPackageManagerGuard(DefaultPackageManagerGuardConfig(), nil, nil,
		[]analyzer.PackageVersionAnalyzer{mq}, PackageManagerGuardInteraction{})
	if err != nil {
		t.Fatalf("failed to create pg: %v", err)
	}

	t.Run("should resolve a single known malicious package version", func(t *testing.T) {
		r, err := pg.concurrentAnalyzePackages(context.Background(), []*packagev1.PackageVersion{
			{
				Package: &packagev1.Package{
					Name:      "nyc-config",
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
				},
				Version: "10.0.0",
			},
		})
		if err != nil {
			t.Fatalf("failed to analyze packages: %v", err)
		}

		assert.Equal(t, 1, len(r))
		assert.Equal(t, "nyc-config", r[0].PackageVersion.GetPackage().GetName())
		assert.Equal(t, "10.0.0", r[0].PackageVersion.GetVersion())
		assert.Equal(t, packagev1.Ecosystem_ECOSYSTEM_NPM, r[0].PackageVersion.GetPackage().GetEcosystem())
		assert.NotEmpty(t, r[0].ReferenceURL)
		assert.NotEmpty(t, r[0].Summary)
		assert.NotNil(t, r[0].Data)
		assert.Equal(t, analyzer.ActionBlock, r[0].Action)
	})
}
