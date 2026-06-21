package malysiscache

import (
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/analyzer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func pkg(eco packagev1.Ecosystem, name, version string) *packagev1.PackageVersion {
	pv := &packagev1.PackageVersion{}
	pv.SetPackage(&packagev1.Package{})
	pv.GetPackage().SetName(name)
	pv.GetPackage().SetEcosystem(eco)
	pv.SetVersion(version)
	return pv
}

func TestCacheable(t *testing.T) {
	cases := []struct {
		name string
		in   *analyzer.PackageVersionAnalysisResult
		want bool
	}{
		{"clean allow", &analyzer.PackageVersionAnalysisResult{Action: analyzer.ActionAllow}, true},
		{"block", &analyzer.PackageVersionAnalysisResult{Action: analyzer.ActionBlock}, false},
		{"allow but malware", &analyzer.PackageVersionAnalysisResult{Action: analyzer.ActionAllow, IsMalware: true}, false},
		{"excluded malware downgrade", &analyzer.PackageVersionAnalysisResult{Action: analyzer.ActionAllow, IsMalware: true, IsExcluded: true}, false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, cacheable(tc.in))
		})
	}
}

func TestKeyAndReconstruct(t *testing.T) {
	eco, name, ver := packageKey(pkg(packagev1.Ecosystem_ECOSYSTEM_NPM, "left-pad", "1.0.0"))
	assert.Equal(t, "ECOSYSTEM_NPM", eco)
	assert.Equal(t, "left-pad", name)
	assert.Equal(t, "1.0.0", ver)

	res, ok := reconstruct(eco, name, ver, "aid", "https://ref", "ok")
	require.True(t, ok)
	assert.Equal(t, analyzer.ActionAllow, res.Action)
	assert.False(t, res.IsMalware)
	assert.Equal(t, packagev1.Ecosystem_ECOSYSTEM_NPM, res.PackageVersion.GetPackage().GetEcosystem())
	assert.Equal(t, "left-pad", res.PackageVersion.GetPackage().GetName())
	assert.Equal(t, "1.0.0", res.PackageVersion.GetVersion())

	_, ok = reconstruct("ECOSYSTEM_FROM_THE_FUTURE", name, ver, "", "", "")
	assert.False(t, ok)
}
