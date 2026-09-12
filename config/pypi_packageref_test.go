package config

import (
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPypiPackageRefNormalization(t *testing.T) {
	for _, tt := range []struct{ raw, normalized string }{
		{"0.6c11", "0.6rc11"}, {"3.05", "3.5"}, {"0.01", "0.1"},
		{"0!1.0", "1.0"}, {"1.0RC1", "1.0rc1"}, {"1.0.0", "1.0.0"},
	} {
		t.Run(tt.raw, func(t *testing.T) {
			cfg := &Config{
				TrustedPackages:    []TrustedPackage{{Purl: "pkg:pypi/demo@" + tt.raw}},
				DependencyCooldown: DependencyCooldownConfig{Skip: []TrustedPackage{{Purl: "pkg:pypi/demo@" + tt.raw}}},
			}
			require.NoError(t, preprocessPackageRefs(cfg))
			ref := cfg.TrustedPackages[0].purlRef
			for _, version := range []string{tt.raw, tt.normalized} {
				assert.True(t, ref.matches(&packagev1.PackageVersion{
					Package: &packagev1.Package{Ecosystem: packagev1.Ecosystem_ECOSYSTEM_PYPI, Name: "demo"}, Version: version,
				}))
			}
			assert.True(t, cooldownSkip(cfg.DependencyCooldown.Skip, packagev1.Ecosystem_ECOSYSTEM_PYPI, "demo").ExemptsVersion(tt.normalized))
			assert.Equal(t, "pkg:pypi/demo@"+tt.raw, cfg.TrustedPackages[0].Purl)
		})
	}
}

func TestPypiPackageRefNormalizationBoundaries(t *testing.T) {
	for _, tt := range []struct {
		purl, version string
		ecosystem     packagev1.Ecosystem
		want          bool
	}{
		{"pkg:pypi/demo", "1.0", packagev1.Ecosystem_ECOSYSTEM_PYPI, true},
		{"pkg:pypi/demo@invalid", "1.0", packagev1.Ecosystem_ECOSYSTEM_PYPI, false},
		{"pkg:pypi/demo@1.0.0", "1.0", packagev1.Ecosystem_ECOSYSTEM_PYPI, false},
		{"pkg:pypi/demo@1.0rc1", "1.0", packagev1.Ecosystem_ECOSYSTEM_PYPI, false},
		{"pkg:npm/demo@0.01", "0.1", packagev1.Ecosystem_ECOSYSTEM_NPM, false},
	} {
		t.Run(tt.purl+"/"+tt.version, func(t *testing.T) {
			var ref purlRef
			ref.parseFrom(tt.purl)
			assert.Equal(t, tt.want, ref.matches(&packagev1.PackageVersion{
				Package: &packagev1.Package{Ecosystem: tt.ecosystem, Name: "demo"}, Version: tt.version,
			}))
		})
	}
}
