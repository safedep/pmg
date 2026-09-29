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
				assert.True(t, ref.matches(packageIdentity(packagev1.Ecosystem_ECOSYSTEM_PYPI, "demo", version)))
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
		{"pkg:pypi/demo@1.0.0", "1.0", packagev1.Ecosystem_ECOSYSTEM_PYPI, true},
		{"pkg:pypi/demo@1.0rc1", "1.0", packagev1.Ecosystem_ECOSYSTEM_PYPI, false},
		{"pkg:npm/demo@0.01", "0.1", packagev1.Ecosystem_ECOSYSTEM_NPM, false},
		{"pkg:pypi/evil/demo", "1.0", packagev1.Ecosystem_ECOSYSTEM_PYPI, false},
		{"pkg:unknown/demo", "1.0", packagev1.Ecosystem_ECOSYSTEM_UNSPECIFIED, false},
	} {
		t.Run(tt.purl+"/"+tt.version, func(t *testing.T) {
			cfg := &Config{TrustedPackages: []TrustedPackage{{Purl: tt.purl}}}
			require.NoError(t, preprocessPackageRefs(cfg))
			assert.Equal(t, tt.want, isTrustedPackageVersion(cfg.TrustedPackages, &packagev1.PackageVersion{
				Package: &packagev1.Package{Ecosystem: tt.ecosystem, Name: "demo"}, Version: tt.version,
			}))
		})
	}
}

func TestPypiPackageRefSpellings(t *testing.T) {
	cfg := &Config{
		TrustedPackages:    []TrustedPackage{{Purl: "pkg:pypi/calcboxlite@1.0"}},
		DependencyCooldown: DependencyCooldownConfig{Skip: []TrustedPackage{{Purl: "pkg:pypi/calcboxlite@1.0"}}},
	}
	require.NoError(t, preprocessPackageRefs(cfg))

	for _, tt := range []struct {
		name, version string
		want          bool
	}{
		{"calcboxlite", "1.0", true},
		{"calcboxlite", "1.0.0", true},
		{"calcboxlite", "01.0", true},
		{"calcboxlite", "v1.0", true},
		{"calcboxlite", "0!1.0", true},
		{"CalcBoxLite", "1.0.0", true},
		{"CALCBOXLITE", "1.0", true},
		{"calcboxlite", "1.0rc1", false},
		{"calcboxlite", "1!1.0", false},
		{"calcboxlite", "1.0.1", false},
		{"calc-box-lite", "1.0", false},
		{"calc_box_lite", "v1.0", false},
	} {
		t.Run(tt.name+"@"+tt.version, func(t *testing.T) {
			assert.Equal(t, tt.want, isTrustedPackageVersion(cfg.TrustedPackages, &packagev1.PackageVersion{
				Package: &packagev1.Package{Ecosystem: packagev1.Ecosystem_ECOSYSTEM_PYPI, Name: tt.name}, Version: tt.version,
			}))
			assert.Equal(t, tt.want, cooldownSkip(cfg.DependencyCooldown.Skip, packagev1.Ecosystem_ECOSYSTEM_PYPI, tt.name).ExemptsVersion(tt.version))
		})
	}
}

func TestPypiPackageRefNameFold(t *testing.T) {
	for _, tt := range []struct {
		purl, name, version string
		want                bool
	}{
		{"pkg:pypi/calc-box-lite@1.0", "calc_box_lite", "v1.0", true},
		{"pkg:pypi/calc-box-lite@1.0", "Calc.Box_Lite", "1.0.0", true},
		{"pkg:pypi/calc-box-lite@1.0", "calc--box--lite", "1", true},
		{"pkg:pypi/calc-box-lite@1.0", "calcboxlite", "1.0", false},
		{"pkg:pypi/zope.interface@5.0", "zope-interface", "5", true},
	} {
		t.Run(tt.purl+"/"+tt.name+"@"+tt.version, func(t *testing.T) {
			cfg := &Config{
				TrustedPackages:    []TrustedPackage{{Purl: tt.purl}},
				DependencyCooldown: DependencyCooldownConfig{Skip: []TrustedPackage{{Purl: tt.purl}}},
			}
			require.NoError(t, preprocessPackageRefs(cfg))
			assert.Equal(t, tt.want, isTrustedPackageVersion(cfg.TrustedPackages, &packagev1.PackageVersion{
				Package: &packagev1.Package{Ecosystem: packagev1.Ecosystem_ECOSYSTEM_PYPI, Name: tt.name}, Version: tt.version,
			}))
			assert.Equal(t, tt.want, cooldownSkip(cfg.DependencyCooldown.Skip, packagev1.Ecosystem_ECOSYSTEM_PYPI, tt.name).ExemptsVersion(tt.version))
		})
	}
}
