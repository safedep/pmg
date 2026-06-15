package config

import (
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/stretchr/testify/assert"
)

func TestCooldownSkip(t *testing.T) {
	tests := []struct {
		name        string
		skip        []TrustedPackage
		ecosystem   packagev1.Ecosystem
		pkgName     string
		wantSkipAll bool
		wantVers    map[string]bool
	}{
		{
			name:      "empty skip list",
			skip:      []TrustedPackage{},
			ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
			pkgName:   "internal-sdk",
		},
		{
			name:      "empty package name",
			skip:      []TrustedPackage{{Purl: "pkg:npm/internal-sdk"}},
			ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
			pkgName:   "",
		},
		{
			name:        "version-less entry skips all versions",
			skip:        []TrustedPackage{{Purl: "pkg:npm/internal-sdk", Reason: "first-party"}},
			ecosystem:   packagev1.Ecosystem_ECOSYSTEM_NPM,
			pkgName:     "internal-sdk",
			wantSkipAll: true,
		},
		{
			name:      "version-pinned entry skips only that version",
			skip:      []TrustedPackage{{Purl: "pkg:npm/internal-sdk@1.2.3", Reason: "first-party"}},
			ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
			pkgName:   "internal-sdk",
			wantVers:  map[string]bool{"1.2.3": true},
		},
		{
			name: "multiple version-pinned entries",
			skip: []TrustedPackage{
				{Purl: "pkg:npm/internal-sdk@1.2.3"},
				{Purl: "pkg:npm/internal-sdk@1.3.0"},
			},
			ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
			pkgName:   "internal-sdk",
			wantVers:  map[string]bool{"1.2.3": true, "1.3.0": true},
		},
		{
			name: "version-less wins over version-pinned for same package",
			skip: []TrustedPackage{
				{Purl: "pkg:npm/internal-sdk@1.2.3"},
				{Purl: "pkg:npm/internal-sdk"},
			},
			ecosystem:   packagev1.Ecosystem_ECOSYSTEM_NPM,
			pkgName:     "internal-sdk",
			wantSkipAll: true,
		},
		{
			name:      "name mismatch",
			skip:      []TrustedPackage{{Purl: "pkg:npm/internal-sdk"}},
			ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
			pkgName:   "express",
		},
		{
			name:      "ecosystem mismatch",
			skip:      []TrustedPackage{{Purl: "pkg:pypi/internal-tool"}},
			ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
			pkgName:   "internal-tool",
		},
		{
			name:        "pypi version-less entry",
			skip:        []TrustedPackage{{Purl: "pkg:pypi/internal-tool"}},
			ecosystem:   packagev1.Ecosystem_ECOSYSTEM_PYPI,
			pkgName:     "internal-tool",
			wantSkipAll: true,
		},
		{
			name: "invalid purl skipped, valid match still found",
			skip: []TrustedPackage{
				{Purl: "invalid-purl"},
				{Purl: "pkg:npm/internal-sdk"},
			},
			ecosystem:   packagev1.Ecosystem_ECOSYSTEM_NPM,
			pkgName:     "internal-sdk",
			wantSkipAll: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{DependencyCooldown: DependencyCooldownConfig{Skip: tt.skip}}
			_ = preprocessTrustedPackages(cfg)

			got := cooldownSkip(cfg.TrustedPackages, cfg.DependencyCooldown.Skip, tt.ecosystem, tt.pkgName)
			assert.Equal(t, tt.wantSkipAll, got.SkipAll)
			assert.Equal(t, tt.wantVers, got.Versions)
		})
	}
}

func TestCooldownSkipInfo_ExemptsVersion(t *testing.T) {
	skipAll := CooldownSkipInfo{SkipAll: true}
	assert.True(t, skipAll.ExemptsVersion("9.9.9"), "skip-all exempts any version")

	pinned := CooldownSkipInfo{Versions: map[string]bool{"1.2.3": true}}
	assert.True(t, pinned.ExemptsVersion("1.2.3"))
	assert.False(t, pinned.ExemptsVersion("1.2.4"))

	none := CooldownSkipInfo{}
	assert.False(t, none.ExemptsVersion("1.0.0"))
}

// TestCooldownSkipRespectsTrustedPackages verifies that the top-level
// trusted_packages list is a superset waiver: a trusted package waives both
// malware analysis AND the cooldown window. The dependency_cooldown.skip list
// is the narrower, cooldown-only waiver and does NOT waive malware analysis.
func TestCooldownSkipRespectsTrustedPackages(t *testing.T) {
	cfg := &Config{
		TrustedPackages: []TrustedPackage{
			{Purl: "pkg:npm/fully-trusted", Reason: "waives everything"},
			{Purl: "pkg:npm/trusted-pinned@2.0.0", Reason: "waives everything for 2.0.0"},
		},
		DependencyCooldown: DependencyCooldownConfig{
			Skip: []TrustedPackage{
				{Purl: "pkg:npm/cooldown-skipped", Reason: "waives cooldown only"},
			},
		},
	}
	_ = preprocessTrustedPackages(cfg)

	cooldownSkipped := &packagev1.PackageVersion{
		Package: &packagev1.Package{Name: "cooldown-skipped", Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM},
		Version: "1.0.0",
	}
	fullyTrusted := &packagev1.PackageVersion{
		Package: &packagev1.Package{Name: "fully-trusted", Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM},
		Version: "1.0.0",
	}

	// Cooldown-skip-only package is still malware-analyzed (not in trusted_packages).
	assert.False(t, isTrustedPackageVersion(cfg.TrustedPackages, cooldownSkipped),
		"cooldown-skipped package must NOT waive malware analysis")
	assert.True(t, cooldownSkip(cfg.TrustedPackages, cfg.DependencyCooldown.Skip, packagev1.Ecosystem_ECOSYSTEM_NPM, "cooldown-skipped").SkipAll,
		"cooldown-skipped package must skip the cooldown window")

	// Globally-trusted package waives malware analysis AND cooldown.
	assert.True(t, isTrustedPackageVersion(cfg.TrustedPackages, fullyTrusted),
		"trusted package must waive malware analysis")
	assert.True(t, cooldownSkip(cfg.TrustedPackages, cfg.DependencyCooldown.Skip, packagev1.Ecosystem_ECOSYSTEM_NPM, "fully-trusted").SkipAll,
		"trusted package must also skip the cooldown window")

	// Version-pinned trusted entry skips cooldown only for that exact version.
	pinned := cooldownSkip(cfg.TrustedPackages, cfg.DependencyCooldown.Skip, packagev1.Ecosystem_ECOSYSTEM_NPM, "trusted-pinned")
	assert.False(t, pinned.SkipAll)
	assert.True(t, pinned.ExemptsVersion("2.0.0"))
	assert.False(t, pinned.ExemptsVersion("2.0.1"))
}
