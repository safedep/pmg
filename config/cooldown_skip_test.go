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

			got := cooldownSkip(cfg.DependencyCooldown.Skip, tt.ecosystem, tt.pkgName)
			assert.Equal(t, tt.wantSkipAll, got.SkipAll)
			assert.Equal(t, tt.wantVers, got.VersionSet())
		})
	}
}

func TestCooldownSkipInfo_ExemptsVersion(t *testing.T) {
	skipAll := CooldownSkipInfo{SkipAll: true}
	assert.True(t, skipAll.ExemptsVersion("9.9.9"), "skip-all exempts any version")

	pinned := CooldownSkipInfo{Versions: map[string]CooldownSkipReason{"1.2.3": CooldownSkipReasonCooldownSkipList}}
	assert.True(t, pinned.ExemptsVersion("1.2.3"))
	assert.False(t, pinned.ExemptsVersion("1.2.4"))

	none := CooldownSkipInfo{}
	assert.False(t, none.ExemptsVersion("1.0.0"))
}

// TestCooldownSkipRespectsTrustedPackages verifies that the top-level
// trusted_packages list is a superset waiver: a trusted package waives both
// malware analysis AND the cooldown window, and the resulting skip info is
// tagged with the trusted_packages reason so the interceptor can audit-log it
// correctly. The dependency_cooldown.skip list remains the narrower,
// cooldown-only waiver.
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

	merge := func(name string) CooldownSkipInfo {
		return mergeCooldownSkip(
			cooldownSkip(cfg.TrustedPackages, packagev1.Ecosystem_ECOSYSTEM_NPM, name),
			cooldownSkip(cfg.DependencyCooldown.Skip, packagev1.Ecosystem_ECOSYSTEM_NPM, name),
		)
	}

	cooldownSkipped := &packagev1.PackageVersion{
		Package: &packagev1.Package{Name: "cooldown-skipped", Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM},
		Version: "1.0.0",
	}
	fullyTrusted := &packagev1.PackageVersion{
		Package: &packagev1.Package{Name: "fully-trusted", Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM},
		Version: "1.0.0",
	}

	// Cooldown-skip-only package is still malware-analyzed (not in trusted_packages)
	// and its skip info is tagged with the cooldown-skip-list reason.
	assert.False(t, isTrustedPackageVersion(cfg.TrustedPackages, cooldownSkipped),
		"cooldown-skipped package must NOT waive malware analysis")
	gotSkip := merge("cooldown-skipped")
	assert.True(t, gotSkip.SkipAll, "cooldown-skipped package must skip the cooldown window")
	assert.Equal(t, CooldownSkipReasonCooldownSkipList, gotSkip.SkipAllReason)

	// Globally-trusted package waives malware analysis AND cooldown.
	assert.True(t, isTrustedPackageVersion(cfg.TrustedPackages, fullyTrusted),
		"trusted package must waive malware analysis")
	gotTrusted := merge("fully-trusted")
	assert.True(t, gotTrusted.SkipAll, "trusted package must also skip the cooldown window")
	assert.Equal(t, CooldownSkipReasonTrustedPackage, gotTrusted.SkipAllReason)

	// Version-pinned trusted entry skips cooldown only for that exact version,
	// and the version carries the trusted_packages reason.
	pinned := merge("trusted-pinned")
	assert.False(t, pinned.SkipAll)
	assert.True(t, pinned.ExemptsVersion("2.0.0"))
	assert.False(t, pinned.ExemptsVersion("2.0.1"))
	assert.Equal(t, CooldownSkipReasonTrustedPackage, pinned.Versions["2.0.0"])
}

// TestMergeCooldownSkipPrefersTrusted verifies trusted_packages always wins
// when both lists exempt the same package or version.
func TestMergeCooldownSkipPrefersTrusted(t *testing.T) {
	t.Run("SkipAll in both: trusted wins", func(t *testing.T) {
		trusted := CooldownSkipInfo{SkipAll: true}
		other := CooldownSkipInfo{SkipAll: true}
		got := mergeCooldownSkip(trusted, other)
		assert.True(t, got.SkipAll)
		assert.Equal(t, CooldownSkipReasonTrustedPackage, got.SkipAllReason)
	})

	t.Run("SkipAll only in cooldown list", func(t *testing.T) {
		got := mergeCooldownSkip(CooldownSkipInfo{}, CooldownSkipInfo{SkipAll: true})
		assert.True(t, got.SkipAll)
		assert.Equal(t, CooldownSkipReasonCooldownSkipList, got.SkipAllReason)
	})

	t.Run("trusted SkipAll shadows pinned cooldown entries", func(t *testing.T) {
		trusted := CooldownSkipInfo{SkipAll: true}
		other := CooldownSkipInfo{Versions: map[string]CooldownSkipReason{"1.0.0": CooldownSkipReasonNone}}
		got := mergeCooldownSkip(trusted, other)
		assert.True(t, got.SkipAll)
		assert.Equal(t, CooldownSkipReasonTrustedPackage, got.SkipAllReason)
		assert.Nil(t, got.Versions)
	})

	t.Run("same version in both: trusted wins", func(t *testing.T) {
		trusted := CooldownSkipInfo{Versions: map[string]CooldownSkipReason{"1.2.3": CooldownSkipReasonNone}}
		other := CooldownSkipInfo{Versions: map[string]CooldownSkipReason{"1.2.3": CooldownSkipReasonNone}}
		got := mergeCooldownSkip(trusted, other)
		assert.Equal(t, CooldownSkipReasonTrustedPackage, got.Versions["1.2.3"])
	})

	t.Run("disjoint versions tagged per source list", func(t *testing.T) {
		trusted := CooldownSkipInfo{Versions: map[string]CooldownSkipReason{"1.0.0": CooldownSkipReasonNone}}
		other := CooldownSkipInfo{Versions: map[string]CooldownSkipReason{"2.0.0": CooldownSkipReasonNone}}
		got := mergeCooldownSkip(trusted, other)
		assert.Equal(t, CooldownSkipReasonTrustedPackage, got.Versions["1.0.0"])
		assert.Equal(t, CooldownSkipReasonCooldownSkipList, got.Versions["2.0.0"])
	})
}

func TestCooldownSkipReasonString(t *testing.T) {
	assert.Equal(t, "trusted_packages", CooldownSkipReasonTrustedPackage.String())
	assert.Equal(t, "dependency_cooldown.skip", CooldownSkipReasonCooldownSkipList.String())
	assert.Equal(t, "none", CooldownSkipReasonNone.String())
}
