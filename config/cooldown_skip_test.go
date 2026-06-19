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
		reason      CooldownSkipReason
		wantSkipAll bool
		wantVers    map[string]bool
	}{
		{
			name:      "empty skip list",
			skip:      []TrustedPackage{},
			ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
			pkgName:   "internal-sdk",
			reason:    CooldownSkipReasonCooldownSkipList,
		},
		{
			name:      "empty package name",
			skip:      []TrustedPackage{{Purl: "pkg:npm/internal-sdk"}},
			ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
			pkgName:   "",
			reason:    CooldownSkipReasonCooldownSkipList,
		},
		{
			name:        "version-less entry skips all versions",
			skip:        []TrustedPackage{{Purl: "pkg:npm/internal-sdk", Reason: "first-party"}},
			ecosystem:   packagev1.Ecosystem_ECOSYSTEM_NPM,
			pkgName:     "internal-sdk",
			reason:      CooldownSkipReasonCooldownSkipList,
			wantSkipAll: true,
		},
		{
			name:      "version-pinned entry skips only that version",
			skip:      []TrustedPackage{{Purl: "pkg:npm/internal-sdk@1.2.3", Reason: "first-party"}},
			ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
			pkgName:   "internal-sdk",
			reason:    CooldownSkipReasonCooldownSkipList,
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
			reason:    CooldownSkipReasonCooldownSkipList,
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
			reason:      CooldownSkipReasonCooldownSkipList,
			wantSkipAll: true,
		},
		{
			name:      "name mismatch",
			skip:      []TrustedPackage{{Purl: "pkg:npm/internal-sdk"}},
			ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
			pkgName:   "express",
			reason:    CooldownSkipReasonCooldownSkipList,
		},
		{
			name:      "ecosystem mismatch",
			skip:      []TrustedPackage{{Purl: "pkg:pypi/internal-tool"}},
			ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
			pkgName:   "internal-tool",
			reason:    CooldownSkipReasonCooldownSkipList,
		},
		{
			name:        "pypi version-less entry",
			skip:        []TrustedPackage{{Purl: "pkg:pypi/internal-tool"}},
			ecosystem:   packagev1.Ecosystem_ECOSYSTEM_PYPI,
			pkgName:     "internal-tool",
			reason:      CooldownSkipReasonCooldownSkipList,
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
			reason:      CooldownSkipReasonCooldownSkipList,
			wantSkipAll: true,
		},
		{
			name:        "trusted-packages reason tags SkipAll",
			skip:        []TrustedPackage{{Purl: "pkg:npm/fully-trusted"}},
			ecosystem:   packagev1.Ecosystem_ECOSYSTEM_NPM,
			pkgName:     "fully-trusted",
			reason:      CooldownSkipReasonTrustedPackage,
			wantSkipAll: true,
		},
		{
			name:      "trusted-packages reason tags per-version entry",
			skip:      []TrustedPackage{{Purl: "pkg:npm/trusted-pinned@2.0.0"}},
			ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
			pkgName:   "trusted-pinned",
			reason:    CooldownSkipReasonTrustedPackage,
			wantVers:  map[string]bool{"2.0.0": true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{DependencyCooldown: DependencyCooldownConfig{Skip: tt.skip}}
			_ = preprocessTrustedPackages(cfg)

			got := collectCooldownSkip(cfg.DependencyCooldown.Skip, tt.ecosystem, tt.pkgName, tt.reason)
			assert.Equal(t, tt.wantSkipAll, got.SkipAll)
			assert.Equal(t, tt.wantVers, got.VersionSet())

			if tt.wantSkipAll {
				assert.Equal(t, tt.reason, got.SkipReason, "SkipAll match must carry the passed-in reason")
			}
			for v, r := range got.Versions {
				assert.Equal(t, tt.reason, r, "version %q must carry the passed-in reason", v)
			}
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
// tagged with the trusted_packages reason. trusted_packages takes precedence
// over the cooldown skip list whenever both cover the same package or version.
func TestCooldownSkipRespectsTrustedPackages(t *testing.T) {
	cfg := &Config{
		TrustedPackages: []TrustedPackage{
			{Purl: "pkg:npm/fully-trusted", Reason: "waives everything"},
			{Purl: "pkg:npm/trusted-pinned@2.0.0", Reason: "waives everything for 2.0.0"},
			{Purl: "pkg:npm/overlap-pkg", Reason: "trusted; broader waiver"},
			{Purl: "pkg:npm/overlap-version@3.0.0", Reason: "trusted; broader waiver"},
		},
		DependencyCooldown: DependencyCooldownConfig{
			Skip: []TrustedPackage{
				{Purl: "pkg:npm/cooldown-skipped", Reason: "waives cooldown only"},
				{Purl: "pkg:npm/overlap-pkg", Reason: "also on cooldown skip list"},
				{Purl: "pkg:npm/overlap-version@3.0.0", Reason: "also on cooldown skip list"},
			},
		},
	}
	_ = preprocessTrustedPackages(cfg)

	skipFor := func(name string) CooldownSkipInfo {
		trusted := collectCooldownSkip(cfg.TrustedPackages, packagev1.Ecosystem_ECOSYSTEM_NPM, name, CooldownSkipReasonTrustedPackage)
		if trusted.SkipAll {
			return trusted
		}
		dc := collectCooldownSkip(cfg.DependencyCooldown.Skip, packagev1.Ecosystem_ECOSYSTEM_NPM, name, CooldownSkipReasonCooldownSkipList)
		return mergeCooldownSkip(trusted, dc)
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
	gotSkip := skipFor("cooldown-skipped")
	assert.True(t, gotSkip.SkipAll, "cooldown-skipped package must skip the cooldown window")
	assert.Equal(t, CooldownSkipReasonCooldownSkipList, gotSkip.SkipReason)

	// Globally-trusted package waives malware analysis AND cooldown.
	assert.True(t, isTrustedPackageVersion(cfg.TrustedPackages, fullyTrusted),
		"trusted package must waive malware analysis")
	gotTrusted := skipFor("fully-trusted")
	assert.True(t, gotTrusted.SkipAll, "trusted package must also skip the cooldown window")
	assert.Equal(t, CooldownSkipReasonTrustedPackage, gotTrusted.SkipReason)

	// Version-pinned trusted entry skips cooldown only for that exact version,
	// and the version carries the trusted_packages reason.
	pinned := skipFor("trusted-pinned")
	assert.False(t, pinned.SkipAll)
	assert.True(t, pinned.ExemptsVersion("2.0.0"))
	assert.False(t, pinned.ExemptsVersion("2.0.1"))
	assert.Equal(t, CooldownSkipReasonTrustedPackage, pinned.Versions["2.0.0"])

	// Package is in both lists with no version: trusted_packages reason wins.
	overlap := skipFor("overlap-pkg")
	assert.True(t, overlap.SkipAll)
	assert.Equal(t, CooldownSkipReasonTrustedPackage, overlap.SkipReason)

	// Same version is in both lists: trusted_packages reason wins.
	overlapVer := skipFor("overlap-version")
	assert.False(t, overlapVer.SkipAll)
	assert.Equal(t, CooldownSkipReasonTrustedPackage, overlapVer.Versions["3.0.0"])

	// Disjoint pinned entries from both lists must both survive the merge,
	// each carrying the reason of the list it came from.
	cfgDisjoint := &Config{
		TrustedPackages:    []TrustedPackage{{Purl: "pkg:npm/disjoint-pkg@1.0.0"}},
		DependencyCooldown: DependencyCooldownConfig{Skip: []TrustedPackage{{Purl: "pkg:npm/disjoint-pkg@2.0.0"}}},
	}
	_ = preprocessTrustedPackages(cfgDisjoint)
	trustedDis := collectCooldownSkip(cfgDisjoint.TrustedPackages, packagev1.Ecosystem_ECOSYSTEM_NPM, "disjoint-pkg", CooldownSkipReasonTrustedPackage)
	dcDis := collectCooldownSkip(cfgDisjoint.DependencyCooldown.Skip, packagev1.Ecosystem_ECOSYSTEM_NPM, "disjoint-pkg", CooldownSkipReasonCooldownSkipList)
	disjoint := mergeCooldownSkip(trustedDis, dcDis)
	assert.False(t, disjoint.SkipAll)
	assert.True(t, disjoint.ExemptsVersion("1.0.0"))
	assert.True(t, disjoint.ExemptsVersion("2.0.0"))
	assert.False(t, disjoint.ExemptsVersion("3.0.0"))
	assert.Equal(t, CooldownSkipReasonTrustedPackage, disjoint.Versions["1.0.0"])
	assert.Equal(t, CooldownSkipReasonCooldownSkipList, disjoint.Versions["2.0.0"])

	// DC version-less covers every version, so the trusted pinned entry is
	// subsumed; SkipAll wins and carries the DC reason.
	cfgDcAll := &Config{
		TrustedPackages:    []TrustedPackage{{Purl: "pkg:npm/dc-all-pkg@1.0.0"}},
		DependencyCooldown: DependencyCooldownConfig{Skip: []TrustedPackage{{Purl: "pkg:npm/dc-all-pkg"}}},
	}
	_ = preprocessTrustedPackages(cfgDcAll)
	trustedDcAll := collectCooldownSkip(cfgDcAll.TrustedPackages, packagev1.Ecosystem_ECOSYSTEM_NPM, "dc-all-pkg", CooldownSkipReasonTrustedPackage)
	dcAll := collectCooldownSkip(cfgDcAll.DependencyCooldown.Skip, packagev1.Ecosystem_ECOSYSTEM_NPM, "dc-all-pkg", CooldownSkipReasonCooldownSkipList)
	dcAllMerged := mergeCooldownSkip(trustedDcAll, dcAll)
	assert.True(t, dcAllMerged.SkipAll)
	assert.Equal(t, CooldownSkipReasonCooldownSkipList, dcAllMerged.SkipReason)

	// Trusted version-less entry shadows a per-version entry from the other list.
	cfg2 := &Config{
		TrustedPackages:    []TrustedPackage{{Purl: "pkg:npm/shadow-pkg"}},
		DependencyCooldown: DependencyCooldownConfig{Skip: []TrustedPackage{{Purl: "pkg:npm/shadow-pkg@1.0.0"}}},
	}
	_ = preprocessTrustedPackages(cfg2)
	trustedShadow := collectCooldownSkip(cfg2.TrustedPackages, packagev1.Ecosystem_ECOSYSTEM_NPM, "shadow-pkg", CooldownSkipReasonTrustedPackage)
	dcShadow := collectCooldownSkip(cfg2.DependencyCooldown.Skip, packagev1.Ecosystem_ECOSYSTEM_NPM, "shadow-pkg", CooldownSkipReasonCooldownSkipList)
	shadowed := mergeCooldownSkip(trustedShadow, dcShadow)
	assert.True(t, shadowed.SkipAll)
	assert.Equal(t, CooldownSkipReasonTrustedPackage, shadowed.SkipReason)
	assert.Nil(t, shadowed.Versions, "version-less SkipAll must clear per-version entries")
}

func TestCooldownSkipReasonString(t *testing.T) {
	assert.Equal(t, "trusted_packages", CooldownSkipReasonTrustedPackage.String())
	assert.Equal(t, "dependency_cooldown.skip", CooldownSkipReasonCooldownSkipList.String())
	assert.Equal(t, "none", CooldownSkipReasonNone.String())
}
