package config

import (
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/stretchr/testify/assert"
)

func setGlobalForTest(t *testing.T, cfg *Config) {
	t.Helper()
	prev := globalConfig
	globalConfig = &RuntimeConfig{Config: *cfg}
	t.Cleanup(func() { globalConfig = prev })
}

func TestIsTrustedPackageRef(t *testing.T) {
	cfg := &Config{TrustedPackages: []TrustedPackage{
		{Purl: "pkg:npm/all-versions"},
		{Purl: "pkg:npm/pinned@1.0.0"},
	}}
	_ = preprocessTrustedPackages(cfg)
	setGlobalForTest(t, cfg)

	assert.True(t, IsTrustedPackageRef(packagev1.Ecosystem_ECOSYSTEM_NPM, "all-versions", "9.9.9"))
	assert.True(t, IsTrustedPackageRef(packagev1.Ecosystem_ECOSYSTEM_NPM, "pinned", "1.0.0"))
	assert.False(t, IsTrustedPackageRef(packagev1.Ecosystem_ECOSYSTEM_NPM, "pinned", "2.0.0"))
	assert.False(t, IsTrustedPackageRef(packagev1.Ecosystem_ECOSYSTEM_NPM, "other", "1.0.0"))
}

func TestIsTrustedPackageAllVersions(t *testing.T) {
	cfg := &Config{TrustedPackages: []TrustedPackage{
		{Purl: "pkg:npm/all-versions"},
		{Purl: "pkg:npm/pinned@1.0.0"},
	}}
	_ = preprocessTrustedPackages(cfg)
	setGlobalForTest(t, cfg)

	assert.True(t, IsTrustedPackageAllVersions(packagev1.Ecosystem_ECOSYSTEM_NPM, "all-versions"))
	assert.False(t, IsTrustedPackageAllVersions(packagev1.Ecosystem_ECOSYSTEM_NPM, "pinned"))
	assert.False(t, IsTrustedPackageAllVersions(packagev1.Ecosystem_ECOSYSTEM_NPM, "absent"))
}

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

func TestCooldownSkipIsSkipListOnly(t *testing.T) {
	cfg := &Config{
		TrustedPackages:    []TrustedPackage{{Purl: "pkg:npm/trusted-only"}},
		DependencyCooldown: DependencyCooldownConfig{Skip: []TrustedPackage{{Purl: "pkg:npm/cooldown-only"}}},
	}
	_ = preprocessTrustedPackages(cfg)
	setGlobalForTest(t, cfg)

	assert.False(t, CooldownSkip(packagev1.Ecosystem_ECOSYSTEM_NPM, "trusted-only").SkipAll, "trusted_packages must not leak into CooldownSkip")
	assert.True(t, CooldownSkip(packagev1.Ecosystem_ECOSYSTEM_NPM, "cooldown-only").SkipAll)
}
