package guard

import (
	"context"
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/packagemanager"
	"github.com/stretchr/testify/assert"
)

func TestGuardConcurrentlyAnalyzePackagesMalwareQueryService(t *testing.T) {
	mq, err := analyzer.NewMalysisQueryAnalyzer(analyzer.MalysisQueryAnalyzerConfig{})
	if err != nil {
		t.Fatalf("failed to create mq: %v", err)
	}

	pg, err := NewPackageManagerGuard(DefaultPackageManagerGuardConfig(), nil, nil,
		[]analyzer.PackageVersionAnalyzer{mq}, PackageManagerGuardInteraction{
			ShowWarning: func(message string) {},
		})
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

func TestGuardInsecureInstallation(t *testing.T) {
	mq, err := analyzer.NewMalysisQueryAnalyzer(analyzer.MalysisQueryAnalyzerConfig{})
	if err != nil {
		t.Fatalf("failed to create mq: %v", err)
	}

	t.Run("should bypass malware blocking when InsecureInstallation is enabled", func(t *testing.T) {
		// Create guard with InsecureInstallation enabled
		config := DefaultPackageManagerGuardConfig()
		config.InsecureInstallation = true
		config.DryRun = true               // Enable dry run to avoid actual command execution
		config.ResolveDependencies = false // Disable dependency resolution to avoid nil pointer issues

		blockCalled := false
		warningCalled := false
		var warningMessage string

		interaction := PackageManagerGuardInteraction{
			ShowWarning: func(message string) {
				warningCalled = true
				warningMessage = message
			},
			Block: func(config *ui.BlockConfig) error {
				blockCalled = true
				return nil
			},
		}

		pg, err := NewPackageManagerGuard(config, nil, nil,
			[]analyzer.PackageVersionAnalyzer{mq}, interaction)
		if err != nil {
			t.Fatalf("failed to create pg: %v", err)
		}

		// Create a parsed command with a known malicious package
		parsedCommand := &packagemanager.ParsedCommand{
			Command: packagemanager.Command{
				Exe:  "npm",
				Args: []string{"install", "nyc-config@10.0.0"},
			},
			InstallTargets: []*packagemanager.PackageInstallTarget{
				{
					PackageVersion: &packagev1.PackageVersion{
						Package: &packagev1.Package{
							Name:      "nyc-config",
							Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
						},
						Version: "10.0.0",
					},
				},
			},
		}

		err = pg.Run(context.Background(), []string{"npm", "install", "nyc-config@10.0.0"}, parsedCommand)

		// With dry run enabled, we expect no error even though we're bypassing execution
		assert.NoError(t, err)

		// Block should not be called because InsecureInstallation bypasses the analysis
		assert.False(t, blockCalled, "Block should not be called when InsecureInstallation is enabled")

		// Warning should be called to inform user about insecure installation
		assert.True(t, warningCalled, "Warning should be called when InsecureInstallation is enabled")
		assert.Contains(t, warningMessage, "INSECURE INSTALLATION MODE", "Warning message should mention insecure installation")
	})

	t.Run("should block malware when InsecureInstallation is disabled", func(t *testing.T) {
		// Create guard with InsecureInstallation disabled (default)
		config := DefaultPackageManagerGuardConfig()
		config.InsecureInstallation = false
		config.DryRun = true
		config.ResolveDependencies = false // Disable dependency resolution to avoid nil pointer issues

		blockCalled := false
		var blockedPackages []*analyzer.PackageVersionAnalysisResult

		interaction := PackageManagerGuardInteraction{
			ShowWarning: func(message string) {},
			Block: func(config *ui.BlockConfig) error {
				blockCalled = true
				blockedPackages = config.MalwarePackages
				return nil
			},
		}

		pg, err := NewPackageManagerGuard(config, nil, nil,
			[]analyzer.PackageVersionAnalyzer{mq}, interaction)
		if err != nil {
			t.Fatalf("failed to create pg: %v", err)
		}

		// Create a parsed command with a known malicious package
		parsedCommand := &packagemanager.ParsedCommand{
			Command: packagemanager.Command{
				Exe:  "npm",
				Args: []string{"install", "nyc-config@10.0.0"},
			},
			InstallTargets: []*packagemanager.PackageInstallTarget{
				{
					PackageVersion: &packagev1.PackageVersion{
						Package: &packagev1.Package{
							Name:      "nyc-config",
							Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
						},
						Version: "10.0.0",
					},
				},
			},
		}

		err = pg.Run(context.Background(), []string{"npm", "install", "nyc-config@10.0.0"}, parsedCommand)

		// We expect no error from the guard itself (blocking is handled via the Block callback)
		assert.NoError(t, err)

		// Block should be called because InsecureInstallation is disabled
		assert.True(t, blockCalled, "Block should be called when InsecureInstallation is disabled")

		// Verify that the malicious package was detected and blocked
		assert.NotEmpty(t, blockedPackages, "Blocked packages should not be empty")
		if len(blockedPackages) > 0 {
			assert.Equal(t, "nyc-config", blockedPackages[0].PackageVersion.GetPackage().GetName())
			assert.Equal(t, "10.0.0", blockedPackages[0].PackageVersion.GetVersion())
			assert.Equal(t, analyzer.ActionBlock, blockedPackages[0].Action)
		}
	})

	t.Run("should continue execution for commands without install targets when InsecureInstallation is enabled", func(t *testing.T) {
		// Create guard with InsecureInstallation enabled
		config := DefaultPackageManagerGuardConfig()
		config.InsecureInstallation = true
		config.DryRun = true
		config.ResolveDependencies = false // Disable dependency resolution to avoid nil pointer issues

		blockCalled := false

		interaction := PackageManagerGuardInteraction{
			ShowWarning: func(message string) {},
			Block: func(config *ui.BlockConfig) error {
				blockCalled = true
				return nil
			},
		}

		pg, err := NewPackageManagerGuard(config, nil, nil,
			[]analyzer.PackageVersionAnalyzer{mq}, interaction)
		if err != nil {
			t.Fatalf("failed to create pg: %v", err)
		}

		// Create a parsed command without install targets (e.g., npm list)
		parsedCommand := &packagemanager.ParsedCommand{
			Command: packagemanager.Command{
				Exe:  "npm",
				Args: []string{"list"},
			},
			InstallTargets: []*packagemanager.PackageInstallTarget{}, // No install targets
		}

		err = pg.Run(context.Background(), []string{"npm", "list"}, parsedCommand)

		// Should not error since there are no install targets to analyze
		assert.NoError(t, err)

		// Block should not be called since there are no packages to analyze
		assert.False(t, blockCalled, "Block should not be called when there are no install targets")
	})

	t.Run("should handle manifest-based installation when InsecureInstallation is enabled", func(t *testing.T) {
		// Create guard with InsecureInstallation enabled
		config := DefaultPackageManagerGuardConfig()
		config.InsecureInstallation = true
		config.DryRun = true
		config.ResolveDependencies = false // Disable dependency resolution to avoid nil pointer issues

		blockCalled := false

		interaction := PackageManagerGuardInteraction{
			ShowWarning: func(message string) {},
			Block: func(config *ui.BlockConfig) error {
				blockCalled = true
				return nil
			},
		}

		pg, err := NewPackageManagerGuard(config, nil, nil,
			[]analyzer.PackageVersionAnalyzer{mq}, interaction)
		if err != nil {
			t.Fatalf("failed to create pg: %v", err)
		}

		// Create a parsed command for manifest-based installation
		parsedCommand := &packagemanager.ParsedCommand{
			Command: packagemanager.Command{
				Exe:  "npm",
				Args: []string{"install"},
			},
			InstallTargets:    []*packagemanager.PackageInstallTarget{}, // No direct install targets
			IsManifestInstall: true,
			ManifestFiles:     []string{"package.json"},
		}

		err = pg.Run(context.Background(), []string{"npm", "install"}, parsedCommand)

		// Should not error and should bypass malware checking
		assert.NoError(t, err)

		// Block should not be called because InsecureInstallation bypasses analysis
		assert.False(t, blockCalled, "Block should not be called when InsecureInstallation is enabled for manifest installation")
	})

	t.Run("should verify InsecureInstallation defaults to false", func(t *testing.T) {
		config := DefaultPackageManagerGuardConfig()

		// Verify that InsecureInstallation defaults to false
		assert.False(t, config.InsecureInstallation, "InsecureInstallation should default to false")
	})
}

func TestGuardIsTrustedPackageVersion(t *testing.T) {
	tests := []struct {
		name            string
		trustedPackages []config.TrustedPackage
		pkgVersion      *packagev1.PackageVersion
		want            bool
	}{
		{
			name:            "nil package version returns false",
			trustedPackages: []config.TrustedPackage{},
			pkgVersion:      nil,
			want:            false,
		},
		{
			name:            "empty trusted packages list returns false",
			trustedPackages: []config.TrustedPackage{},
			pkgVersion: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Name:      "express",
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
				},
				Version: "4.18.0",
			},
			want: false,
		},
		{
			name: "exact match with version returns true",
			trustedPackages: []config.TrustedPackage{
				{
					Purl:   "pkg:npm/express@4.18.0",
					Reason: "trusted by team",
				},
			},
			pkgVersion: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Name:      "express",
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
				},
				Version: "4.18.0",
			},
			want: true,
		},
		{
			name: "match without version in trusted package returns true",
			trustedPackages: []config.TrustedPackage{
				{
					Purl:   "pkg:npm/express",
					Reason: "all versions trusted",
				},
			},
			pkgVersion: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Name:      "express",
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
				},
				Version: "4.18.0",
			},
			want: true,
		},
		{
			name: "version mismatch returns false",
			trustedPackages: []config.TrustedPackage{
				{
					Purl:   "pkg:npm/express@4.17.0",
					Reason: "old version trusted",
				},
			},
			pkgVersion: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Name:      "express",
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
				},
				Version: "4.18.0",
			},
			want: false,
		},
		{
			name: "name mismatch returns false",
			trustedPackages: []config.TrustedPackage{
				{
					Purl:   "pkg:npm/react@18.0.0",
					Reason: "trusted package",
				},
			},
			pkgVersion: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Name:      "express",
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
				},
				Version: "4.18.0",
			},
			want: false,
		},
		{
			name: "ecosystem mismatch returns false",
			trustedPackages: []config.TrustedPackage{
				{
					Purl:   "pkg:pypi/requests@2.28.0",
					Reason: "trusted package",
				},
			},
			pkgVersion: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Name:      "requests",
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
				},
				Version: "2.28.0",
			},
			want: false,
		},
		{
			name: "pypi package exact match returns true",
			trustedPackages: []config.TrustedPackage{
				{
					Purl:   "pkg:pypi/requests@2.28.0",
					Reason: "trusted http library",
				},
			},
			pkgVersion: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Name:      "requests",
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_PYPI,
				},
				Version: "2.28.0",
			},
			want: true,
		},
		{
			name: "multiple trusted packages finds correct match",
			trustedPackages: []config.TrustedPackage{
				{
					Purl:   "pkg:npm/lodash@4.17.21",
					Reason: "utility library",
				},
				{
					Purl:   "pkg:npm/express@4.18.0",
					Reason: "web framework",
				},
				{
					Purl:   "pkg:pypi/requests@2.28.0",
					Reason: "http library",
				},
			},
			pkgVersion: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Name:      "express",
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
				},
				Version: "4.18.0",
			},
			want: true,
		},
		{
			name: "multiple trusted packages no match returns false",
			trustedPackages: []config.TrustedPackage{
				{
					Purl:   "pkg:npm/lodash@4.17.21",
					Reason: "utility library",
				},
				{
					Purl:   "pkg:npm/react@18.0.0",
					Reason: "ui library",
				},
			},
			pkgVersion: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Name:      "express",
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
				},
				Version: "4.18.0",
			},
			want: false,
		},
		{
			name: "invalid purl in trusted packages skips and returns false",
			trustedPackages: []config.TrustedPackage{
				{
					Purl:   "invalid-purl-format",
					Reason: "malformed",
				},
			},
			pkgVersion: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Name:      "express",
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
				},
				Version: "4.18.0",
			},
			want: false,
		},
		{
			name: "invalid purl skipped but valid match found",
			trustedPackages: []config.TrustedPackage{
				{
					Purl:   "invalid-purl-format",
					Reason: "malformed",
				},
				{
					Purl:   "pkg:npm/express@4.18.0",
					Reason: "valid trusted package",
				},
			},
			pkgVersion: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Name:      "express",
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
				},
				Version: "4.18.0",
			},
			want: true,
		},
		{
			name: "package version without version field matches versionless trusted package",
			trustedPackages: []config.TrustedPackage{
				{
					Purl:   "pkg:npm/express",
					Reason: "all versions trusted",
				},
			},
			pkgVersion: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Name:      "express",
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
				},
				Version: "",
			},
			want: true,
		},
		{
			name: "package version without version field does not match versioned trusted package",
			trustedPackages: []config.TrustedPackage{
				{
					Purl:   "pkg:npm/express@4.18.0",
					Reason: "specific version trusted",
				},
			},
			pkgVersion: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Name:      "express",
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
				},
				Version: "",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := PackageManagerGuardConfig{
				TrustedPackages: tt.trustedPackages,
			}

			got := config.IsTrustedPackageVersion(tt.pkgVersion)
			assert.Equal(t, tt.want, got)
		})
	}
}
