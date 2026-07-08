package guard

import (
	"context"
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/analyzer"
	pmgconfig "github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/models"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/packagemanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// noopExecutor is a no-op executor for use in tests that set DryRun=true
// or otherwise don't reach actual command execution.
var noopExecutor CommandExecutor = func(_ context.Context, _ *packagemanager.ParsedCommand) error {
	return nil
}

func TestGuardConcurrentlyAnalyzePackagesMalwareQueryService(t *testing.T) {
	mq, err := analyzer.NewMalysisQueryAnalyzer(analyzer.MalysisQueryAnalyzerConfig{})
	if err != nil {
		t.Fatalf("failed to create mq: %v", err)
	}

	pg, err := NewPackageManagerGuard(DefaultPackageManagerGuardConfig(), nil, nil,
		[]analyzer.PackageVersionAnalyzer{mq}, PackageManagerGuardInteraction{
			ShowWarning: func(message string) {},
		}, noopExecutor)
	if err != nil {
		t.Fatalf("failed to create pg: %v", err)
	}

	t.Run("should resolve a single known malicious package version", func(t *testing.T) {
		r, trustedSkipped, err := pg.concurrentAnalyzePackages(context.Background(), []*packagev1.PackageVersion{
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

		assert.Equal(t, 0, trustedSkipped)
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
			[]analyzer.PackageVersionAnalyzer{mq}, interaction, noopExecutor)
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

		_, err = pg.Run(context.Background(), []string{"npm", "install", "nyc-config@10.0.0"}, parsedCommand)

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

		interaction := PackageManagerGuardInteraction{
			ShowWarning: func(message string) {},
		}

		pg, err := NewPackageManagerGuard(config, nil, nil,
			[]analyzer.PackageVersionAnalyzer{mq}, interaction, noopExecutor)
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

		r, err := pg.Run(context.Background(), []string{"npm", "install", "nyc-config@10.0.0"}, parsedCommand)

		// We expect no error from the guard itself (blocking is handled via the Block callback)
		assert.NoError(t, err)

		// Verify that the malicious package was detected and blocked
		assert.NotEmpty(t, r.BlockedPackages, "Blocked packages should not be empty")
		assert.Greater(t, r.BlockedCount, 0)
		assert.Equal(t, "nyc-config", r.BlockedPackages[0].PackageVersion.GetPackage().GetName())
		assert.Equal(t, "10.0.0", r.BlockedPackages[0].PackageVersion.GetVersion())
		assert.Equal(t, analyzer.ActionBlock, r.BlockedPackages[0].Action)
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
			[]analyzer.PackageVersionAnalyzer{mq}, interaction, noopExecutor)
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

		_, err = pg.Run(context.Background(), []string{"npm", "list"}, parsedCommand)

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
			[]analyzer.PackageVersionAnalyzer{mq}, interaction, noopExecutor)
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

		_, err = pg.Run(context.Background(), []string{"npm", "install"}, parsedCommand)

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

type recordingAnalyzer struct {
	calls int
}

func (a *recordingAnalyzer) Name() string { return "recording" }

func (a *recordingAnalyzer) Analyze(_ context.Context, pv *packagev1.PackageVersion) (*analyzer.PackageVersionAnalysisResult, error) {
	a.calls++
	return &analyzer.PackageVersionAnalysisResult{PackageVersion: pv, Action: analyzer.ActionAllow}, nil
}

func TestGuardBlocklistedPackage(t *testing.T) {
	rc := pmgconfig.Get()
	savedBlocked := rc.Config.BlockedPackages
	savedTrusted := rc.Config.TrustedPackages
	t.Cleanup(func() {
		rc.Config.BlockedPackages = savedBlocked
		rc.Config.TrustedPackages = savedTrusted
		assert.NoError(t, pmgconfig.PreprocessPackageRefs(&rc.Config))
	})

	// Trusted AND blocked: block must win, and analysis must never run.
	rc.Config.BlockedPackages = []pmgconfig.BlockedPackage{{Purl: "pkg:npm/left-pad", Reason: "banned by policy"}}
	rc.Config.TrustedPackages = []pmgconfig.TrustedPackage{{Purl: "pkg:npm/left-pad"}}
	require.NoError(t, pmgconfig.PreprocessPackageRefs(&rc.Config))

	guardConfig := DefaultPackageManagerGuardConfig()
	guardConfig.DryRun = true
	guardConfig.ResolveDependencies = false

	rec := &recordingAnalyzer{}
	pg, err := NewPackageManagerGuard(guardConfig, nil, nil,
		[]analyzer.PackageVersionAnalyzer{rec}, PackageManagerGuardInteraction{
			ShowWarning: func(string) {},
		}, noopExecutor)
	require.NoError(t, err)

	parsedCommand := &packagemanager.ParsedCommand{
		Command: packagemanager.Command{Exe: "npm", Args: []string{"install", "left-pad@1.3.0"}},
		InstallTargets: []*packagemanager.PackageInstallTarget{
			{
				PackageVersion: &packagev1.PackageVersion{
					Package: &packagev1.Package{
						Name:      "left-pad",
						Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
					},
					Version: "1.3.0",
				},
			},
		},
	}

	result, err := pg.Run(context.Background(), []string{"npm", "install", "left-pad@1.3.0"}, parsedCommand)
	require.NoError(t, err)

	assert.Equal(t, 0, rec.calls, "blocklisted package must not be analyzed")
	assert.Greater(t, result.BlockedCount, 0)
	require.Len(t, result.BlocklistBlocked, 1)
	assert.Equal(t, models.BlocklistBlock{Name: "left-pad", Version: "1.3.0", Reason: "banned by policy"}, result.BlocklistBlocked[0])
}
