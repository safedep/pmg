package guard

import (
	"context"
	"strings"
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/analyzer"
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

type testPackageManager struct {
	name      string
	ecosystem packagev1.Ecosystem
}

func (pm testPackageManager) Name() string {
	return pm.name
}

func (pm testPackageManager) ParseCommand(_ []string) (*packagemanager.ParsedCommand, error) {
	return nil, nil
}

func (pm testPackageManager) Ecosystem() packagev1.Ecosystem {
	return pm.ecosystem
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

func TestGuardUnsafeDownloadOptIn(t *testing.T) {
	mq, err := analyzer.NewMalysisQueryAnalyzer(analyzer.MalysisQueryAnalyzerConfig{})
	require.NoError(t, err)

	analyzers := []analyzer.PackageVersionAnalyzer{mq}
	baseConfig := func() PackageManagerGuardConfig {
		config := DefaultPackageManagerGuardConfig()
		config.DryRun = true
		config.ResolveDependencies = false
		return config
	}

	newGuard := func(t *testing.T, config PackageManagerGuardConfig, pm packagemanager.PackageManager) *packageManagerGuard {
		t.Helper()
		pg, err := NewPackageManagerGuard(config, pm, nil, analyzers, PackageManagerGuardInteraction{
			ShowWarning: func(message string) {},
		}, noopExecutor)
		require.NoError(t, err)
		return pg
	}

	commandArgs := func(pc *packagemanager.ParsedCommand) []string {
		return append([]string{pc.Command.Exe}, pc.Command.Args...)
	}

	noTargetCommand := func(exe string, args ...string) *packagemanager.ParsedCommand {
		return &packagemanager.ParsedCommand{
			Command: packagemanager.Command{
				Exe:  exe,
				Args: args,
			},
			InstallTargets:            []*packagemanager.PackageInstallTarget{},
			IsKnownNonDownloadCommand: false,
		}
	}

	manifestNoPackageCommand := &packagemanager.ParsedCommand{
		Command: packagemanager.Command{
			Exe:  "npm",
			Args: []string{"install"},
		},
		InstallTargets:            []*packagemanager.PackageInstallTarget{},
		IsManifestInstall:         true,
		ManifestFiles:             []string{"pmg-test-missing-package-lock.json"},
		IsKnownNonDownloadCommand: false,
	}

	cases := []struct {
		name           string
		configure      func(*PackageManagerGuardConfig)
		packageManager packagemanager.PackageManager
		parsedCommand  *packagemanager.ParsedCommand
		wantErr        bool
		wantLockedHelp bool
	}{
		{
			name:          "fails closed for download-capable command without install targets and no opt-in",
			parsedCommand: noTargetCommand("npm", "ci"),
			wantErr:       true,
		},
		{
			name: "bypasses safety check when AllowUnsafeDownload is enabled in config",
			configure: func(config *PackageManagerGuardConfig) {
				config.AllowUnsafeDownload = true
			},
			parsedCommand: noTargetCommand("npm", "ci"),
			wantErr:       false,
		},
		{
			name: "bypasses safety check when InsecureInstallation is enabled",
			configure: func(config *PackageManagerGuardConfig) {
				config.InsecureInstallation = true
			},
			parsedCommand: noTargetCommand("npm", "ci"),
			wantErr:       false,
		},
		{
			name: "fails closed and does not prompt when global config is locked",
			configure: func(config *PackageManagerGuardConfig) {
				config.IsConfigLocked = true
			},
			parsedCommand:  noTargetCommand("npm", "ci"),
			wantErr:        true,
			wantLockedHelp: true,
		},
		{
			name: "keeps locked config authoritative over InsecureInstallation",
			configure: func(config *PackageManagerGuardConfig) {
				config.InsecureInstallation = true
				config.IsConfigLocked = true
			},
			parsedCommand: noTargetCommand("npm", "ci"),
			wantErr:       true,
		},
		{
			name:           "applies opt-in gate when manifest extraction yields no packages",
			packageManager: testPackageManager{name: "npm", ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM},
			parsedCommand:  manifestNoPackageCommand,
			wantErr:        true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := baseConfig()
			if tc.configure != nil {
				tc.configure(&config)
			}

			pg := newGuard(t, config, tc.packageManager)
			_, err := pg.Run(context.Background(), commandArgs(tc.parsedCommand), tc.parsedCommand)

			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "Blocked execution of download-capable command")
			} else {
				require.NoError(t, err)
			}

			if tc.wantLockedHelp {
				uerr, ok := err.(interface{ Help() string })
				require.True(t, ok)
				assert.Contains(t, uerr.Help(), "blocked by the locked global configuration")
			}
		})
	}

	t.Run("fails closed for npm commands that can download without install targets", func(t *testing.T) {
		pm, err := packagemanager.NewNpmPackageManager(packagemanager.DefaultNpmPackageManagerConfig())
		require.NoError(t, err)

		for _, command := range []string{
			"npm pack react",
			"npm cache add react",
		} {
			t.Run(command, func(t *testing.T) {
				parsedCommand, err := pm.ParseCommand(strings.Split(command, " "))
				require.NoError(t, err)
				require.False(t, parsedCommand.IsKnownNonDownloadCommand)
				require.True(t, parsedCommand.MayDownloadPackages())
				require.Empty(t, parsedCommand.InstallTargets)

				pg := newGuard(t, baseConfig(), nil)
				_, err = pg.Run(context.Background(), commandArgs(parsedCommand), parsedCommand)

				require.Error(t, err)
				assert.Contains(t, err.Error(), "Blocked execution of download-capable command")
			})
		}
	})

	t.Run("allows harmless npm commands without requiring unsafe download opt-in", func(t *testing.T) {
		pm, err := packagemanager.NewNpmPackageManager(packagemanager.DefaultNpmPackageManagerConfig())
		require.NoError(t, err)

		for _, command := range []string{
			"npm",
			"npm --version",
			"npm -l",
			"npm pack",
		} {
			t.Run(command, func(t *testing.T) {
				parsedCommand, err := pm.ParseCommand(strings.Split(command, " "))
				require.NoError(t, err)
				require.True(t, parsedCommand.IsKnownNonDownloadCommand)
				require.False(t, parsedCommand.MayDownloadPackages())

				pg := newGuard(t, baseConfig(), nil)
				_, err = pg.Run(context.Background(), commandArgs(parsedCommand), parsedCommand)

				require.NoError(t, err)
			})
		}
	})

	t.Run("shows non-interactive opt-in notice through warning callback", func(t *testing.T) {
		var warnings []string
		interaction := PackageManagerGuardInteraction{
			ShowWarning: func(message string) {
				warnings = append(warnings, message)
			},
		}
		interaction.SetInput(strings.NewReader(""))

		pg, err := NewPackageManagerGuard(baseConfig(), nil, nil, analyzers, interaction, noopExecutor)
		require.NoError(t, err)

		parsedCommand := noTargetCommand("npm", "ci")
		_, err = pg.Run(context.Background(), commandArgs(parsedCommand), parsedCommand)

		require.Error(t, err)
		require.Len(t, warnings, 2)
		assert.Contains(t, warnings[1], "unable to prompt for explicit opt-in")
	})
}

func TestIsExplicitUnsafeDownloadOptIn(t *testing.T) {
	assert.True(t, isExplicitUnsafeDownloadOptIn("y"))
	assert.True(t, isExplicitUnsafeDownloadOptIn("yes"))
	assert.False(t, isExplicitUnsafeDownloadOptIn("yikes"))
	assert.False(t, isExplicitUnsafeDownloadOptIn("yolo"))
	assert.False(t, isExplicitUnsafeDownloadOptIn("n"))
}
