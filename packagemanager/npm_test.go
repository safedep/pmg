package packagemanager

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNpmParseCommand(t *testing.T) {
	cases := []struct {
		name    string
		command string
		assert  func(t *testing.T, parsedCommand *ParsedCommand, err error)
	}{
		{
			name:    "install a single package",
			command: "npm install @types/node",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 1, len(parsedCommand.InstallTargets))
				assert.Equal(t, "@types/node", parsedCommand.InstallTargets[0].PackageVersion.Package.Name)
				assert.Empty(t, parsedCommand.InstallTargets[0].PackageVersion.Version)
			},
		},
		{
			name:    "install a single package with specific version",
			command: "npm install @types/node@1.2.3",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 1, len(parsedCommand.InstallTargets))
				assert.Equal(t, "@types/node", parsedCommand.InstallTargets[0].PackageVersion.Package.Name)
				assert.Equal(t, "1.2.3", parsedCommand.InstallTargets[0].PackageVersion.Version)
			},
		},
		{
			name:    "install a development package",
			command: "npm install --save-dev @types/node",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 1, len(parsedCommand.InstallTargets))
				assert.Equal(t, "@types/node", parsedCommand.InstallTargets[0].PackageVersion.Package.Name)
			},
		},
		{
			name:    "install a development package with short flag",
			command: "npm i @types/node -D",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 1, len(parsedCommand.InstallTargets))
				assert.Equal(t, "@types/node", parsedCommand.InstallTargets[0].PackageVersion.Package.Name)
			},
		},
		{
			name:    "no install target",
			command: "npm install",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 0, len(parsedCommand.InstallTargets))
			},
		},
		{
			name:    "multiple package installations",
			command: "npm install @types/node @types/react",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 2, len(parsedCommand.InstallTargets))
				assert.Equal(t, "@types/node", parsedCommand.InstallTargets[0].PackageVersion.Package.Name)
				assert.Equal(t, "@types/react", parsedCommand.InstallTargets[1].PackageVersion.Package.Name)
			},
		},
		{
			name:    "not an installation command",
			command: "npm update @types/node",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, parsedCommand)
				assert.Equal(t, 0, len(parsedCommand.InstallTargets))
			},
		},
		{
			name:    "skip intermediate flags",
			command: "npm --x -y install @types/node",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 1, len(parsedCommand.InstallTargets))
				assert.Equal(t, "@types/node", parsedCommand.InstallTargets[0].PackageVersion.Package.Name)
			},
		},
		{
			name:    "multiple development packages",
			command: "npm i @types/node @types/react -D",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 2, len(parsedCommand.InstallTargets))
				assert.Equal(t, "@types/node", parsedCommand.InstallTargets[0].PackageVersion.Package.Name)
				assert.Equal(t, "@types/react", parsedCommand.InstallTargets[1].PackageVersion.Package.Name)
			},
		},
		{
			name:    "second package has a version",
			command: "npm i express @types/node@1.2.3",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 2, len(parsedCommand.InstallTargets))
				assert.Equal(t, "express", parsedCommand.InstallTargets[0].PackageVersion.Package.Name)
				assert.Empty(t, parsedCommand.InstallTargets[0].PackageVersion.Version)
				assert.Equal(t, "@types/node", parsedCommand.InstallTargets[1].PackageVersion.Package.Name)
				assert.Equal(t, "1.2.3", parsedCommand.InstallTargets[1].PackageVersion.Version)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			npm, err := NewNpmPackageManager(DefaultNpmPackageManagerConfig())
			assert.NoError(t, err)

			parsedCommand, err := npm.ParseCommand(strings.Split(tc.command, " "))
			tc.assert(t, parsedCommand, err)
		})
	}
}

func TestNpmParseCommand_ManifestInstallation(t *testing.T) {
	pm, err := NewNpmPackageManager(DefaultNpmPackageManagerConfig())
	assert.NoError(t, err)

	cases := []struct {
		name              string
		args              []string
		expectedManifest  bool
		expectedFiles     []string
		expectedTargets   int
	}{
		{
			name:              "npm install without args (bare install)",
			args:              []string{"install"},
			expectedManifest:  true,
			expectedFiles:     []string{"package.json"},
			expectedTargets:   0,
		},
		{
			name:              "npm i without args (short form)",
			args:              []string{"i"},
			expectedManifest:  true,
			expectedFiles:     []string{"package.json"},
			expectedTargets:   0,
		},
		{
			name:              "npm install with explicit package",
			args:              []string{"install", "react"},
			expectedManifest:  false,
			expectedFiles:     nil,
			expectedTargets:   1,
		},
		{
			name:              "npm install with multiple packages",
			args:              []string{"install", "react", "vue"},
			expectedManifest:  false,
			expectedFiles:     nil,
			expectedTargets:   2,
		},
		{
			name:              "npm install with flags but no packages",
			args:              []string{"install", "--save-dev"},
			expectedManifest:  true,
			expectedFiles:     []string{"package.json"},
			expectedTargets:   0,
		},
		{
			name:              "npm install with mixed args",
			args:              []string{"install", "react", "--save"},
			expectedManifest:  false,
			expectedFiles:     nil,
			expectedTargets:   1,
		},
		{
			name:              "non-install command",
			args:              []string{"run", "build"},
			expectedManifest:  false,
			expectedFiles:     nil,
			expectedTargets:   0,
		},
		{
			name:              "pnpm install without args",
			args:              []string{"install"},
			expectedManifest:  true,
			expectedFiles:     []string{"package.json"},
			expectedTargets:   0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := pm.ParseCommand(tc.args)
			assert.NoError(t, err)
			
			assert.Equal(t, tc.expectedManifest, parsed.IsManifestInstall, "IsManifestInstall mismatch")
			assert.Equal(t, tc.expectedFiles, parsed.ManifestFiles, "ManifestFiles mismatch")
			assert.Equal(t, tc.expectedTargets, len(parsed.InstallTargets), "InstallTargets count mismatch")
			
			// Test helper methods
			assert.Equal(t, tc.expectedManifest, parsed.HasManifestInstall(), "HasManifestInstall mismatch")
			
			expectedShouldExtract := tc.expectedManifest && tc.expectedTargets == 0
			assert.Equal(t, expectedShouldExtract, parsed.ShouldExtractFromManifest(), "ShouldExtractFromManifest mismatch")
		})
	}
}
