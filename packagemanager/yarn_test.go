package packagemanager

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestYarnParseCommand(t *testing.T) {
	cases := []struct {
		name    string
		command string
		assert  func(t *testing.T, parsedCommand *ParsedCommand, err error)
	}{
		{
			name:    "install a single package",
			command: "yarn add @types/node",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 1, len(parsedCommand.InstallTargets))
				assert.Equal(t, "@types/node", parsedCommand.InstallTargets[0].PackageVersion.Package.Name)
				assert.Empty(t, parsedCommand.InstallTargets[0].PackageVersion.Version)
			},
		},
		{
			name:    "install a single package with specific version",
			command: "yarn add @types/node@1.2.3",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 1, len(parsedCommand.InstallTargets))
				assert.Equal(t, "@types/node", parsedCommand.InstallTargets[0].PackageVersion.Package.Name)
				assert.Equal(t, "1.2.3", parsedCommand.InstallTargets[0].PackageVersion.Version)
			},
		},
		{
			name:    "install a development package",
			command: "yarn add --dev @types/node",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 1, len(parsedCommand.InstallTargets))
				assert.Equal(t, "@types/node", parsedCommand.InstallTargets[0].PackageVersion.Package.Name)
			},
		},
		{
			name:    "install a development package with short flag",
			command: "yarn add -D @types/node",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 1, len(parsedCommand.InstallTargets))
				assert.Equal(t, "@types/node", parsedCommand.InstallTargets[0].PackageVersion.Package.Name)
			},
		},
		{
			name:    "manifest installation with install command",
			command: "yarn install",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 0, len(parsedCommand.InstallTargets))
				assert.Equal(t, true, parsedCommand.IsManifestInstall)
			},
		},
		{
			name:    "bare yarn command (manifest install)",
			command: "yarn",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 0, len(parsedCommand.InstallTargets))
				assert.Equal(t, true, parsedCommand.IsManifestInstall)
			},
		},
		{
			name:    "yarn install with package name (invalid syntax)",
			command: "yarn install express",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, parsedCommand)
				assert.Equal(t, 0, len(parsedCommand.InstallTargets))
				assert.Equal(t, false, parsedCommand.IsManifestInstall)
			},
		},
		{
			name:    "multiple package installations",
			command: "yarn add @types/node @types/react",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 2, len(parsedCommand.InstallTargets))
				assert.Equal(t, "@types/node", parsedCommand.InstallTargets[0].PackageVersion.Package.Name)
				assert.Equal(t, "@types/react", parsedCommand.InstallTargets[1].PackageVersion.Package.Name)
			},
		},
		{
			name:    "not an installation command",
			command: "yarn remove @types/node",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, parsedCommand)
				assert.Equal(t, 0, len(parsedCommand.InstallTargets))
			},
		},
		{
			name:    "skip intermediate flags",
			command: "yarn --x -y add @types/node",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 1, len(parsedCommand.InstallTargets))
				assert.Equal(t, "@types/node", parsedCommand.InstallTargets[0].PackageVersion.Package.Name)
			},
		},
		{
			name:    "multiple development packages",
			command: "yarn add -D @types/node -D @types/react",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 2, len(parsedCommand.InstallTargets))
				assert.Equal(t, "@types/node", parsedCommand.InstallTargets[0].PackageVersion.Package.Name)
				assert.Equal(t, "@types/react", parsedCommand.InstallTargets[1].PackageVersion.Package.Name)
			},
		},
		{
			name:    "second package has a version",
			command: "yarn add express @types/node@1.2.3",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 2, len(parsedCommand.InstallTargets))
				assert.Equal(t, "express", parsedCommand.InstallTargets[0].PackageVersion.Package.Name)
				assert.Empty(t, parsedCommand.InstallTargets[0].PackageVersion.Version)
				assert.Equal(t, "@types/node", parsedCommand.InstallTargets[1].PackageVersion.Package.Name)
				assert.Equal(t, "1.2.3", parsedCommand.InstallTargets[1].PackageVersion.Version)
			},
		},
		{
			name:    "yarn add with dev flag but no packages",
			command: "yarn add --dev",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 0, len(parsedCommand.InstallTargets))
				assert.Equal(t, false, parsedCommand.IsManifestInstall)
			},
		},
		{
			name:    "yarn with global flag",
			command: "yarn global add typescript",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 1, len(parsedCommand.InstallTargets))
				assert.Equal(t, "typescript", parsedCommand.InstallTargets[0].PackageVersion.Package.Name)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			yarn, err := NewNpmPackageManager(DefaultYarnPackageManagerConfig())
			assert.NoError(t, err)

			parsedCommand, err := yarn.ParseCommand(strings.Split(tc.command, " "))
			tc.assert(t, parsedCommand, err)
		})
	}
}