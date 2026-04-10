package packagemanager

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			command: "npm i -D @types/node",
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
			name:    "update is a known download command",
			command: "npm update @types/node",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, parsedCommand)
				assert.Empty(t, parsedCommand.InstallTargets)
				assert.True(t, parsedCommand.IsKnownDownloadCommand)
				assert.True(t, parsedCommand.MayDownloadPackages())
			},
		},
		{
			name:    "ci is a known download command",
			command: "npm ci",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.True(t, parsedCommand.IsKnownDownloadCommand)
				assert.True(t, parsedCommand.MayDownloadPackages())
				assert.False(t, parsedCommand.IsInstallationCommand())
			},
		},
		{
			name:    "audit is a known download command",
			command: "npm audit",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.True(t, parsedCommand.IsKnownDownloadCommand)
				assert.True(t, parsedCommand.MayDownloadPackages())
			},
		},
		{
			name:    "ls is not a download command",
			command: "npm ls",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.False(t, parsedCommand.IsKnownDownloadCommand)
				assert.False(t, parsedCommand.MayDownloadPackages())
				assert.False(t, parsedCommand.IsInstallationCommand())
			},
		},
		{
			name:    "install sets MayDownloadPackages via IsInstallationCommand",
			command: "npm install express",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.False(t, parsedCommand.IsKnownDownloadCommand)
				assert.True(t, parsedCommand.IsInstallationCommand())
				assert.True(t, parsedCommand.MayDownloadPackages())
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
			command: "npm i -D @types/node -D @types/react",
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
		{
			name:    "manifest installation (bare install)",
			command: "npm install",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 0, len(parsedCommand.InstallTargets))
				assert.Equal(t, true, parsedCommand.IsManifestInstall)
			},
		},
		{
			name:    "manifest installation (short form)",
			command: "npm i",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 0, len(parsedCommand.InstallTargets))
				assert.Equal(t, true, parsedCommand.IsManifestInstall)
			},
		},
		{
			name:    "npm install with dev flag but no packages",
			command: "npm install --save-dev",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 0, len(parsedCommand.InstallTargets))
				assert.Equal(t, false, parsedCommand.IsManifestInstall) // with no package name, npm won’t add or install anything new
			},
		},
		{
			name:    "npm install with global flag with single package",
			command: "npm install -g prettier",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 1, len(parsedCommand.InstallTargets))
				assert.Equal(t, false, parsedCommand.IsManifestInstall)
				assert.Equal(t, "prettier", parsedCommand.InstallTargets[0].PackageVersion.Package.Name)
			},
		},
		{
			name:    "npm install with global flag with multiple packages",
			command: "npm install -g prettier eslint",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 2, len(parsedCommand.InstallTargets))
				assert.Equal(t, false, parsedCommand.IsManifestInstall)
				assert.Equal(t, "prettier", parsedCommand.InstallTargets[0].PackageVersion.Package.Name)
				assert.Equal(t, "eslint", parsedCommand.InstallTargets[1].PackageVersion.Package.Name)
			},
		},
		{
			name:    "npm install with global and dev flags with multiple packages",
			command: "npm install -g --save-dev prettier eslint",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 2, len(parsedCommand.InstallTargets))
				assert.Equal(t, false, parsedCommand.IsManifestInstall)
				var pkgs []string
				for _, target := range parsedCommand.InstallTargets {
					pkgs = append(pkgs, target.PackageVersion.Package.Name)
				}
				assert.ElementsMatch(t, []string{"prettier", "eslint"}, pkgs)
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
			name:    "skip intermediate flags",
			command: "yarn --x -y add @types/node",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 1, len(parsedCommand.InstallTargets))
				assert.Equal(t, "@types/node", parsedCommand.InstallTargets[0].PackageVersion.Package.Name)
			},
		},
		{
			name:    "yarn npm subcommand is not stripped",
			command: "npm login",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				require.NoError(t, err)
				assert.Equal(t, "yarn", parsedCommand.Command.Exe)
				assert.Equal(t, []string{"npm", "login"}, parsedCommand.Command.Args)
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

func TestPnpmParseCommand(t *testing.T) {
	cases := []struct {
		name    string
		command string
		assert  func(t *testing.T, parsedCommand *ParsedCommand, err error)
	}{
		{
			name:    "install a single package",
			command: "pnpm add @types/node",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 1, len(parsedCommand.InstallTargets))
				assert.Equal(t, "@types/node", parsedCommand.InstallTargets[0].PackageVersion.Package.Name)
				assert.Empty(t, parsedCommand.InstallTargets[0].PackageVersion.Version)
			},
		},
		{
			name:    "install a development package with short flag",
			command: "pnpm i -D @types/node",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 1, len(parsedCommand.InstallTargets))
				assert.Equal(t, "@types/node", parsedCommand.InstallTargets[0].PackageVersion.Package.Name)
			},
		},
		{
			name:    "manifest installation",
			command: "pnpm install",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, true, parsedCommand.IsManifestInstall)
				assert.Equal(t, 0, len(parsedCommand.InstallTargets))
			},
		},
		{
			name:    "multiple package installations",
			command: "pnpm add @types/node @types/react",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 2, len(parsedCommand.InstallTargets))
				assert.Equal(t, "@types/node", parsedCommand.InstallTargets[0].PackageVersion.Package.Name)
				assert.Equal(t, "@types/react", parsedCommand.InstallTargets[1].PackageVersion.Package.Name)
			},
		},
		{
			name:    "skip intermediate flags",
			command: "pnpm --x -y add @types/node",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 1, len(parsedCommand.InstallTargets))
				assert.Equal(t, "@types/node", parsedCommand.InstallTargets[0].PackageVersion.Package.Name)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pnpm, err := NewNpmPackageManager(DefaultPnpmPackageManagerConfig())
			assert.NoError(t, err)

			parsedCommand, err := pnpm.ParseCommand(strings.Split(tc.command, " "))
			tc.assert(t, parsedCommand, err)
		})
	}
}

func TestBunParseCommand(t *testing.T) {
	cases := []struct {
		name    string
		command string
		assert  func(t *testing.T, parsedCommand *ParsedCommand, err error)
	}{
		{
			name:    "install a single package",
			command: "bun add @types/node",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 1, len(parsedCommand.InstallTargets))
				assert.Equal(t, "@types/node", parsedCommand.InstallTargets[0].PackageVersion.Package.Name)
				assert.Empty(t, parsedCommand.InstallTargets[0].PackageVersion.Version)
			},
		},
		{
			name:    "install a development package with short flag",
			command: "bun add -d @types/node",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 1, len(parsedCommand.InstallTargets))
				assert.Equal(t, "@types/node", parsedCommand.InstallTargets[0].PackageVersion.Package.Name)
			},
		},
		{
			name:    "manifest installation",
			command: "bun install",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, true, parsedCommand.IsManifestInstall)
				assert.Equal(t, 0, len(parsedCommand.InstallTargets))
			},
		},
		{
			name:    "multiple package installations",
			command: "bun add @types/node @types/react",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 2, len(parsedCommand.InstallTargets))
				assert.Equal(t, "@types/node", parsedCommand.InstallTargets[0].PackageVersion.Package.Name)
				assert.Equal(t, "@types/react", parsedCommand.InstallTargets[1].PackageVersion.Package.Name)
			},
		},
		{
			name:    "skip intermediate flags",
			command: "bun --x -y add @types/node",
			assert: func(t *testing.T, parsedCommand *ParsedCommand, err error) {
				assert.NoError(t, err)
				assert.Equal(t, 1, len(parsedCommand.InstallTargets))
				assert.Equal(t, "@types/node", parsedCommand.InstallTargets[0].PackageVersion.Package.Name)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bun, err := NewNpmPackageManager(DefaultBunPackageManagerConfig())
			assert.NoError(t, err)

			parsedCommand, err := bun.ParseCommand(strings.Split(tc.command, " "))
			tc.assert(t, parsedCommand, err)
		})
	}
}

func TestNpmDownloadCommands(t *testing.T) {
	cases := []struct {
		name                   string
		pm                     func() (*npmPackageManager, error)
		command                string
		isKnownDownloadCommand bool
		isInstallationCommand  bool
	}{
		{
			name:                   "yarn upgrade is a known download command",
			pm:                     func() (*npmPackageManager, error) { return NewNpmPackageManager(DefaultYarnPackageManagerConfig()) },
			command:                "yarn upgrade",
			isKnownDownloadCommand: true,
			isInstallationCommand:  false,
		},
		{
			name:                   "pnpm update is a known download command",
			pm:                     func() (*npmPackageManager, error) { return NewNpmPackageManager(DefaultPnpmPackageManagerConfig()) },
			command:                "pnpm update",
			isKnownDownloadCommand: true,
			isInstallationCommand:  false,
		},
		{
			name:                   "bun update is a known download command",
			pm:                     func() (*npmPackageManager, error) { return NewNpmPackageManager(DefaultBunPackageManagerConfig()) },
			command:                "bun update",
			isKnownDownloadCommand: true,
			isInstallationCommand:  false,
		},
		{
			name:                   "npm exec is a known download command",
			pm:                     func() (*npmPackageManager, error) { return NewNpmPackageManager(DefaultNpmPackageManagerConfig()) },
			command:                "npm exec create-react-app",
			isKnownDownloadCommand: true,
			isInstallationCommand:  false,
		},
		{
			name:                   "pnpm dlx is a known download command",
			pm:                     func() (*npmPackageManager, error) { return NewNpmPackageManager(DefaultPnpmPackageManagerConfig()) },
			command:                "pnpm dlx create-react-app",
			isKnownDownloadCommand: true,
			isInstallationCommand:  false,
		},
		{
			name:                   "pnpm exec is a known download command",
			pm:                     func() (*npmPackageManager, error) { return NewNpmPackageManager(DefaultPnpmPackageManagerConfig()) },
			command:                "pnpm exec tsc",
			isKnownDownloadCommand: true,
			isInstallationCommand:  false,
		},
		{
			name:                   "yarn dlx is a known download command",
			pm:                     func() (*npmPackageManager, error) { return NewNpmPackageManager(DefaultYarnPackageManagerConfig()) },
			command:                "yarn dlx create-react-app",
			isKnownDownloadCommand: true,
			isInstallationCommand:  false,
		},
		{
			name:                   "bun x is a known download command",
			pm:                     func() (*npmPackageManager, error) { return NewNpmPackageManager(DefaultBunPackageManagerConfig()) },
			command:                "bun x create-vite",
			isKnownDownloadCommand: true,
			isInstallationCommand:  false,
		},
		{
			name:                   "npm outdated is not a download command",
			pm:                     func() (*npmPackageManager, error) { return NewNpmPackageManager(DefaultNpmPackageManagerConfig()) },
			command:                "npm outdated",
			isKnownDownloadCommand: false,
			isInstallationCommand:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pm, err := tc.pm()
			assert.NoError(t, err)

			parsed, err := pm.ParseCommand(strings.Split(tc.command, " "))
			assert.NoError(t, err)
			assert.Equal(t, tc.isKnownDownloadCommand, parsed.IsKnownDownloadCommand)
			assert.Equal(t, tc.isInstallationCommand, parsed.IsInstallationCommand())
			assert.Equal(t, tc.isKnownDownloadCommand || tc.isInstallationCommand, parsed.MayDownloadPackages())
		})
	}
}
