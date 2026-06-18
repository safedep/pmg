package packagemanager

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPipxExecutorParseCommand(t *testing.T) {
	pm, err := NewPypiPackageExecutor(DefaultPipxPackageExecutorConfig())
	assert.NoError(t, err)

	cases := []struct {
		name             string
		args             []string
		expectedManifest bool
		expectedTargets  int
		expectedPackages []string
		wantErr          bool
	}{
		{
			name:             "pipx install simple package",
			args:             []string{"install", "black"},
			expectedManifest: false,
			expectedTargets:  1,
			expectedPackages: []string{"black"},
		},
		{
			name:             "pipx install with specific version",
			args:             []string{"install", "black==22.3.0"},
			expectedManifest: false,
			expectedTargets:  1,
			expectedPackages: []string{"black"},
		},
		{
			name:             "pipx install with --force flag",
			args:             []string{"install", "--force", "ruff"},
			expectedManifest: false,
			expectedTargets:  1,
			expectedPackages: []string{"ruff"},
		},
		{
			name:             "pipx install with --pip-args flag",
			args:             []string{"install", "--pip-args", "--no-cache-dir", "black"},
			expectedManifest: false,
			expectedTargets:  1,
			expectedPackages: []string{"black"},
		},
		{
			name:             "pipx install with --python flag",
			args:             []string{"install", "--python", "python3.11", "black"},
			expectedManifest: false,
			expectedTargets:  1,
			expectedPackages: []string{"black"},
		},
		{
			name:             "pipx run simple package",
			args:             []string{"run", "cowsay", "hello"},
			expectedManifest: false,
			expectedTargets:  1,
			expectedPackages: []string{"cowsay"},
		},
		{
			name:             "pipx run with --spec flag",
			args:             []string{"run", "--spec", "black==22.3.0", "black", "--check", "."},
			expectedManifest: false,
			expectedTargets:  1,
			expectedPackages: []string{"black"},
		},
		{
			name:             "pipx run with --no-cache flag",
			args:             []string{"run", "--no-cache", "cowsay", "hello"},
			expectedManifest: false,
			expectedTargets:  1,
			expectedPackages: []string{"cowsay"},
		},
		{
			name:             "pipx run bare (no package)",
			args:             []string{"run"},
			expectedManifest: false,
			expectedTargets:  0,
			expectedPackages: []string{},
		},
		{
			name:             "pipx inject skips target venv",
			args:             []string{"inject", "poetry", "poetry-plugin-export"},
			expectedManifest: false,
			expectedTargets:  1,
			expectedPackages: []string{"poetry-plugin-export"},
		},
		{
			name:             "pipx inject multiple packages",
			args:             []string{"inject", "myapp", "requests", "flask"},
			expectedManifest: false,
			expectedTargets:  2,
			expectedPackages: []string{"requests", "flask"},
		},
		{
			name:             "pipx inject with --force flag",
			args:             []string{"inject", "--force", "poetry", "poetry-plugin-export"},
			expectedManifest: false,
			expectedTargets:  1,
			expectedPackages: []string{"poetry-plugin-export"},
		},
		{
			name:             "pipx inject with --include-apps flag",
			args:             []string{"inject", "--include-apps", "myapp", "flask"},
			expectedManifest: false,
			expectedTargets:  1,
			expectedPackages: []string{"flask"},
		},
		{
			name:             "pipx inject with --pip-args flag",
			args:             []string{"inject", "--pip-args", "--no-deps", "myapp", "flask"},
			expectedManifest: false,
			expectedTargets:  1,
			expectedPackages: []string{"flask"},
		},
		{
			name:             "pipx inject only target venv (no packages)",
			args:             []string{"inject", "poetry"},
			expectedManifest: false,
			expectedTargets:  0,
			expectedPackages: []string{},
		},
		{
			name:             "pipx inject bare (no args)",
			args:             []string{"inject"},
			expectedManifest: false,
			expectedTargets:  0,
			expectedPackages: []string{},
		},
		{
			name:             "pipx list",
			args:             []string{"list"},
			expectedManifest: false,
			expectedTargets:  0,
			expectedPackages: []string{},
		},
		{
			name:             "pipx uninstall",
			args:             []string{"uninstall", "black"},
			expectedManifest: false,
			expectedTargets:  0,
			expectedPackages: []string{},
		},
		{
			name:             "bare pipx invocation",
			args:             []string{},
			expectedManifest: false,
			expectedTargets:  0,
			expectedPackages: []string{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := pm.ParseCommand(tc.args)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)

			assert.Equal(t, tc.expectedManifest, result.HasManifestInstall(), "HasManifestInstall mismatch")
			assert.Equal(t, tc.expectedTargets, len(result.InstallTargets), "Number of install targets mismatch")

			for i, expectedPkg := range tc.expectedPackages {
				if i < len(result.InstallTargets) {
					target := result.InstallTargets[i]
					assert.Equal(t, expectedPkg, target.PackageVersion.Package.Name, "Package name mismatch for package %d", i)
				}
			}
		})
	}
}

func TestPipxExecutorProxyBehavior(t *testing.T) {
	cases := []struct {
		name                  string
		command               string
		isKnownNonDownloadCmd bool
		isInstallationCommand bool
	}{
		{
			name:                  "pipx install — proxy runs",
			command:               "pipx install black",
			isKnownNonDownloadCmd: false,
			isInstallationCommand: true,
		},
		{
			name:                  "pipx run — proxy runs",
			command:               "pipx run cowsay moo",
			isKnownNonDownloadCmd: false,
			isInstallationCommand: true,
		},
		{
			name:                  "pipx inject — proxy runs",
			command:               "pipx inject myapp requests",
			isKnownNonDownloadCmd: false,
			isInstallationCommand: true,
		},
		{
			name:                  "pipx upgrade — proxy runs (downloads newer version)",
			command:               "pipx upgrade black",
			isKnownNonDownloadCmd: false,
			isInstallationCommand: true,
		},
		{
			name:                  "pipx upgrade-all — proxy runs (downloads newer versions)",
			command:               "pipx upgrade-all",
			isKnownNonDownloadCmd: false,
			isInstallationCommand: false,
		},
		{
			name:                  "pipx list — proxy skipped",
			command:               "pipx list",
			isKnownNonDownloadCmd: true,
			isInstallationCommand: false,
		},
		{
			name:                  "pipx uninstall — proxy skipped",
			command:               "pipx uninstall black",
			isKnownNonDownloadCmd: true,
			isInstallationCommand: false,
		},
		{
			name:                  "pipx uninstall-all — proxy skipped",
			command:               "pipx uninstall-all",
			isKnownNonDownloadCmd: true,
			isInstallationCommand: false,
		},
		{
			name:                  "pipx completions — proxy skipped",
			command:               "pipx completions",
			isKnownNonDownloadCmd: true,
			isInstallationCommand: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pm, err := NewPypiPackageExecutor(DefaultPipxPackageExecutorConfig())
			assert.NoError(t, err)

			parsed, err := pm.ParseCommand(strings.Split(tc.command, " "))
			assert.NoError(t, err)
			assert.Equal(t, tc.isKnownNonDownloadCmd, parsed.IsKnownNonDownloadCommand)
			assert.Equal(t, tc.isInstallationCommand, parsed.IsInstallationCommand())
			assert.Equal(t, !tc.isKnownNonDownloadCmd, parsed.MayDownloadPackages())
		})
	}
}

func TestPypiExecutorUnsupportedCommandName(t *testing.T) {
	pm, err := NewPypiPackageExecutor(PypiPackageExecutorConfig{CommandName: "pipz"})
	assert.NoError(t, err)

	_, err = pm.ParseCommand([]string{"install", "black"})
	assert.ErrorContains(t, err, "unsupported package executor: pipz")
}

func TestUvxExecutorParseCommand(t *testing.T) {
	pm, err := NewPypiPackageExecutor(DefaultUvxPackageExecutorConfig())
	assert.NoError(t, err)

	cases := []struct {
		name             string
		command          string
		expectedPackages []string
		expectedVersions []string
	}{
		{
			name:             "uvx package as first positional arg",
			command:          "uvx ruff@0.3.0 check",
			expectedPackages: []string{"ruff"},
			expectedVersions: []string{"0.3.0"},
		},
		{
			name:             "uvx package from --from flag",
			command:          "uvx --from httpie==3.2.2 http",
			expectedPackages: []string{"httpie"},
			expectedVersions: []string{"3.2.2"},
		},
		{
			name:             "uvx package from --from equals flag",
			command:          "uvx --from=mypy[faster-cache,reports]==1.13.0 mypy --xml-report report",
			expectedPackages: []string{"mypy"},
			expectedVersions: []string{"1.13.0"},
		},
		{
			name:             "uvx ignores --from after end of options delimiter",
			command:          "uvx ruff@0.3.0 -- --from httpie==3.2.2",
			expectedPackages: []string{"ruff"},
			expectedVersions: []string{"0.3.0"},
		},
		{
			name:             "uvx skips option values before positional package",
			command:          "uvx --python 3.10 ruff@0.3.0",
			expectedPackages: []string{"ruff"},
			expectedVersions: []string{"0.3.0"},
		},
		{
			name:             "bare uvx invocation",
			command:          "uvx",
			expectedPackages: []string{},
			expectedVersions: []string{},
		},
		{
			name:             "uvx skips non pypi source from --from flag",
			command:          "uvx --from git+https://github.com/httpie/cli httpie",
			expectedPackages: []string{},
			expectedVersions: []string{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := pm.ParseCommand(strings.Split(tc.command, " "))
			assert.NoError(t, err)
			assert.Equal(t, len(tc.expectedPackages), len(result.InstallTargets), "Number of install targets mismatch")

			for i, expectedPkg := range tc.expectedPackages {
				target := result.InstallTargets[i]
				assert.Equal(t, expectedPkg, target.PackageVersion.Package.Name, "Package name mismatch for package %d", i)
				assert.Equal(t, tc.expectedVersions[i], target.PackageVersion.Version, "Package version mismatch for package %d", i)
				assert.True(t, target.IsExplicitVersion, "Expected explicit version for package %d", i)
			}
		})
	}
}

func TestUvxExecutorProxyBehavior(t *testing.T) {
	cases := []struct {
		name                  string
		command               string
		isKnownNonDownloadCmd bool
		isInstallationCommand bool
	}{
		{
			name:                  "uvx positional package — proxy runs",
			command:               "uvx ruff@0.3.0 check",
			isKnownNonDownloadCmd: false,
			isInstallationCommand: true,
		},
		{
			name:                  "uvx --from package — proxy runs",
			command:               "uvx --from httpie==3.2.2 http",
			isKnownNonDownloadCmd: false,
			isInstallationCommand: true,
		},
		{
			name:                  "bare uvx — proxy runs fail safe",
			command:               "uvx",
			isKnownNonDownloadCmd: false,
			isInstallationCommand: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pm, err := NewPypiPackageExecutor(DefaultUvxPackageExecutorConfig())
			assert.NoError(t, err)

			parsed, err := pm.ParseCommand(strings.Split(tc.command, " "))
			assert.NoError(t, err)
			assert.Equal(t, tc.isKnownNonDownloadCmd, parsed.IsKnownNonDownloadCommand)
			assert.Equal(t, tc.isInstallationCommand, parsed.IsInstallationCommand())
			assert.Equal(t, !tc.isKnownNonDownloadCmd, parsed.MayDownloadPackages())
		})
	}
}
