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
			wantErr:          false,
		},
		{
			name:             "pipx run simple package",
			args:             []string{"run", "cowsay", "hello"},
			expectedManifest: false,
			expectedTargets:  1,
			expectedPackages: []string{"cowsay"},
			wantErr:          false,
		},
		{
			name:             "pipx inject",
			args:             []string{"inject", "poetry", "poetry-plugin-export"},
			expectedManifest: false,
			expectedTargets:  2,
			expectedPackages: []string{"poetry", "poetry-plugin-export"},
			wantErr:          false,
		},
		{
			name:             "pipx list",
			args:             []string{"list"},
			expectedManifest: false,
			expectedTargets:  0,
			expectedPackages: []string{},
			wantErr:          false,
		},
		{
			name:             "pipx install with specific version",
			args:             []string{"install", "black==22.3.0"},
			expectedManifest: false,
			expectedTargets:  1,
			expectedPackages: []string{"black"},
			wantErr:          false,
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
			assert.Equal(t, len(tc.expectedPackages), len(result.InstallTargets), "Number of install targets mismatch")

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
			name:                  "pipx list — proxy skipped",
			command:               "pipx list",
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
