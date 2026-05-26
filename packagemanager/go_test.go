package packagemanager

import (
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/stretchr/testify/assert"
)

func TestGoPackageManagerParseCommand(t *testing.T) {
	pm, _ := NewGoPackageManager(DefaultGoPackageManagerConfig())

	tests := []struct {
		name     string
		args     []string
		expected *ParsedCommand
	}{
		{
			name: "go get package",
			args: []string{"get", "github.com/stretchr/testify"},
			expected: &ParsedCommand{
				Command: Command{Exe: "go", Args: []string{"get", "github.com/stretchr/testify"}},
				InstallTargets: []*PackageInstallTarget{
					{
						IsExplicitVersion: false,
						PackageVersion: &packagev1.PackageVersion{
							Package: &packagev1.Package{
								Ecosystem: packagev1.Ecosystem_ECOSYSTEM_GO,
								Name:      "github.com/stretchr/testify",
							},
							Version: "",
						},
					},
				},
				IsManifestInstall: false,
				ManifestFiles:     []string{},
			},
		},
		{
			name: "go get package@version",
			args: []string{"get", "github.com/stretchr/testify@v1.7.0"},
			expected: &ParsedCommand{
				Command: Command{Exe: "go", Args: []string{"get", "github.com/stretchr/testify@v1.7.0"}},
				InstallTargets: []*PackageInstallTarget{
					{
						IsExplicitVersion: true,
						PackageVersion: &packagev1.PackageVersion{
							Package: &packagev1.Package{
								Ecosystem: packagev1.Ecosystem_ECOSYSTEM_GO,
								Name:      "github.com/stretchr/testify",
							},
							Version: "v1.7.0",
						},
					},
				},
				IsManifestInstall: false,
				ManifestFiles:     []string{},
			},
		},
		{
			name: "go mod download",
			args: []string{"mod", "download"},
			expected: &ParsedCommand{
				Command:           Command{Exe: "go", Args: []string{"mod", "download"}},
				IsManifestInstall: true,
				ManifestFiles:     []string{"go.mod"},
			},
		},
		{
			name: "go mod tidy",
			args: []string{"mod", "tidy"},
			expected: &ParsedCommand{
				Command:           Command{Exe: "go", Args: []string{"mod", "tidy"}},
				IsManifestInstall: true,
				ManifestFiles:     []string{"go.mod"},
			},
		},
		{
			name: "go build (non-download)",
			args: []string{"build"},
			expected: &ParsedCommand{
				Command:                   Command{Exe: "go", Args: []string{"build"}},
				IsKnownNonDownloadCommand: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := pm.ParseCommand(tt.args)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected.Command, actual.Command)
			assert.Equal(t, tt.expected.IsManifestInstall, actual.IsManifestInstall)
			assert.Equal(t, tt.expected.ManifestFiles, actual.ManifestFiles)
			assert.Equal(t, tt.expected.IsKnownNonDownloadCommand, actual.IsKnownNonDownloadCommand)
			
			if tt.expected.InstallTargets != nil {
				assert.Equal(t, len(tt.expected.InstallTargets), len(actual.InstallTargets))
				for i := range tt.expected.InstallTargets {
					assert.Equal(t, tt.expected.InstallTargets[i].IsExplicitVersion, actual.InstallTargets[i].IsExplicitVersion)
					assert.Equal(t, tt.expected.InstallTargets[i].PackageVersion.Package.Name, actual.InstallTargets[i].PackageVersion.Package.Name)
					assert.Equal(t, tt.expected.InstallTargets[i].PackageVersion.Version, actual.InstallTargets[i].PackageVersion.Version)
				}
			}
		})
	}
}
