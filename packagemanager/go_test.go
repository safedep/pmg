package packagemanager

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGoParseCommand(t *testing.T) {
	pm, err := NewGoPackageManager(DefaultGoPackageManagerConfig())
	require.NoError(t, err)

	cases := []struct {
		name    string
		command string
		assert  func(t *testing.T, parsed *ParsedCommand, err error)
	}{
		{
			name:    "go install explicit module version",
			command: "go install github.com/google/uuid@v1.6.0",
			assert: func(t *testing.T, parsed *ParsedCommand, err error) {
				require.NoError(t, err)
				require.Len(t, parsed.InstallTargets, 1)
				assert.Equal(t, "github.com/google/uuid", parsed.InstallTargets[0].PackageVersion.GetPackage().GetName())
				assert.Equal(t, "v1.6.0", parsed.InstallTargets[0].PackageVersion.GetVersion())
				assert.True(t, parsed.MayDownloadPackages())
			},
		},
		{
			name:    "go install local pattern stays passthrough-like",
			command: "go install ./cmd/...",
			assert: func(t *testing.T, parsed *ParsedCommand, err error) {
				require.NoError(t, err)
				assert.Empty(t, parsed.InstallTargets)
				assert.False(t, parsed.IsInstallationCommand())
				assert.True(t, parsed.MayDownloadPackages())
			},
		},
		{
			name:    "go get remote module without explicit version",
			command: "go get github.com/google/uuid",
			assert: func(t *testing.T, parsed *ParsedCommand, err error) {
				require.NoError(t, err)
				require.Len(t, parsed.InstallTargets, 1)
				assert.Equal(t, "github.com/google/uuid", parsed.InstallTargets[0].PackageVersion.GetPackage().GetName())
				assert.Empty(t, parsed.InstallTargets[0].PackageVersion.GetVersion())
				assert.True(t, parsed.IsInstallationCommand())
			},
		},
		{
			name:    "go get local package does not produce install target",
			command: "go get ./...",
			assert: func(t *testing.T, parsed *ParsedCommand, err error) {
				require.NoError(t, err)
				assert.Empty(t, parsed.InstallTargets)
				assert.False(t, parsed.IsInstallationCommand())
				assert.True(t, parsed.MayDownloadPackages())
			},
		},
		{
			name:    "go mod tidy is manifest install",
			command: "go mod tidy",
			assert: func(t *testing.T, parsed *ParsedCommand, err error) {
				require.NoError(t, err)
				assert.True(t, parsed.IsManifestInstall)
				assert.Equal(t, []string{"go.mod", "go.sum"}, parsed.ManifestFiles)
				assert.True(t, parsed.MayDownloadPackages())
			},
		},
		{
			name:    "go mod download with explicit module target",
			command: "go mod download github.com/google/uuid@v1.6.0",
			assert: func(t *testing.T, parsed *ParsedCommand, err error) {
				require.NoError(t, err)
				require.Len(t, parsed.InstallTargets, 1)
				assert.False(t, parsed.IsManifestInstall)
				assert.Equal(t, "github.com/google/uuid", parsed.InstallTargets[0].PackageVersion.GetPackage().GetName())
				assert.Equal(t, "v1.6.0", parsed.InstallTargets[0].PackageVersion.GetVersion())
			},
		},
		{
			name:    "go mod download without explicit modules is manifest install",
			command: "go mod download",
			assert: func(t *testing.T, parsed *ParsedCommand, err error) {
				require.NoError(t, err)
				assert.True(t, parsed.IsManifestInstall)
				assert.Equal(t, []string{"go.mod", "go.sum"}, parsed.ManifestFiles)
				assert.Empty(t, parsed.InstallTargets)
			},
		},
		{
			name:    "go run remote module target",
			command: "go run github.com/google/uuid@v1.6.0",
			assert: func(t *testing.T, parsed *ParsedCommand, err error) {
				require.NoError(t, err)
				require.Len(t, parsed.InstallTargets, 1)
				assert.Equal(t, "github.com/google/uuid", parsed.InstallTargets[0].PackageVersion.GetPackage().GetName())
				assert.Equal(t, "v1.6.0", parsed.InstallTargets[0].PackageVersion.GetVersion())
				assert.True(t, parsed.IsInstallationCommand())
				assert.True(t, parsed.MayDownloadPackages())
				assert.False(t, parsed.IsKnownNonDownloadCommand)
			},
		},
		{
			name:    "go run remote module target without explicit version",
			command: "go run github.com/google/uuid",
			assert: func(t *testing.T, parsed *ParsedCommand, err error) {
				require.NoError(t, err)
				require.Len(t, parsed.InstallTargets, 1)
				assert.Equal(t, "github.com/google/uuid", parsed.InstallTargets[0].PackageVersion.GetPackage().GetName())
				assert.Empty(t, parsed.InstallTargets[0].PackageVersion.GetVersion())
				assert.True(t, parsed.IsInstallationCommand())
				assert.True(t, parsed.MayDownloadPackages())
			},
		},
		{
			name:    "go run local package does not produce install target",
			command: "go run ./main.go",
			assert: func(t *testing.T, parsed *ParsedCommand, err error) {
				require.NoError(t, err)
				assert.Empty(t, parsed.InstallTargets)
				assert.False(t, parsed.IsInstallationCommand())
				assert.True(t, parsed.MayDownloadPackages())
				assert.False(t, parsed.IsKnownNonDownloadCommand)
			},
		},
		{
			name:    "go test is known non download command",
			command: "go test ./...",
			assert: func(t *testing.T, parsed *ParsedCommand, err error) {
				require.NoError(t, err)
				assert.True(t, parsed.IsKnownNonDownloadCommand)
				assert.False(t, parsed.MayDownloadPackages())
			},
		},
		{
			name:    "go build is known non download command",
			command: "go build ./...",
			assert: func(t *testing.T, parsed *ParsedCommand, err error) {
				require.NoError(t, err)
				assert.True(t, parsed.IsKnownNonDownloadCommand)
				assert.False(t, parsed.MayDownloadPackages())
			},
		},
		{
			name:    "go list remains unknown to keep proxy fail safe",
			command: "go list -m github.com/google/uuid",
			assert: func(t *testing.T, parsed *ParsedCommand, err error) {
				require.NoError(t, err)
				assert.False(t, parsed.IsKnownNonDownloadCommand)
				assert.True(t, parsed.MayDownloadPackages())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parts := strings.Fields(tc.command)
			parsed, err := pm.ParseCommand(parts)
			tc.assert(t, parsed, err)
		})
	}
}
