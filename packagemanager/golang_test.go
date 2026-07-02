package packagemanager

import (
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGoPackageManagerParseCommand(t *testing.T) {
	type target struct {
		name     string
		version  string
		explicit bool
	}

	cases := []struct {
		name              string
		args              []string
		nonDownload       bool
		manifestInstall   bool
		targets           []target
		wantManifestFiles []string
	}{
		{
			name:        "go version is non-download",
			args:        []string{"go", "version"},
			nonDownload: true,
		},
		{
			name:        "go env is non-download",
			args:        []string{"go", "env", "GOPROXY"},
			nonDownload: true,
		},
		{
			name: "go vet is not non-download (can fetch on cold cache)",
			args: []string{"go", "vet", "./..."},
		},
		{
			name: "go build runs with proxy",
			args: []string{"go", "build", "./..."},
		},
		{
			name:    "go get with canonical version",
			args:    []string{"go", "get", "github.com/x/y@v1.2.3"},
			targets: []target{{name: "github.com/x/y", version: "v1.2.3", explicit: true}},
		},
		{
			name:    "go get with pseudo-version is explicit",
			args:    []string{"go", "get", "github.com/x/y@v0.0.0-20191109021931-daa7c04131f5"},
			targets: []target{{name: "github.com/x/y", version: "v0.0.0-20191109021931-daa7c04131f5", explicit: true}},
		},
		{
			name:    "go install with latest query is not explicit",
			args:    []string{"go", "install", "github.com/x/y/cmd/y@latest"},
			targets: []target{{name: "github.com/x/y/cmd/y", version: "latest", explicit: false}},
		},
		{
			name:    "go get with branch query is not explicit",
			args:    []string{"go", "get", "github.com/x/y@master"},
			targets: []target{{name: "github.com/x/y", version: "master", explicit: false}},
		},
		{
			name: "go install local path yields no target",
			args: []string{"go", "install", "./cmd/foo"},
		},
		{
			name: "go run current dir yields no target",
			args: []string{"go", "run", "."},
		},
		{
			name:    "go get without version",
			args:    []string{"go", "get", "example.com/m"},
			targets: []target{{name: "example.com/m", version: "", explicit: false}},
		},
		{
			name:    "flags before target are skipped",
			args:    []string{"go", "get", "-u", "example.com/m@v2.0.0"},
			targets: []target{{name: "example.com/m", version: "v2.0.0", explicit: true}},
		},
		{
			name:              "go mod tidy is manifest install",
			args:              []string{"go", "mod", "tidy"},
			manifestInstall:   true,
			wantManifestFiles: []string{"go.mod"},
		},
		{
			name:              "go mod download without args is manifest install",
			args:              []string{"go", "mod", "download"},
			manifestInstall:   true,
			wantManifestFiles: []string{"go.mod"},
		},
		{
			name:    "go mod download with module",
			args:    []string{"go", "mod", "download", "example.com/m@v1.0.0"},
			targets: []target{{name: "example.com/m", version: "v1.0.0", explicit: true}},
		},
		{
			name: "no subcommand",
			args: []string{"go"},
		},
	}

	pm, err := NewGoPackageManager(DefaultGoPackageManagerConfig())
	require.NoError(t, err)

	assert.Equal(t, "go", pm.Name())
	assert.Equal(t, packagev1.Ecosystem_ECOSYSTEM_GO, pm.Ecosystem())

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := pm.ParseCommand(tc.args)
			require.NoError(t, err)

			assert.Equal(t, tc.nonDownload, parsed.IsKnownNonDownloadCommand)
			assert.Equal(t, tc.manifestInstall, parsed.IsManifestInstall)
			assert.Equal(t, tc.wantManifestFiles, parsed.ManifestFiles)

			require.Len(t, parsed.InstallTargets, len(tc.targets))
			for i, want := range tc.targets {
				got := parsed.InstallTargets[i]
				assert.Equal(t, want.name, got.PackageVersion.GetPackage().GetName())
				assert.Equal(t, want.version, got.PackageVersion.GetVersion())
				assert.Equal(t, want.explicit, got.IsExplicitVersion)
				assert.Equal(t, packagev1.Ecosystem_ECOSYSTEM_GO, got.PackageVersion.GetPackage().GetEcosystem())
			}
		})
	}
}

func TestIsGoRemoteModuleTarget(t *testing.T) {
	cases := []struct {
		target string
		want   bool
	}{
		{"github.com/x/y", true},
		{"example.com/m@v1.0.0", true},
		{"gopkg.in/yaml.v3", true},
		{".", false},
		{"..", false},
		{"./cmd/foo", false},
		{"../pkg", false},
		{"/abs/path", false},
		{"./...", false},
		{"...", false},
		{`a\b`, false},
		{"", false},
		{"fmt", false},
		{"cmd/foo", false},
	}

	for _, tc := range cases {
		assert.Equal(t, tc.want, isGoRemoteModuleTarget(tc.target), "target %q", tc.target)
	}
}
