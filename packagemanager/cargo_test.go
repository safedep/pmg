package packagemanager

import (
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCargoPackageManagerParseCommand(t *testing.T) {
	type target struct {
		name     string
		version  string
		explicit bool
	}

	cases := []struct {
		name            string
		args            []string
		nonDownload     bool
		manifestInstall bool
		targets         []target
	}{
		{
			name:        "cargo version is non-download",
			args:        []string{"cargo", "version"},
			nonDownload: true,
		},
		{
			name:        "cargo clean is non-download",
			args:        []string{"cargo", "clean"},
			nonDownload: true,
		},
		{
			name:        "cargo new is non-download",
			args:        []string{"cargo", "new", "myproject"},
			nonDownload: true,
		},
		{
			name: "cargo metadata is not non-download (resolves the graph, can fetch the index)",
			args: []string{"cargo", "metadata"},
		},
		{
			name: "cargo fmt is not non-download (resolves workspace metadata)",
			args: []string{"cargo", "fmt"},
		},
		{
			name:            "cargo build is manifest install",
			args:            []string{"cargo", "build", "--release"},
			manifestInstall: true,
		},
		{
			name:            "cargo run alias is manifest install",
			args:            []string{"cargo", "r"},
			manifestInstall: true,
		},
		{
			name:            "cargo test is manifest install",
			args:            []string{"cargo", "test"},
			manifestInstall: true,
		},
		{
			name:            "cargo fetch is manifest install",
			args:            []string{"cargo", "fetch"},
			manifestInstall: true,
		},
		{
			name:            "cargo update is manifest install",
			args:            []string{"cargo", "update"},
			manifestInstall: true,
		},
		{
			name:    "cargo add with exact version is explicit",
			args:    []string{"cargo", "add", "serde@1.0.219"},
			targets: []target{{name: "serde", version: "1.0.219", explicit: true}},
		},
		{
			name:    "cargo add with caret requirement is not explicit",
			args:    []string{"cargo", "add", "serde@^1.0"},
			targets: []target{{name: "serde", version: "^1.0", explicit: false}},
		},
		{
			name:    "cargo add without version",
			args:    []string{"cargo", "add", "tokio"},
			targets: []target{{name: "tokio", version: "", explicit: false}},
		},
		{
			name: "cargo add multiple crates with feature flag value skipped",
			args: []string{"cargo", "add", "serde@1.0.219", "--features", "derive", "tokio"},
			targets: []target{
				{name: "serde", version: "1.0.219", explicit: true},
				{name: "tokio", version: "", explicit: false},
			},
		},
		{
			name: "cargo add dev dependency",
			args: []string{"cargo", "add", "--dev", "mockall@0.13.1"},
			targets: []target{
				{name: "mockall", version: "0.13.1", explicit: true},
			},
		},
		{
			name:            "cargo add path dependency yields no registry target",
			args:            []string{"cargo", "add", "--path", "../mylib"},
			manifestInstall: true,
		},
		{
			name:            "cargo add git dependency yields no registry target",
			args:            []string{"cargo", "add", "--git", "https://github.com/x/y", "ylib"},
			manifestInstall: false,
			targets:         []target{{name: "ylib", version: "", explicit: false}},
		},
		{
			name:    "cargo install with at version",
			args:    []string{"cargo", "install", "ripgrep@14.1.1"},
			targets: []target{{name: "ripgrep", version: "14.1.1", explicit: true}},
		},
		{
			name:    "cargo install with version flag",
			args:    []string{"cargo", "install", "ripgrep", "--version", "14.1.1"},
			targets: []target{{name: "ripgrep", version: "14.1.1", explicit: true}},
		},
		{
			name:    "cargo install with version flag equals form",
			args:    []string{"cargo", "install", "--version=14.1.1", "ripgrep"},
			targets: []target{{name: "ripgrep", version: "14.1.1", explicit: true}},
		},
		{
			name:            "cargo install local path is manifest install",
			args:            []string{"cargo", "install", "--path", "."},
			manifestInstall: true,
		},
		{
			name: "no subcommand",
			args: []string{"cargo"},
		},
	}

	pm, err := NewCargoPackageManager(DefaultCargoPackageManagerConfig())
	require.NoError(t, err)

	assert.Equal(t, "cargo", pm.Name())
	assert.Equal(t, packagev1.Ecosystem_ECOSYSTEM_CARGO, pm.Ecosystem())

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := pm.ParseCommand(tc.args)
			require.NoError(t, err)

			assert.Equal(t, tc.nonDownload, parsed.IsKnownNonDownloadCommand)
			assert.Equal(t, tc.manifestInstall, parsed.IsManifestInstall)

			require.Len(t, parsed.InstallTargets, len(tc.targets))
			for i, want := range tc.targets {
				got := parsed.InstallTargets[i]
				assert.Equal(t, want.name, got.PackageVersion.GetPackage().GetName())
				assert.Equal(t, want.version, got.PackageVersion.GetVersion())
				assert.Equal(t, want.explicit, got.IsExplicitVersion)
				assert.Equal(t, packagev1.Ecosystem_ECOSYSTEM_CARGO, got.PackageVersion.GetPackage().GetEcosystem())
			}
		})
	}
}

func TestCargoExactVersion(t *testing.T) {
	cases := []struct {
		version string
		want    bool
	}{
		{"1.0.219", true},
		{"0.1.0-alpha.1", true},
		{"1.2.3+build.5", true},
		{"1.0", false},
		{"^1.0.3", false},
		{"~1.2", false},
		{">=1.0, <2.0", false},
		{"*", false},
		{"latest", false},
		{"", false},
	}

	for _, tc := range cases {
		assert.Equal(t, tc.want, cargoExactVersion.MatchString(tc.version), "version %q", tc.version)
	}
}
