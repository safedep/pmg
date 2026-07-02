package packagemanager

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUvxExecutorParseCommand(t *testing.T) {
	pm, err := NewPypiPackageExecutor(DefaultUvxPackageExecutorConfig())
	assert.NoError(t, err)

	cases := []struct {
		name             string
		args             []string
		expectedTargets  int
		expectedPackages []string
	}{
		{
			name:             "simple tool",
			args:             []string{"ruff"},
			expectedTargets:  1,
			expectedPackages: []string{"ruff"},
		},
		{
			name:             "tool with its own args is not a package",
			args:             []string{"ruff", "check", "."},
			expectedTargets:  1,
			expectedPackages: []string{"ruff"},
		},
		{
			name:             "tool with its own flags is not parsed as uvx flags",
			args:             []string{"ruff", "--fix", "--no-cache"},
			expectedTargets:  1,
			expectedPackages: []string{"ruff"},
		},
		{
			name:             "version pin via @ syntax",
			args:             []string{"ruff@0.3.0"},
			expectedTargets:  1,
			expectedPackages: []string{"ruff"},
		},
		{
			name:             "version @latest drops constraint",
			args:             []string{"ruff@latest"},
			expectedTargets:  1,
			expectedPackages: []string{"ruff"},
		},
		{
			name:             "version pin via == specifier",
			args:             []string{"ruff==0.3.0"},
			expectedTargets:  1,
			expectedPackages: []string{"ruff"},
		},
		{
			name:             "extras with version",
			args:             []string{"mypy[faster-cache]@1.0.0"},
			expectedTargets:  1,
			expectedPackages: []string{"mypy"},
		},
		{
			name:             "--from overrides positional command",
			args:             []string{"--from", "httpie", "http"},
			expectedTargets:  1,
			expectedPackages: []string{"httpie"},
		},
		{
			name:             "--from with version and positional command",
			args:             []string{"--from", "ruff==0.3.0", "ruff", "--check", "."},
			expectedTargets:  1,
			expectedPackages: []string{"ruff"},
		},
		{
			name:             "--from with @ version",
			args:             []string{"--from", "ruff@0.3.0", "ruff"},
			expectedTargets:  1,
			expectedPackages: []string{"ruff"},
		},
		{
			name:             "--with adds extra packages",
			args:             []string{"--with", "rich", "mkdocs"},
			expectedTargets:  2,
			expectedPackages: []string{"mkdocs", "rich"},
		},
		{
			name:             "repeated --with collects all",
			args:             []string{"--with", "rich", "--with", "pygments", "mkdocs"},
			expectedTargets:  3,
			expectedPackages: []string{"mkdocs", "rich", "pygments"},
		},
		{
			name:             "--with shorthand -w",
			args:             []string{"-w", "rich", "mkdocs"},
			expectedTargets:  2,
			expectedPackages: []string{"mkdocs", "rich"},
		},
		{
			name:             "--from combined with --with",
			args:             []string{"--from", "mkdocs-material", "--with", "mkdocs", "mkdocs"},
			expectedTargets:  2,
			expectedPackages: []string{"mkdocs-material", "mkdocs"},
		},
		{
			name:             "value flag does not consume the package",
			args:             []string{"--python", "3.12", "ruff"},
			expectedTargets:  1,
			expectedPackages: []string{"ruff"},
		},
		{
			name:             "boolean flag does not consume the package",
			args:             []string{"--isolated", "ruff"},
			expectedTargets:  1,
			expectedPackages: []string{"ruff"},
		},
		{
			name:             "reinstall boolean does not consume the package",
			args:             []string{"--reinstall", "ruff"},
			expectedTargets:  1,
			expectedPackages: []string{"ruff"},
		},
		{
			name:             "no-cache shorthand does not consume the package",
			args:             []string{"-n", "ruff"},
			expectedTargets:  1,
			expectedPackages: []string{"ruff"},
		},
		{
			name:             "index url value flag",
			args:             []string{"--index-url", "https://example.com/simple", "ruff"},
			expectedTargets:  1,
			expectedPackages: []string{"ruff"},
		},
		{
			name:            "git+ spec is skipped",
			args:            []string{"--from", "git+https://github.com/foo/bar@v1", "bar"},
			expectedTargets: 0,
		},
		{
			name:            "url spec is skipped",
			args:            []string{"https://example.com/pkg.whl"},
			expectedTargets: 0,
		},
		{
			name:            "local path spec is skipped",
			args:            []string{"./local-tool"},
			expectedTargets: 0,
		},
		{
			name:            "bare uvx invocation",
			args:            []string{},
			expectedTargets: 0,
		},
		{
			name:            "uvx prefix is stripped",
			args:            []string{"uvx", "ruff"},
			expectedTargets: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := pm.ParseCommand(tc.args)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedTargets, len(result.InstallTargets), "number of install targets mismatch")

			for i, expectedPkg := range tc.expectedPackages {
				if i < len(result.InstallTargets) {
					assert.Equal(t, expectedPkg, result.InstallTargets[i].PackageVersion.Package.Name, "package name mismatch for target %d", i)
				}
			}
		})
	}
}

// TestUvxExecutorParseCommandVersions pins the resolved name/version and the
// explicit-version flag for pinned specs. These cases use exact versions so no
// registry lookup is needed.
func TestUvxExecutorParseCommandVersions(t *testing.T) {
	pm, err := NewPypiPackageExecutor(DefaultUvxPackageExecutorConfig())
	assert.NoError(t, err)

	cases := []struct {
		name            string
		args            []string
		expectedName    string
		expectedVersion string
	}{
		{
			name:            "positional @ version",
			args:            []string{"ruff@0.3.0", "check"},
			expectedName:    "ruff",
			expectedVersion: "0.3.0",
		},
		{
			name:            "positional == version",
			args:            []string{"ruff==0.3.0"},
			expectedName:    "ruff",
			expectedVersion: "0.3.0",
		},
		{
			name:            "--from with == version",
			args:            []string{"--from", "httpie==3.2.2", "http"},
			expectedName:    "httpie",
			expectedVersion: "3.2.2",
		},
		{
			name:            "--from= with extras and version",
			args:            []string{"--from=mypy[faster-cache,reports]==1.13.0", "mypy", "--xml-report", "report"},
			expectedName:    "mypy",
			expectedVersion: "1.13.0",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := pm.ParseCommand(tc.args)
			assert.NoError(t, err)
			assert.Len(t, result.InstallTargets, 1)

			target := result.InstallTargets[0]
			assert.Equal(t, tc.expectedName, target.PackageVersion.Package.Name)
			assert.Equal(t, tc.expectedVersion, target.PackageVersion.Version)
			assert.True(t, target.IsExplicitVersion, "pinned spec should be marked as explicit version")
		})
	}
}

func TestUvxExecutorProxyBehavior(t *testing.T) {
	pm, err := NewPypiPackageExecutor(DefaultUvxPackageExecutorConfig())
	assert.NoError(t, err)

	cases := []struct {
		name    string
		command string
	}{
		{name: "uvx tool run downloads", command: "uvx ruff"},
		{name: "uvx --from run downloads", command: "uvx --from httpie http"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := pm.ParseCommand(strings.Split(tc.command, " "))
			assert.NoError(t, err)

			// uvx always runs a tool, so it always may download packages and is
			// never a known non-download command.
			assert.False(t, parsed.IsKnownNonDownloadCommand)
			assert.True(t, parsed.MayDownloadPackages())
			assert.True(t, parsed.IsInstallationCommand())
		})
	}
}

func TestUvxNormalizeSpec(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"ruff", "ruff"},
		{"ruff@0.3.0", "ruff==0.3.0"},
		{"ruff@latest", "ruff"},
		{"ruff@", "ruff"},
		{"ruff@>=0.3.0", "ruff>=0.3.0"},
		{"ruff==0.3.0", "ruff==0.3.0"},
		{"mypy[faster-cache]@1.0.0", "mypy[faster-cache]==1.0.0"},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			assert.Equal(t, tc.expected, uvxNormalizeSpec(tc.input))
		})
	}
}

func TestUvxIsAuditableSpec(t *testing.T) {
	cases := []struct {
		input     string
		auditable bool
	}{
		{"ruff", true},
		{"ruff@0.3.0", true},
		{"mypy[faster-cache]", true},
		{"", false},
		{"git+https://github.com/foo/bar", false},
		{"https://example.com/pkg.whl", false},
		{"file:///tmp/pkg", false},
		{"./local", false},
		{"../local", false},
		{"~/tool", false},
		{"/abs/path", false},
		{"dist/pkg.tar.gz", false},
		{"pkg.whl", false},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			assert.Equal(t, tc.auditable, uvxIsAuditableSpec(tc.input))
		})
	}
}
