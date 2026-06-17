package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSandboxAllowOverrides_ValidFormats(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)

	tests := []struct {
		name          string
		raw           string
		expectedType  SandboxAllowType
		expectedValue string
	}{
		{
			name:          "write with relative path",
			raw:           "write=./.gitignore",
			expectedType:  SandboxAllowWrite,
			expectedValue: filepath.Join(cwd, ".gitignore"),
		},
		{
			name:          "write with absolute path",
			raw:           "write=/tmp/output",
			expectedType:  SandboxAllowWrite,
			expectedValue: "/tmp/output",
		},
		{
			name:          "write with glob pattern",
			raw:           "write=./dist/**",
			expectedType:  SandboxAllowWrite,
			expectedValue: filepath.Join(cwd, "dist/**"),
		},
		{
			name:          "read with absolute path",
			raw:           "read=/opt/config/registry.json",
			expectedType:  SandboxAllowRead,
			expectedValue: "/opt/config/registry.json",
		},
		{
			name:          "read with glob pattern",
			raw:           "read=./src/**",
			expectedType:  SandboxAllowRead,
			expectedValue: filepath.Join(cwd, "src/**"),
		},
		{
			name:          "exec with absolute path",
			raw:           "exec=/usr/bin/curl",
			expectedType:  SandboxAllowExec,
			expectedValue: "/usr/bin/curl",
		},
		{
			name:          "net-connect with host:port",
			raw:           "net-connect=registry.npmjs.org:443",
			expectedType:  SandboxAllowNetConnect,
			expectedValue: "registry.npmjs.org:443",
		},
		{
			name:          "net-bind with localhost",
			raw:           "net-bind=127.0.0.1:3000",
			expectedType:  SandboxAllowNetBind,
			expectedValue: "127.0.0.1:3000",
		},
		{
			name:          "net-bind with localhost wildcard port",
			raw:           "net-bind=localhost:*",
			expectedType:  SandboxAllowNetBind,
			expectedValue: "localhost:*",
		},
		{
			name:          "write with relative path no dot prefix",
			raw:           "write=dist/output",
			expectedType:  SandboxAllowWrite,
			expectedValue: filepath.Join(cwd, "dist/output"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			overrides, err := parseSandboxAllowOverrides([]string{tt.raw})
			require.NoError(t, err)
			require.Len(t, overrides, 1)

			assert.Equal(t, tt.expectedType, overrides[0].Type)
			assert.Equal(t, tt.expectedValue, overrides[0].Value)
			assert.Equal(t, tt.raw, overrides[0].Raw)
		})
	}
}

func TestParseSingleOverride_ExpandsSandboxVariables(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)

	home, err := os.UserHomeDir()
	require.NoError(t, err)

	tmpDir := os.TempDir()

	tests := []struct {
		name          string
		raw           string
		expectedType  SandboxAllowType
		expectedValue string
		notContains   string
	}{
		{
			name:          "write expands CWD glob",
			raw:           "write=${CWD}/**",
			expectedType:  SandboxAllowWrite,
			expectedValue: filepath.Clean(filepath.Join(cwd, "**")),
			notContains:   "${CWD}",
		},
		{
			name:          "read expands HOME",
			raw:           "read=${HOME}/x",
			expectedType:  SandboxAllowRead,
			expectedValue: filepath.Clean(filepath.Join(home, "x")),
			notContains:   "${HOME}",
		},
		{
			name:          "write expands TMPDIR",
			raw:           "write=${TMPDIR}/pmg-cache",
			expectedType:  SandboxAllowWrite,
			expectedValue: filepath.Clean(filepath.Join(tmpDir, "pmg-cache")),
			notContains:   "${TMPDIR}",
		},
		{
			name:          "exec expands CWD",
			raw:           "exec=${CWD}/bin/tool",
			expectedType:  SandboxAllowExec,
			expectedValue: filepath.Clean(filepath.Join(cwd, "bin", "tool")),
			notContains:   "${CWD}",
		},
		{
			name:          "absolute path without variables is unchanged",
			raw:           "write=/tmp/pmg-output",
			expectedType:  SandboxAllowWrite,
			expectedValue: filepath.Clean("/tmp/pmg-output"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSingleOverride(tt.raw)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedType, got.Type)
			assert.Equal(t, tt.expectedValue, got.Value)
			assert.Equal(t, tt.raw, got.Raw)
			if tt.notContains != "" {
				assert.NotContains(t, got.Value, tt.notContains)
			}
		})
	}
}

func TestParseSandboxAllowOverrides_Env(t *testing.T) {
	tests := []struct {
		name          string
		raw           string
		expectedValue string
	}{
		{name: "exact name", raw: "env=NPM_TOKEN", expectedValue: "NPM_TOKEN"},
		{name: "glob name kept verbatim", raw: "env=npm_config_*", expectedValue: "npm_config_*"},
		{name: "not path resolved", raw: "env=AWS_PROFILE", expectedValue: "AWS_PROFILE"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			overrides, err := parseSandboxAllowOverrides([]string{tt.raw})
			require.NoError(t, err)
			require.Len(t, overrides, 1)

			assert.Equal(t, SandboxAllowEnv, overrides[0].Type)
			// Value is kept verbatim, with no CWD/path resolution.
			assert.Equal(t, tt.expectedValue, overrides[0].Value)
		})
	}
}

func TestParseSandboxAllowOverrides_EnvInvalid(t *testing.T) {
	invalid := []string{
		"env=NPM/TOKEN",
		"env=FOO=BAR",
		"env=HAS SPACE",
		"env=HAS\tTAB",
		"env=HAS\nNEWLINE",
		"env=HAS\rRETURN",
		"env=BACK\\SLASH",
		"env=CTRL\x07CHAR",
	}

	for _, raw := range invalid {
		_, err := parseSandboxAllowOverrides([]string{raw})
		assert.Error(t, err, "expected error for %q", raw)
	}
}

func TestParseSandboxAllowOverrides_MultipleValues(t *testing.T) {
	raw := []string{
		"write=./.gitignore",
		"exec=/usr/bin/curl",
		"net-connect=example.com:443",
	}

	overrides, err := parseSandboxAllowOverrides(raw)
	require.NoError(t, err)
	require.Len(t, overrides, 3)

	assert.Equal(t, SandboxAllowWrite, overrides[0].Type)
	assert.Equal(t, SandboxAllowExec, overrides[1].Type)
	assert.Equal(t, SandboxAllowNetConnect, overrides[2].Type)
}

func TestParseSandboxAllowOverrides_EmptySlice(t *testing.T) {
	overrides, err := parseSandboxAllowOverrides([]string{})
	require.NoError(t, err)
	assert.Empty(t, overrides)
}

func TestParseSandboxAllowOverrides_InvalidFormats(t *testing.T) {
	tests := []struct {
		name        string
		raw         string
		errContains string
	}{
		{
			name:        "missing separator",
			raw:         "./foo",
			errContains: "missing '=' separator",
		},
		{
			name:        "missing type",
			raw:         "=./foo",
			errContains: "missing type before '='",
		},
		{
			name:        "empty value",
			raw:         "write=",
			errContains: "missing value after '='",
		},
		{
			name:        "unknown type",
			raw:         "foo=bar",
			errContains: "unknown type",
		},
		{
			name:        "net shorthand rejected",
			raw:         "net=host:443",
			errContains: "use net-connect or net-bind",
		},
		{
			name:        "exec with glob pattern",
			raw:         "exec=/usr/bin/*",
			errContains: "glob patterns are not allowed for exec",
		},
		{
			name:        "net-connect with wildcard host",
			raw:         "net-connect=*:443",
			errContains: "wildcards are not allowed for net-connect",
		},
		{
			name:        "net-connect with glob host",
			raw:         "net-connect=*.example.com:443",
			errContains: "wildcards are not allowed for net-connect",
		},
		{
			name:        "net-connect with wildcard port",
			raw:         "net-connect=example.com:*",
			errContains: "port wildcard is not allowed for net-connect",
		},
		{
			name:        "net-bind with host wildcard",
			raw:         "net-bind=*:3000",
			errContains: "host wildcards are not allowed for net-bind",
		},
		{
			name:        "net-bind with full wildcard",
			raw:         "net-bind=*:*",
			errContains: "host wildcards are not allowed for net-bind",
		},
		{
			name:        "net-connect missing port",
			raw:         "net-connect=example.com",
			errContains: "expected host:port format",
		},
		{
			name:        "net-bind missing port",
			raw:         "net-bind=localhost",
			errContains: "expected host:port format",
		},
		{
			name:        "tilde path for write",
			raw:         "write=~/file",
			errContains: "starts with '~'",
		},
		{
			name:        "tilde path for read",
			raw:         "read=~/.config/foo",
			errContains: "starts with '~'",
		},
		{
			name:        "tilde path for exec",
			raw:         "exec=~/bin/tool",
			errContains: "starts with '~'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseSandboxAllowOverrides([]string{tt.raw})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errContains)
		})
	}
}

func TestParseSandboxAllowOverrides_ValueWithEquals(t *testing.T) {
	// Values can contain '=' characters — the parser splits on the first '=' only
	overrides, err := parseSandboxAllowOverrides([]string{"write=./path=with=equals.txt"})
	require.NoError(t, err)
	require.Len(t, overrides, 1)

	cwd, err := os.Getwd()
	require.NoError(t, err)

	assert.Equal(t, SandboxAllowWrite, overrides[0].Type)
	assert.Equal(t, filepath.Join(cwd, "path=with=equals.txt"), overrides[0].Value)
}

func TestParseSandboxAllowOverrides_PathCleaning(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)

	// Paths with ".." are cleaned via filepath.Clean
	overrides, err := parseSandboxAllowOverrides([]string{"write=./foo/../bar"})
	require.NoError(t, err)
	require.Len(t, overrides, 1)

	assert.Equal(t, filepath.Join(cwd, "bar"), overrides[0].Value)
}

func TestParseSandboxAllowOverrides_NetBindNonLocalhost(t *testing.T) {
	// Non-localhost should succeed (with a warning logged, which we can't easily assert here)
	overrides, err := parseSandboxAllowOverrides([]string{"net-bind=0.0.0.0:3000"})
	require.NoError(t, err)
	require.Len(t, overrides, 1)

	assert.Equal(t, SandboxAllowNetBind, overrides[0].Type)
	assert.Equal(t, "0.0.0.0:3000", overrides[0].Value)
}

func TestParseSandboxAllowOverrides_FirstErrorStops(t *testing.T) {
	// If the first value is invalid, the second is not parsed
	_, err := parseSandboxAllowOverrides([]string{"write=./ok", "bad"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing '=' separator")
}

func TestParseSingleOverride_Exported(t *testing.T) {
	got, err := ParseSingleOverride("net-bind=localhost:4321")
	require.NoError(t, err)
	assert.Equal(t, SandboxAllowNetBind, got.Type)
	assert.Equal(t, "localhost:4321", got.Value)
	assert.Equal(t, "net-bind=localhost:4321", got.Raw)
}

func TestParseSingleOverride_ExportedRejectsInvalid(t *testing.T) {
	_, err := ParseSingleOverride("garbage")
	assert.Error(t, err)
}
