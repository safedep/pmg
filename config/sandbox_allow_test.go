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
