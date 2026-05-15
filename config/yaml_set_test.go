package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
	"github.com/goccy/go-yaml/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_setValueInYAML(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		key      string
		value    string
		expected string
		wantErr  string
	}{
		{
			name:     "set top-level bool to true",
			input:    "transitive: true\nparanoid: false\n",
			key:      "paranoid",
			value:    "true",
			expected: "transitive: true\nparanoid: true\n",
		},
		{
			name:     "set top-level bool to false",
			input:    "transitive: true\nparanoid: true\n",
			key:      "paranoid",
			value:    "false",
			expected: "transitive: true\nparanoid: false\n",
		},
		{
			name:     "set top-level integer",
			input:    "transitive_depth: 5\n",
			key:      "transitive_depth",
			value:    "10",
			expected: "transitive_depth: 10\n",
		},
		{
			name:     "set top-level string",
			input:    "verbosity: normal\n",
			key:      "verbosity",
			value:    "verbose",
			expected: "verbosity: verbose\n",
		},
		{
			name:     "set nested key",
			input:    "cloud:\n  enabled: false\n  endpoint_id: \"\"\n",
			key:      "cloud.enabled",
			value:    "true",
			expected: "cloud:\n  enabled: true\n  endpoint_id: \"\"\n",
		},
		{
			name:     "set deeply nested key",
			input:    "dependency_cooldown:\n  enabled: true\n  days: 5\n",
			key:      "dependency_cooldown.days",
			value:    "10",
			expected: "dependency_cooldown:\n  enabled: true\n  days: 10\n",
		},
		{
			name:     "preserve comments",
			input:    "# Important setting\ntransitive: true\n# Paranoid mode\nparanoid: false\n",
			key:      "paranoid",
			value:    "true",
			expected: "# Important setting\ntransitive: true\n# Paranoid mode\nparanoid: true\n",
		},
		{
			name:     "set string with spaces",
			input:    "verbosity: normal\n",
			key:      "verbosity",
			value:    "my custom value",
			expected: "verbosity: my custom value\n",
		},
		{
			name:     "set same value is idempotent",
			input:    "paranoid: false\n",
			key:      "paranoid",
			value:    "false",
			expected: "paranoid: false\n",
		},
		{
			name:    "error on empty key",
			input:   "transitive: true\n",
			key:     "",
			value:   "false",
			wantErr: "key cannot be empty",
		},
		{
			name:    "error on nonexistent key",
			input:   "transitive: true\n",
			key:     "nonexistent",
			value:   "false",
			wantErr: "key not found",
		},
		{
			name:    "error on nonexistent nested key",
			input:   "cloud:\n  enabled: false\n",
			key:     "cloud.nonexistent",
			value:   "true",
			wantErr: "key not found",
		},
		{
			name:    "error when setting non-leaf node",
			input:   "cloud:\n  enabled: false\n",
			key:     "cloud",
			value:   "true",
			wantErr: "cannot set value on non-scalar node",
		},
		{
			name:    "error when intermediate key is not a mapping",
			input:   "transitive: true\n",
			key:     "transitive.nested",
			value:   "true",
			wantErr: "intermediate key",
		},
		{
			name:    "error on sequence node target",
			input:   "trusted_packages:\n  - purl: pkg:npm/foo\n    reason: test\n",
			key:     "trusted_packages",
			value:   "true",
			wantErr: "cannot set value on non-scalar node",
		},
		{
			name:    "error on invalid bool value",
			input:   "paranoid: false\n",
			key:     "paranoid",
			value:   "falce",
			wantErr: "invalid value",
		},
		{
			name:    "error on non-integer for integer field",
			input:   "transitive_depth: 5\n",
			key:     "transitive_depth",
			value:   "abc",
			wantErr: "invalid value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := setValueInYAML([]byte(tt.input), tt.key, tt.value)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expected, string(result))
		})
	}
}

func Test_createScalarNode(t *testing.T) {
	pos := &token.Position{Line: 1, Column: 1, Offset: 0}

	tests := []struct {
		name         string
		value        string
		expectedType ast.NodeType
	}{
		{name: "true is bool", value: "true", expectedType: ast.BoolType},
		{name: "false is bool", value: "false", expectedType: ast.BoolType},
		{name: "positive int", value: "42", expectedType: ast.IntegerType},
		{name: "zero is int", value: "0", expectedType: ast.IntegerType},
		{name: "negative int", value: "-5", expectedType: ast.IntegerType},
		{name: "plain string", value: "hello", expectedType: ast.StringType},
		{name: "float-like is string", value: "3.14", expectedType: ast.StringType},
		{name: "True (capitalized) is string", value: "True", expectedType: ast.StringType},
		{name: "empty string", value: "", expectedType: ast.StringType},
		{name: "numeric-prefix string", value: "123abc", expectedType: ast.StringType},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node, err := createScalarNode(tt.value, pos)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedType, node.Type())
		})
	}
}

func TestSetConfigValue(t *testing.T) {
	t.Run("creates config from template and sets value", func(t *testing.T) {
		tmpDir := t.TempDir()
		t.Setenv("PMG_CONFIG_DIR", tmpDir)
		initConfig()

		err := SetConfigValue("paranoid", "true")
		require.NoError(t, err)

		data, err := os.ReadFile(filepath.Join(tmpDir, "config.yml"))
		require.NoError(t, err)
		assert.Contains(t, string(data), "paranoid: true")
	})

	t.Run("updates existing config preserving other values", func(t *testing.T) {
		tmpDir := t.TempDir()
		t.Setenv("PMG_CONFIG_DIR", tmpDir)
		initConfig()

		configPath := filepath.Join(tmpDir, "config.yml")
		err := os.WriteFile(configPath, []byte("transitive: true\nparanoid: false\n"), 0o644)
		require.NoError(t, err)

		err = SetConfigValue("paranoid", "true")
		require.NoError(t, err)

		data, err := os.ReadFile(configPath)
		require.NoError(t, err)
		assert.Contains(t, string(data), "transitive: true")
		assert.Contains(t, string(data), "paranoid: true")
	})

	t.Run("returns error for nonexistent key", func(t *testing.T) {
		tmpDir := t.TempDir()
		t.Setenv("PMG_CONFIG_DIR", tmpDir)
		initConfig()

		err := os.WriteFile(filepath.Join(tmpDir, "config.yml"), []byte("paranoid: false\n"), 0o644)
		require.NoError(t, err)

		err = SetConfigValue("nonexistent", "true")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key not found")
	})
}

func TestGetConfigValue(t *testing.T) {
	configYAML := "paranoid: true\ntransitive: false\ntransitive_depth: 10\nverbosity: verbose\n" +
		"cloud:\n  enabled: true\n  endpoint_id: ep-123\n" +
		"dependency_cooldown:\n  enabled: true\n  days: 7\n" +
		"proxy:\n  enabled: false\n  install_only: true\n" +
		"sandbox:\n  enabled: true\n  enforce_always: false\n"

	setupConfig := func(t *testing.T) {
		t.Helper()
		tmpDir := t.TempDir()
		t.Setenv("PMG_CONFIG_DIR", tmpDir)
		err := os.WriteFile(filepath.Join(tmpDir, "config.yml"), []byte(configYAML), 0o644)
		require.NoError(t, err)
		initConfig()
	}

	tests := []struct {
		name     string
		key      string
		expected any
		wantErr  string
	}{
		{name: "top-level bool true", key: "paranoid", expected: true},
		{name: "top-level bool false", key: "transitive", expected: false},
		{name: "top-level integer", key: "transitive_depth", expected: 10},
		{name: "top-level string", key: "verbosity", expected: "verbose"},
		{name: "nested bool", key: "cloud.enabled", expected: true},
		{name: "nested string", key: "cloud.endpoint_id", expected: "ep-123"},
		{name: "nested integer", key: "dependency_cooldown.days", expected: 7},
		{name: "nested bool under proxy", key: "proxy.enabled", expected: false},
		{name: "nested bool under proxy install_only", key: "proxy.install_only", expected: true},
		{name: "nested bool under sandbox", key: "sandbox.enabled", expected: true},
		{name: "nested bool under sandbox enforce_always", key: "sandbox.enforce_always", expected: false},
		{name: "error on empty key", key: "", wantErr: "key cannot be empty"},
		{name: "error on unknown top-level key", key: "totally_bogus", wantErr: "unknown config key"},
		{name: "error on unknown nested key", key: "cloud.nonexistent", wantErr: "unknown config key"},
		{name: "error on too-deep key", key: "cloud.enabled.deep", wantErr: "unknown config key"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupConfig(t)

			val, err := GetConfigValue(tt.key)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expected, val)
		})
	}

	t.Run("returns nested object as map", func(t *testing.T) {
		setupConfig(t)

		val, err := GetConfigValue("cloud")
		require.NoError(t, err)

		m, ok := val.(map[string]any)
		require.True(t, ok, "expected map[string]any, got %T", val)
		assert.Equal(t, true, m["enabled"])
		assert.Equal(t, "ep-123", m["endpoint_id"])
	})

	t.Run("returns defaults when no config file exists", func(t *testing.T) {
		t.Setenv("PMG_CONFIG_DIR", "/tmp/pmg-test/random-does-not-exist")
		initConfig()

		val, err := GetConfigValue("transitive")
		require.NoError(t, err)
		assert.Equal(t, true, val)

		val, err = GetConfigValue("paranoid")
		require.NoError(t, err)
		assert.Equal(t, false, val)
	})

	t.Run("env var overrides config file", func(t *testing.T) {
		tmpDir := t.TempDir()
		t.Setenv("PMG_CONFIG_DIR", tmpDir)
		t.Setenv("PMG_PARANOID", "true")

		err := os.WriteFile(filepath.Join(tmpDir, "config.yml"), []byte("paranoid: false\n"), 0o644)
		require.NoError(t, err)

		initConfig()

		val, err := GetConfigValue("paranoid")
		require.NoError(t, err)
		// Viper returns env var values as strings
		assert.Equal(t, "true", val)
	})
}

func TestSetStringFieldPreservesType(t *testing.T) {
	tests := []struct {
		name  string
		input string
		key   string
		value string
	}{
		{
			name:  "string field set to bool-like value stays string",
			input: "verbosity: normal\n",
			key:   "verbosity",
			value: "true",
		},
		{
			name:  "string field set to integer-like value stays string",
			input: "verbosity: normal\n",
			key:   "verbosity",
			value: "42",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := setValueInYAML([]byte(tt.input), tt.key, tt.value)
			require.NoError(t, err)

			file, err := parser.ParseBytes(result, parser.ParseComments)
			require.NoError(t, err)

			root := file.Docs[0].Body.(*ast.MappingNode)
			for _, mv := range root.Values {
				if mv.Key.String() == tt.key {
					assert.Equal(t, ast.StringType, mv.Value.Type(),
						"expected StringType but got %s", mv.Value.Type())
					return
				}
			}
			t.Fatalf("key %q not found in result", tt.key)
		})
	}
}

func Test_needsQuoting(t *testing.T) {
	tests := []struct {
		value    string
		expected bool
	}{
		{"true", true},
		{"false", true},
		{"True", true},
		{"False", true},
		{"yes", true},
		{"no", true},
		{"null", true},
		{"42", true},
		{"-5", true},
		{"0", true},
		{"3.14", true},
		{"hello", false},
		{"normal", false},
		{"verbose", false},
		{"", false},
		{"123abc", false},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			assert.Equal(t, tt.expected, needsQuoting(tt.value))
		})
	}
}

func TestSetThenGetRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("PMG_CONFIG_DIR", tmpDir)

	configPath := filepath.Join(tmpDir, "config.yml")
	err := os.WriteFile(configPath, []byte("paranoid: false\ntransitive_depth: 5\nverbosity: normal\n"), 0o644)
	require.NoError(t, err)

	initConfig()

	err = SetConfigValue("paranoid", "true")
	require.NoError(t, err)

	err = SetConfigValue("transitive_depth", "20")
	require.NoError(t, err)

	err = SetConfigValue("verbosity", "silent")
	require.NoError(t, err)

	// Reload global config from file to pick up changes
	initConfig()

	val, err := GetConfigValue("paranoid")
	require.NoError(t, err)
	assert.Equal(t, true, val)

	val, err = GetConfigValue("transitive_depth")
	require.NoError(t, err)
	assert.Equal(t, 20, val)

	val, err = GetConfigValue("verbosity")
	require.NoError(t, err)
	assert.Equal(t, "silent", val)
}
