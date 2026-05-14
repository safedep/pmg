package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetValueInYAML(t *testing.T) {
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := SetValueInYAML([]byte(tt.input), tt.key, tt.value)
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
