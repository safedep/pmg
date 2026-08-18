package registryurl

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeIsIdempotent(t *testing.T) {
	tests := []string{
		"https://packages.example.test/npm//",
		"https://packages.example.test///",
		"https://packages.example.test/npm/%2fteam///",
	}

	for _, rawURL := range tests {
		t.Run(rawURL, func(t *testing.T) {
			once, err := Normalize(rawURL)
			require.NoError(t, err)
			twice, err := Normalize(once)
			require.NoError(t, err)

			assert.Equal(t, once, twice)
		})
	}
}
