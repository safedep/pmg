package registryurl

import (
	"strings"
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

func TestNormalizeDoesNotExposeMalformedURLCredentials(t *testing.T) {
	_, err := Normalize("https://user:super-secret@packages.test/%zz")
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "invalid url")
	assert.NotContains(t, err.Error(), "super-secret")
	assert.NotContains(t, err.Error(), "user:")
}

func TestNormalizeRejectsUncleanPathSegments(t *testing.T) {
	tests := []string{
		"https://packages.example.test//npm",
		"https://packages.example.test/npm//team",
		"https://packages.example.test/npm/./team",
		"https://packages.example.test/npm/../team",
		"https://packages.example.test/npm/%2e/team",
		"https://packages.example.test/npm/%2E%2E/team",
		"https://packages.example.test/npm/%2E./team",
	}

	for _, rawURL := range tests {
		t.Run(rawURL, func(t *testing.T) {
			_, err := Normalize(rawURL)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "must not contain empty or dot segments")
		})
	}
}

func TestHasUncleanPathSegments(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"", false},
		{"/", false},
		{"/npm", false},
		{"/npm/", false},
		{"/simple/demo/", false},
		{"/npm//team", true},
		{"//npm", true},
		{"/npm/./team", true},
		{"/npm/../team", true},
		{"/npm/%2e%2e/team", true},
		{"/npm/%2E./team", true},
		{"/npm/.%2e/team", true},
		{"/npm/a%2Fb/team", false}, // escaped slash is not a dot segment
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.want, HasUncleanPathSegments(tt.path))
		})
	}
}
