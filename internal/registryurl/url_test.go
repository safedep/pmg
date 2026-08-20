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

func TestEffectivePort(t *testing.T) {
	tests := []struct {
		scheme string
		port   string
		want   string
		ok     bool
	}{
		{"https", "", "443", true},
		{"http", "", "80", true},
		{"https", "8443", "8443", true},
		{"http", "8080", "8080", true},
		{"HTTPS", "443", "443", true}, // scheme case normalized
		{"https", "443", "443", true},
		{"https", "080", "80", true}, // leading zeros canonicalized
		{"https", "0", "", false},
		{"https", "65536", "", false},
		{"https", "abc", "", false},
		{"https", "443x", "", false},
		{"ftp", "", "", false}, // unknown scheme, no default
		{"ftp", "21", "21", true},
	}

	for _, tt := range tests {
		t.Run(tt.scheme+"/"+tt.port, func(t *testing.T) {
			got, ok := EffectivePort(tt.scheme, tt.port)
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNormalizeEscapedPath(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/npm/team", "/npm/team"},
		{"/npm/%2fteam", "/npm/%2Fteam"}, // lowercase hex uppercased
		{"/npm/%2Fteam", "/npm/%2Fteam"},
		// Invalid/truncated escapes: the normalizer uppercases any %XY pair it
		// finds (lossy for invalid input), but Normalize rejects such URLs at
		// parse time, so this never reaches a match.
		{"/npm/%zz/team", "/npm/%ZZ/team"},
		{"/npm/%2", "/npm/%2"},
		{"/@scope%2Fname", "/@scope%2Fname"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.want, NormalizeEscapedPath(tt.path))
		})
	}
}

func TestNormalizeBasePath(t *testing.T) {
	assert.Equal(t, "/npm", NormalizeBasePath("/npm/"))
	assert.Equal(t, "/npm", NormalizeBasePath("/npm///"))
	assert.Equal(t, "", NormalizeBasePath("///"))
	assert.Equal(t, "/npm/%2Fteam", NormalizeBasePath("/npm/%2fteam/"))
}
