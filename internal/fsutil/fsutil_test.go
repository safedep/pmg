package fsutil

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPathWithinDir(t *testing.T) {
	assert.True(t, PathWithinDir("/usr/local/lib/pmg/bin", "/usr/local/lib/pmg/bin"))
	assert.True(t, PathWithinDir("/usr/local/lib/pmg/bin/npm", "/usr/local/lib/pmg/bin"))
	assert.False(t, PathWithinDir("/usr/local/bin/npm", "/usr/local/lib/pmg/bin"))
	assert.False(t, PathWithinDir("/usr/local/lib/pmg/bin-extra/npm", "/usr/local/lib/pmg/bin"))
	assert.False(t, PathWithinDir("/usr/local/bin/npm", ""))
	assert.False(t, PathWithinDir("", "/usr/local/bin"))
}

// Windows guarantees that one directory answers to every casing. No other
// platform does, so the same pair must not match there.
func TestPathComparisonFoldsCaseOnWindowsOnly(t *testing.T) {
	foldsCase := runtime.GOOS == "windows"

	assert.Equal(t, foldsCase, SamePath("/Users/Dev/.pmg/bin", "/users/dev/.pmg/bin"))
	assert.Equal(t, foldsCase, PathWithinDir("/Users/Dev/.pmg/bin/npm", "/users/dev/.pmg/bin"))
	assert.True(t, SamePath("/Users/Dev/.pmg/bin", "/Users/Dev/.pmg/bin/"))
}

func TestPathWithinAny(t *testing.T) {
	systemDir := filepath.Join("/", "usr", "local", "lib", "pmg", "bin")
	userDir := filepath.Join("/", "home", "dev", ".pmg", "bin")
	dirs := []string{systemDir, userDir}

	assert.True(t, PathWithinAny(filepath.Join(systemDir, "npm"), dirs))
	assert.True(t, PathWithinAny(filepath.Join(userDir, "pip"), dirs))
	assert.False(t, PathWithinAny(filepath.Join("/", "usr", "bin", "yarn"), dirs))
}

func TestSameFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "pmg")
	other := filepath.Join(dir, "other")
	link := filepath.Join(dir, "link")
	require.NoError(t, os.WriteFile(file, []byte("a"), 0o600))
	require.NoError(t, os.WriteFile(other, []byte("a"), 0o600))
	require.NoError(t, os.Link(file, link))

	cases := []struct {
		name string
		a, b string
		want bool
	}{
		{"same path", file, file, true},
		{"hard link", file, link, true},
		{"different file with same content", file, other, false},
		{"missing file", file, filepath.Join(dir, "missing"), false},
		{"empty path", "", file, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, SameFile(tc.a, tc.b))
		})
	}
}
