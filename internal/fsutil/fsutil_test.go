package fsutil

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
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
