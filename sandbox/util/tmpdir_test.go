package util

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetTmpdirParent(t *testing.T) {
	// Save original TMPDIR
	originalTmpdir := os.Getenv("TMPDIR")
	defer os.Setenv("TMPDIR", originalTmpdir)

	t.Run("macOS pattern with /var prefix", func(t *testing.T) {
		os.Setenv("TMPDIR", "/var/folders/ab/cd1234ef/T/")
		parents := GetTmpdirParent()

		assert.Len(t, parents, 2)
		assert.Contains(t, parents, "/var/folders/ab/cd1234ef")
		assert.Contains(t, parents, "/private/var/folders/ab/cd1234ef")
	})

	t.Run("macOS pattern with /private/var prefix", func(t *testing.T) {
		os.Setenv("TMPDIR", "/private/var/folders/xy/z9876543/T/")
		parents := GetTmpdirParent()

		assert.Len(t, parents, 2)
		assert.Contains(t, parents, "/private/var/folders/xy/z9876543")
		assert.Contains(t, parents, "/var/folders/xy/z9876543")
	})

	t.Run("macOS pattern without trailing slash", func(t *testing.T) {
		os.Setenv("TMPDIR", "/var/folders/12/abcdefgh/T")
		parents := GetTmpdirParent()

		assert.Len(t, parents, 2)
		assert.Contains(t, parents, "/var/folders/12/abcdefgh")
		assert.Contains(t, parents, "/private/var/folders/12/abcdefgh")
	})

	t.Run("non-macOS pattern returns empty", func(t *testing.T) {
		testCases := []string{
			"/tmp",
			"/var/tmp",
			"/custom/temp",
			"/var/folders/",
			"/var/folders/ab/",
			"/var/folders/abc/def/T/", // XX should be 2 chars, not 3
		}

		for _, tmpdir := range testCases {
			os.Setenv("TMPDIR", tmpdir)
			parents := GetTmpdirParent()
			assert.Empty(t, parents, "Expected empty result for TMPDIR=%s", tmpdir)
		}
	})

	t.Run("empty TMPDIR returns empty", func(t *testing.T) {
		os.Setenv("TMPDIR", "")
		parents := GetTmpdirParent()
		assert.Empty(t, parents)
	})

	t.Run("unset TMPDIR returns empty", func(t *testing.T) {
		os.Unsetenv("TMPDIR")
		parents := GetTmpdirParent()
		assert.Empty(t, parents)
	})
}
