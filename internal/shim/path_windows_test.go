//go:build windows

package shim

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFilterPMGFromPathWindows(t *testing.T) {
	join := func(entries ...string) string {
		return strings.Join(entries, string(os.PathListSeparator))
	}

	t.Run("strips the data shim dir without PMG_SHIM_PATH", func(t *testing.T) {
		// Doctor and a direct `pmg npm` run without the marker. This is the
		// only guard that keeps ResolveRealBinary from returning PMG's own
		// shim, so PMG would re-enter itself without it.
		t.Setenv(pmgShimPathEnv, "")
		t.Setenv("LOCALAPPDATA", t.TempDir())

		shimDir, err := DataUserBinDir()
		require.NoError(t, err)

		got := FilterPMGFromPath(join(shimDir, `C:\Windows\System32`))
		assert.Equal(t, `C:\Windows\System32`, got)
	})

	t.Run("strips the legacy shim dir without PMG_SHIM_PATH", func(t *testing.T) {
		t.Setenv(pmgShimPathEnv, "")
		home := t.TempDir()
		t.Setenv("USERPROFILE", home)

		shimDir := filepath.Join(home, legacyUserDirName, "bin")
		got := FilterPMGFromPath(join(shimDir, `C:\Windows\System32`))
		assert.Equal(t, `C:\Windows\System32`, got)
	})

	t.Run("strips a PATH entry that differs from PMG_SHIM_PATH only in case", func(t *testing.T) {
		// %~f0 in the shim yields one casing, the PATH entry another. Both
		// name one directory on Windows.
		t.Setenv(pmgShimPathEnv, `C:\Users\Dev\Shims\npm.cmd`)

		got := FilterPMGFromPath(join(`c:\users\dev\shims`, `C:\Windows\System32`))
		assert.Equal(t, `C:\Windows\System32`, got)
	})
}
