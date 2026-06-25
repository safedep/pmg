package flows

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCIEnvOverride proves the fix for #335: pmg forces CI=true for
// non-interactive runs but must not clobber a CI value the user set
// explicitly (e.g. CI=false on a build server).
func TestCIEnvOverride(t *testing.T) {
	t.Run("sets CI=true when unset", func(t *testing.T) {
		original, hadCI := os.LookupEnv("CI")
		require.NoError(t, os.Unsetenv("CI"))
		t.Cleanup(func() {
			if hadCI {
				require.NoError(t, os.Setenv("CI", original))
			}
		})

		assert.Equal(t, []string{"CI=true"}, ciEnvOverride())
	})

	t.Run("does not override explicitly set CI", func(t *testing.T) {
		t.Setenv("CI", "false")
		assert.Nil(t, ciEnvOverride())
	})

	t.Run("does not override CI set to empty", func(t *testing.T) {
		t.Setenv("CI", "")
		assert.Nil(t, ciEnvOverride())
	})
}
