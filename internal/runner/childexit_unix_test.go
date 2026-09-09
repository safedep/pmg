//go:build unix

package runner

import (
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A real child exit through sh, including a signal death, which has no
// Windows equivalent.
func TestExtractExitFromChild(t *testing.T) {
	t.Run("direct non-zero exit resolves the real code", func(t *testing.T) {
		err := exec.Command("sh", "-c", "exit 2").Run()
		require.Error(t, err)

		code, signaled, resolved := extractExit(err)
		assert.Equal(t, 2, code)
		assert.False(t, signaled)
		assert.True(t, resolved)
	})

	t.Run("direct signal termination resolves to 128+signum", func(t *testing.T) {
		err := exec.Command("sh", "-c", "kill -INT $$").Run()
		require.Error(t, err)

		code, signaled, resolved := extractExit(err)
		assert.Equal(t, 130, code) // 128 + SIGINT(2)
		assert.True(t, signaled)
		assert.True(t, resolved)
	})
}
