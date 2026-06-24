package proxy

import (
	"testing"

	"github.com/safedep/pmg/internal/proxyserver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStopExitError(t *testing.T) {
	t.Run("no flag, blocks present -> nil", func(t *testing.T) {
		err := stopExitError(proxyserver.StopResult{BlockedCount: 3, StateVerified: true}, false)
		assert.NoError(t, err)
	})

	t.Run("flag, no blocks -> nil", func(t *testing.T) {
		err := stopExitError(proxyserver.StopResult{BlockedCount: 0, StateVerified: true}, true)
		assert.NoError(t, err)
	})

	t.Run("flag, blocks present -> error", func(t *testing.T) {
		err := stopExitError(proxyserver.StopResult{BlockedCount: 2, StateVerified: true}, true)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "2 package")
	})

	t.Run("flag, crash (unverified state) -> fail closed", func(t *testing.T) {
		err := stopExitError(proxyserver.StopResult{StateVerified: false}, true)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "could not be verified")
	})

	t.Run("no flag, crash -> nil", func(t *testing.T) {
		err := stopExitError(proxyserver.StopResult{StateVerified: false}, false)
		assert.NoError(t, err)
	})
}
