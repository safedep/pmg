package analytics

import (
	"os"
	"testing"

	"github.com/safedep/pmg/config"
	"github.com/stretchr/testify/assert"
)

func TestIsDisabled(t *testing.T) {
	t.Run("returns true if PMG_DISABLE_TELEMETRY is set to true", func(t *testing.T) {
		os.Setenv(telemetryDisableEnvKey, "true")
		defer os.Unsetenv(telemetryDisableEnvKey)

		assert.True(t, IsDisabled())
	})

	t.Run("returns false if PMG_DISABLE_TELEMETRY is not set", func(t *testing.T) {
		config.Get().Config.DisableTelemetry = false
		assert.False(t, IsDisabled())
	})

	t.Run("returns true if telemetry is disabled in config", func(t *testing.T) {
		config.Get().Config.DisableTelemetry = true
		t.Cleanup(func() {
			config.Get().Config.DisableTelemetry = false
		})

		assert.True(t, IsDisabled())
	})
}

func TestCloseIsImmutable(t *testing.T) {
	Close()
	assert.Nil(t, globalPosthogClient)

	Close()
	assert.Nil(t, globalPosthogClient)
}
