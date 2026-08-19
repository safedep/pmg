package audit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/safedep/pmg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func newCheckInConfig(t *testing.T) *config.RuntimeConfig {
	t.Helper()
	tmpDir := t.TempDir()
	t.Setenv("PMG_CONFIG_DIR", tmpDir)
	config.Reload()
	t.Cleanup(config.Reload)

	cfg := config.Get()
	cfg.Config.Cloud.Enabled = true
	cfg.Config.Cloud.CheckIn.Enabled = true
	cfg.Config.Cloud.CheckIn.MinInterval = time.Hour
	return cfg
}

func TestMaybeCheckIn(t *testing.T) {
	ctx := context.Background()

	t.Run("checks in on a zero-event sync", func(t *testing.T) {
		cfg := newCheckInConfig(t)
		calls := 0
		maybeCheckIn(ctx, cfg, 0, nil, func(context.Context) error {
			calls++
			return nil
		})
		assert.Equal(t, 1, calls)
	})

	t.Run("skips when events were synced", func(t *testing.T) {
		cfg := newCheckInConfig(t)
		calls := 0
		maybeCheckIn(ctx, cfg, 3, nil, func(context.Context) error {
			calls++
			return nil
		})
		assert.Equal(t, 0, calls)
	})

	t.Run("skips when the sync failed", func(t *testing.T) {
		cfg := newCheckInConfig(t)
		calls := 0
		maybeCheckIn(ctx, cfg, 0, errors.New("sync failed"), func(context.Context) error {
			calls++
			return nil
		})
		assert.Equal(t, 0, calls)
	})

	t.Run("skips when disabled", func(t *testing.T) {
		cfg := newCheckInConfig(t)
		cfg.Config.Cloud.CheckIn.Enabled = false
		calls := 0
		maybeCheckIn(ctx, cfg, 0, nil, func(context.Context) error {
			calls++
			return nil
		})
		assert.Equal(t, 0, calls)
	})

	t.Run("skips inside the cooldown and records every attempt", func(t *testing.T) {
		cfg := newCheckInConfig(t)
		calls := 0
		checkIn := func(context.Context) error {
			calls++
			return nil
		}

		maybeCheckIn(ctx, cfg, 0, nil, checkIn)
		maybeCheckIn(ctx, cfg, 0, nil, checkIn)
		assert.Equal(t, 1, calls, "second attempt inside the cooldown must not fire")
		require.FileExists(t, cfg.CloudCheckInLastRunPath())
	})

	t.Run("cooldown records a failed attempt too", func(t *testing.T) {
		cfg := newCheckInConfig(t)
		calls := 0
		checkIn := func(context.Context) error {
			calls++
			return status.Error(codes.Unavailable, "server down")
		}

		maybeCheckIn(ctx, cfg, 0, nil, checkIn)
		maybeCheckIn(ctx, cfg, 0, nil, checkIn)
		assert.Equal(t, 1, calls, "a failed check-in must still start the cooldown")
	})

	t.Run("unimplemented degrades to a warning", func(t *testing.T) {
		cfg := newCheckInConfig(t)
		assert.NotPanics(t, func() {
			maybeCheckIn(ctx, cfg, 0, nil, func(context.Context) error {
				return status.Error(codes.Unimplemented, "old server")
			})
		})
	})
}
