package audit

import (
	"bytes"
	"context"
	"testing"
	"time"

	drylog "github.com/safedep/dry/log"
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
	cfg.Config.Cloud.AutoSync.MinInterval = 15 * time.Minute
	return cfg
}

func TestCheckInWithRateLimit(t *testing.T) {
	ctx := context.Background()

	t.Run("checks in when the rate limit elapsed", func(t *testing.T) {
		cfg := newCheckInConfig(t)
		calls := 0
		err := checkInWithRateLimit(ctx, cfg, func(context.Context) error {
			calls++
			return nil
		})
		require.NoError(t, err)
		assert.Equal(t, 1, calls)
	})

	t.Run("skips inside the rate limit and records every attempt", func(t *testing.T) {
		cfg := newCheckInConfig(t)
		calls := 0
		checkIn := func(context.Context) error {
			calls++
			return nil
		}

		require.NoError(t, checkInWithRateLimit(ctx, cfg, checkIn))
		require.NoError(t, checkInWithRateLimit(ctx, cfg, checkIn))
		assert.Equal(t, 1, calls, "second attempt inside the rate limit must not fire")
		require.FileExists(t, cfg.CloudCheckInLastRunPath())
	})

	t.Run("a failed attempt still starts the rate limit", func(t *testing.T) {
		cfg := newCheckInConfig(t)
		calls := 0
		checkIn := func(context.Context) error {
			calls++
			return status.Error(codes.Unavailable, "server down")
		}

		err := checkInWithRateLimit(ctx, cfg, checkIn)
		require.Error(t, err)
		assert.Equal(t, codes.Unavailable, status.Code(err))
		require.NoError(t, checkInWithRateLimit(ctx, cfg, checkIn))
		assert.Equal(t, 1, calls)
	})

	t.Run("logs the check-in and the rate-limited skip", func(t *testing.T) {
		var logs bytes.Buffer
		restore := drylog.SwapGlobalForTest(&logs)
		defer restore()

		cfg := newCheckInConfig(t)
		checkIn := func(context.Context) error { return nil }

		require.NoError(t, checkInWithRateLimit(ctx, cfg, checkIn))
		assert.Contains(t, logs.String(), "cloud check-in sent")

		require.NoError(t, checkInWithRateLimit(ctx, cfg, checkIn))
		assert.Contains(t, logs.String(), "cloud check-in skipped")
	})
}
