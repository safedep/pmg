package audit

import (
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/safedep/pmg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// spawnRecorder is a detachedSpawner stub that captures invocations instead
// of actually forking. We swap it in via withMockSpawner.
type spawnRecorder struct {
	mu    sync.Mutex
	calls []spawnCall
	err   error
}

type spawnCall struct {
	name string
	args []string
}

func (r *spawnRecorder) spawn(name string, args ...string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := make([]string, len(args))
	copy(cp, args)
	r.calls = append(r.calls, spawnCall{name: name, args: cp})
	return r.err
}

func (r *spawnRecorder) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

func withMockSpawner(t *testing.T) *spawnRecorder {
	t.Helper()
	rec := &spawnRecorder{}
	prev := spawnDetached
	spawnDetached = rec.spawn
	t.Cleanup(func() { spawnDetached = prev })
	return rec
}

func newAutoSyncConfig(t *testing.T) *config.RuntimeConfig {
	t.Helper()
	tmpDir := t.TempDir()
	t.Setenv("PMG_CONFIG_DIR", tmpDir)
	// Make sure no PMG_DISABLE_TELEMETRY leak from the host environment can
	// fool the analytics short-circuit in MaybeSpawnBackgroundSync.
	t.Setenv("PMG_DISABLE_TELEMETRY", "false")

	// Re-init the config so configDir picks up the tmpDir we just set.
	// Without this, cfg.CloudSyncLastRunPath() points at the user's real
	// config dir, which may not even exist in CI.
	config.Reload()
	t.Cleanup(config.Reload)

	cfg := config.Get()
	cfg.Config.Cloud.Enabled = true
	cfg.Config.Cloud.AutoSync.Enabled = true
	cfg.Config.Cloud.AutoSync.MinInterval = 15 * time.Minute
	cfg.Config.Cloud.AutoSync.Timeout = time.Minute
	cfg.Config.DisableTelemetry = false
	return cfg
}

func TestMaybeSpawnBackgroundSyncSpawnsByDefault(t *testing.T) {
	rec := withMockSpawner(t)
	cfg := newAutoSyncConfig(t)

	MaybeSpawnBackgroundSync(cfg)

	require.Equal(t, 1, rec.callCount())
	assert.Equal(t, []string{"cloud", "sync-background"}, rec.calls[0].args)
	assert.NotEmpty(t, rec.calls[0].name, "spawned name should be a resolved binary path")
}

func TestMaybeSpawnBackgroundSyncIgnoresTelemetryDisabled(t *testing.T) {
	rec := withMockSpawner(t)
	cfg := newAutoSyncConfig(t)
	cfg.Config.DisableTelemetry = true

	MaybeSpawnBackgroundSync(cfg)
	assert.Equal(t, 1, rec.callCount())
}

func TestMaybeSpawnBackgroundSyncShortCircuits(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		rec := withMockSpawner(t)
		MaybeSpawnBackgroundSync(nil)
		assert.Equal(t, 0, rec.callCount())
	})

	t.Run("cloud disabled", func(t *testing.T) {
		rec := withMockSpawner(t)
		cfg := newAutoSyncConfig(t)
		cfg.Config.Cloud.Enabled = false

		MaybeSpawnBackgroundSync(cfg)
		assert.Equal(t, 0, rec.callCount())
	})

	t.Run("auto_sync disabled", func(t *testing.T) {
		rec := withMockSpawner(t)
		cfg := newAutoSyncConfig(t)
		cfg.Config.Cloud.AutoSync.Enabled = false

		MaybeSpawnBackgroundSync(cfg)
		assert.Equal(t, 0, rec.callCount())
	})

	t.Run("we are the sync-background child", func(t *testing.T) {
		rec := withMockSpawner(t)
		cfg := newAutoSyncConfig(t)

		t.Cleanup(func() { isBackgroundSyncChild = false })
		MarkBackgroundSyncChild()

		MaybeSpawnBackgroundSync(cfg)
		assert.Equal(t, 0, rec.callCount())
	})
}

func TestMaybeSpawnBackgroundSyncRespectsCooldown(t *testing.T) {
	rec := withMockSpawner(t)
	cfg := newAutoSyncConfig(t)

	// Recent attempt → cooldown still in effect → no spawn.
	require.NoError(t, WriteLastSyncAttempt(cfg.CloudSyncLastRunPath()))

	MaybeSpawnBackgroundSync(cfg)
	assert.Equal(t, 0, rec.callCount())
}

func TestMaybeSpawnBackgroundSyncSpawnsAfterCooldownElapses(t *testing.T) {
	rec := withMockSpawner(t)
	cfg := newAutoSyncConfig(t)

	old := time.Now().Add(-time.Hour).Unix()
	require.NoError(t, os.WriteFile(cfg.CloudSyncLastRunPath(),
		[]byte(strconv.FormatInt(old, 10)), 0o600))

	MaybeSpawnBackgroundSync(cfg)
	assert.Equal(t, 1, rec.callCount())
}

func TestMaybeSpawnBackgroundSyncSwallowsSpawnError(t *testing.T) {
	rec := withMockSpawner(t)
	rec.err = os.ErrPermission
	cfg := newAutoSyncConfig(t)

	// We can't observe log.Warnf directly, but we can assert the function
	// neither panics nor blocks when the underlying spawn fails.
	assert.NotPanics(t, func() { MaybeSpawnBackgroundSync(cfg) })
	assert.Equal(t, 1, rec.callCount(), "spawner should still be invoked once")
}
