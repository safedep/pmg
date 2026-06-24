package proxyserver

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/audit"
)

const cloudFlushTimeout = 2 * time.Minute

// proxyEnvVars are the proxy environment variables the cloud sync must not
// honor. The stop command inherits these (pointing at the PMG proxy it just
// shut down), and the cloud gRPC client would otherwise route api.safedep.io
// through the dead proxy and fail with "connection refused".
var proxyEnvVars = []string{
	"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
	"http_proxy", "https_proxy", "all_proxy",
}

// flushCloudEvents synchronously drains pending audit events to SafeDep Cloud.
// It is a no-op when cloud sync is disabled. Used by Stop so events reach the
// cloud before an ephemeral CI runner is destroyed.
func flushCloudEvents(ctx context.Context, cfg *config.RuntimeConfig) error {
	if !cfg.Config.Cloud.Enabled {
		return nil
	}

	// PMG's own cloud traffic must go direct, never through the package-manager
	// proxy (which is already stopped by the time we flush). The sync gRPC
	// client honors HTTP(S)_PROXY, so clear them for this short-lived process.
	clearProxyEnv()

	lock := audit.NewSyncLock(cfg.CloudSyncLockPath())
	lockCtx, lockCancel := context.WithTimeout(ctx, 30*time.Second)
	defer lockCancel()

	locked, err := lock.TryLockContext(lockCtx, 250*time.Millisecond)
	if err != nil {
		return fmt.Errorf("acquire cloud sync lock: %w", err)
	}
	if !locked {
		return fmt.Errorf("another cloud sync is already in progress")
	}
	defer func() {
		if uerr := lock.Unlock(); uerr != nil {
			log.Warnf("failed to release cloud sync lock: %v", uerr)
		}
	}()

	bundle, err := audit.NewSyncClientBundle(cfg)
	if err != nil {
		return fmt.Errorf("init cloud sync client: %w", err)
	}
	defer func() {
		if cerr := bundle.Close(); cerr != nil {
			log.Warnf("failed to close sync client: %v", cerr)
		}
	}()

	syncCtx, cancel := context.WithTimeout(ctx, cloudFlushTimeout)
	defer cancel()

	synced, err := bundle.Sync(syncCtx)
	if err != nil {
		return fmt.Errorf("sync events to cloud: %w", err)
	}

	log.Infof("Flushed %d events to SafeDep Cloud", synced)
	return nil
}

func clearProxyEnv() {
	for _, k := range proxyEnvVars {
		if err := os.Unsetenv(k); err != nil {
			log.Warnf("failed to unset %s for cloud sync: %v", k, err)
		}
	}
}
