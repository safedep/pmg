package proxyserver

import (
	"context"
	"fmt"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/audit"
)

const (
	cloudFlushLockTimeout = 30 * time.Second
	cloudFlushTimeout     = 2 * time.Minute
)

// flushCloudEvents synchronously drains pending audit events to SafeDep Cloud.
// It is a no-op when cloud sync is disabled. Used by Stop so events reach the
// cloud before an ephemeral CI runner is destroyed.
func flushCloudEvents(ctx context.Context, cfg *config.RuntimeConfig) error {
	if !cfg.Config.Cloud.Enabled {
		return nil
	}

	synced, err := audit.DrainToCloud(ctx, cfg, cloudFlushLockTimeout, cloudFlushTimeout)
	if err != nil {
		return fmt.Errorf("flush events to cloud: %w", err)
	}

	log.Infof("Flushed %d events to SafeDep Cloud", synced)
	return nil
}
