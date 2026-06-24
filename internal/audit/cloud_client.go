package audit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/safedep/dry/cloud"
	"github.com/safedep/dry/cloud/endpointsync"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/cloudauth"
	appVersion "github.com/safedep/pmg/internal/version"
)

// ErrSyncInProgress is returned by DrainToCloud when another process already
// holds the cloud sync lock.
var ErrSyncInProgress = errors.New("another cloud sync is already in progress")

// DrainToCloud acquires the cross-process sync lock and drains pending audit
// events from the WAL to SafeDep Cloud, returning the number synced. It records
// the attempt (so a failing endpoint does not make every run retry). Callers
// are responsible for gating on cloud.enabled and for surfacing errors;
// ErrSyncInProgress is returned when the lock is held elsewhere.
//
// lockTimeout bounds acquiring the shared lock; syncTimeout bounds the drain.
func DrainToCloud(ctx context.Context, cfg *config.RuntimeConfig, lockTimeout, syncTimeout time.Duration) (int, error) {
	lock := NewSyncLock(cfg.CloudSyncLockPath())

	lockCtx, lockCancel := context.WithTimeout(ctx, lockTimeout)
	defer lockCancel()

	locked, err := lock.TryLockContext(lockCtx, 250*time.Millisecond)
	if err != nil {
		return 0, fmt.Errorf("acquire cloud sync lock: %w", err)
	}
	if !locked {
		return 0, ErrSyncInProgress
	}
	defer func() {
		if uerr := lock.Unlock(); uerr != nil {
			log.Warnf("failed to release cloud sync lock: %v", uerr)
		}
	}()

	bundle, err := NewSyncClientBundle(cfg)
	if err != nil {
		return 0, fmt.Errorf("init cloud sync client: %w", err)
	}
	defer func() {
		if cerr := bundle.Close(); cerr != nil {
			log.Warnf("failed to close cloud sync client: %v", cerr)
		}
	}()

	syncCtx, cancel := context.WithTimeout(ctx, syncTimeout)
	defer cancel()

	synced, syncErr := bundle.Sync(syncCtx)

	// Record the attempt on every outcome so a stuck endpoint does not make the
	// background auto-sync refire on the next invocation.
	if werr := WriteLastSyncAttempt(cfg.CloudSyncLastRunPath()); werr != nil {
		log.Warnf("failed to update cloud sync lastrun: %v", werr)
	}

	return synced, syncErr
}

// SyncClientBundle holds a SyncClient and its underlying cloud client.
// Callers must call Close() when done.
type SyncClientBundle struct {
	syncClient  *endpointsync.SyncClient
	cloudClient *cloud.Client
}

// Sync delivers pending events from the WAL to SafeDep Cloud.
func (b *SyncClientBundle) Sync(ctx context.Context) (int, error) {
	return b.syncClient.Sync(ctx)
}

func (b *SyncClientBundle) Close() error {
	var errs []error
	if b.syncClient != nil {
		if err := b.syncClient.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if b.cloudClient != nil {
		if err := b.cloudClient.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// NewSyncClientBundle creates an authenticated SyncClient connected to SafeDep Cloud.
func NewSyncClientBundle(cfg *config.RuntimeConfig) (*SyncClientBundle, error) {
	// Resolve credentials via keychain-first, env fallback chain. The keychain
	// resolver can be closed immediately because the data plane client extracts
	// the credential values when it is created.
	creds, closeResolver, err := cloudauth.ResolveCredentials()
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := closeResolver(); closeErr != nil {
			log.Warnf("failed to close keychain resolver: %v", closeErr)
		}
	}()

	cloudClient, err := cloud.NewDataPlaneClient("pmg", creds)
	if err != nil {
		return nil, fmt.Errorf("failed to create data plane client: %w", err)
	}

	transport := endpointsync.NewGrpcTransport(cloudClient.Connection())

	var identityOpts []endpointsync.EndpointIdentityOption
	if cfg.Config.Cloud.EndpointID != "" {
		identityOpts = append(identityOpts, endpointsync.WithEndpointID(cfg.Config.Cloud.EndpointID))
	}

	identity := endpointsync.NewEndpointIdentityResolver(identityOpts...)

	toolVersion := appVersion.Version
	if toolVersion == "" {
		toolVersion = "dev"
	}

	syncClient, err := endpointsync.NewSyncClient("pmg", toolVersion, transport, identity,
		endpointsync.WithWALPath(cfg.CloudSyncDBPath()))
	if err != nil {
		if closeErr := cloudClient.Close(); closeErr != nil {
			log.Warnf("failed to close cloud client after sync client init failure: %v", closeErr)
		}
		return nil, fmt.Errorf("failed to create sync client: %w", err)
	}

	return &SyncClientBundle{
		syncClient:  syncClient,
		cloudClient: cloudClient,
	}, nil
}
