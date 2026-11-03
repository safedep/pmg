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

// ErrSyncInProgress is returned when another process already holds the
// cloud sync lock.
var ErrSyncInProgress = errors.New("another cloud sync is already in progress")

// SyncClientBundle holds a SyncClient and its underlying cloud client.
// Callers must call Close() when done.
type SyncClientBundle struct {
	syncClient  *endpointsync.SyncClient
	cloudClient *cloud.Client
	cfg         *config.RuntimeConfig
}

// Sync delivers pending events from the WAL to SafeDep Cloud.
func (b *SyncClientBundle) Sync(ctx context.Context) (int, error) {
	return b.syncClient.Sync(ctx)
}

// CheckIn reports endpoint presence, rate limited by the auto-sync interval.
// opts add the cloud policy state and the labels. Callers invoke it after a
// successful sync.
func (b *SyncClientBundle) CheckIn(ctx context.Context, opts ...endpointsync.CheckInOption) error {
	return checkInWithRateLimit(ctx, b.cfg, func(ctx context.Context) error {
		return b.syncClient.CheckInWithOptions(ctx, opts...)
	})
}

// checkInWithRateLimit uses its own lastrun file: the proxy ticker keeps
// cloud-sync.lastrun always fresh, which would starve the check-in. Like
// cloud-sync.lastrun, the file records every attempt, so a failing endpoint
// or an old server does not retry on every sync.
func checkInWithRateLimit(ctx context.Context, cfg *config.RuntimeConfig, checkIn func(context.Context) error) error {
	lastRunPath := cfg.CloudCheckInLastRunPath()
	minInterval := cfg.Config.Cloud.AutoSync.MinInterval

	if !SyncCooldownElapsed(lastRunPath, minInterval) {
		log.Debugf("cloud check-in skipped: last attempt %s ago, min interval %s",
			time.Since(ReadLastSyncAttempt(lastRunPath)).Round(time.Second), minInterval)
		return nil
	}

	if err := WriteLastSyncAttempt(lastRunPath); err != nil {
		return fmt.Errorf("update check-in lastrun: %w", err)
	}

	if err := checkIn(ctx); err != nil {
		return err
	}

	log.Debugf("cloud check-in sent")
	return nil
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

	return NewSyncClientBundleWithCredentials(cfg, creds)
}

// NewSyncClientBundleWithCredentials creates a SyncClient with credentials
// that the caller resolved, so one sync resolves them once.
func NewSyncClientBundleWithCredentials(cfg *config.RuntimeConfig, creds *cloud.Credentials) (*SyncClientBundle, error) {
	cloudClient, err := cloud.NewDataPlaneClient("pmg", creds)
	if err != nil {
		return nil, fmt.Errorf("failed to create data plane client: %w", err)
	}

	transport := endpointsync.NewGrpcTransport(cloudClient.Connection())

	syncClient, err := endpointsync.NewSyncClient("pmg", pmgToolVersion(), transport, NewEndpointIdentityResolver(cfg),
		cloudSyncOptions(cfg.CloudSyncDBPath())...)
	if err != nil {
		if closeErr := cloudClient.Close(); closeErr != nil {
			log.Warnf("failed to close cloud client after sync client init failure: %v", closeErr)
		}
		return nil, fmt.Errorf("failed to create sync client: %w", err)
	}

	return &SyncClientBundle{
		syncClient:  syncClient,
		cloudClient: cloudClient,
		cfg:         cfg,
	}, nil
}

// NewEndpointIdentityResolver returns the endpoint identity that the
// check-in and the policy fetch send, so both name one endpoint.
func NewEndpointIdentityResolver(cfg *config.RuntimeConfig) endpointsync.EndpointIdentityResolver {
	var identityOpts []endpointsync.EndpointIdentityOption
	if endpointID := resolveCloudEndpointID(cfg.Config.Cloud.EndpointID); endpointID != "" {
		identityOpts = append(identityOpts, endpointsync.WithEndpointID(endpointID))
	}
	return endpointsync.NewEndpointIdentityResolver(identityOpts...)
}

// ToolVersion returns the version of pmg that cloud events and the policy
// fetch carry.
func ToolVersion() string {
	return pmgToolVersion()
}

// pmgToolVersion returns the tool version stamped on cloud events, defaulting
// to "dev" for local builds.
func pmgToolVersion() string {
	if appVersion.Version == "" {
		return "dev"
	}
	return appVersion.Version
}
