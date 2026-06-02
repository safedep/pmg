package audit

import (
	"context"
	"errors"
	"fmt"

	"github.com/safedep/dry/cloud"
	"github.com/safedep/dry/cloud/endpointsync"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/cloudauth"
	appVersion "github.com/safedep/pmg/internal/version"
)

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
