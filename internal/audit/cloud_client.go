package audit

import (
	"errors"
	"fmt"

	"github.com/safedep/dry/cloud"
	"github.com/safedep/dry/cloud/endpointsync"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	appVersion "github.com/safedep/pmg/internal/version"
)

// SyncClientBundle holds a SyncClient and its underlying cloud client.
// Callers must call Close() when done.
type SyncClientBundle struct {
	SyncClient       *endpointsync.SyncClient
	cloudClient      *cloud.Client
	keychainResolver cloud.CloseableCredentialResolver
}

func (b *SyncClientBundle) Close() error {
	var errs []error
	if b.SyncClient != nil {
		if err := b.SyncClient.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if b.cloudClient != nil {
		if err := b.cloudClient.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if b.keychainResolver != nil {
		if err := b.keychainResolver.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// NewSyncClientBundle creates an authenticated SyncClient connected to SafeDep Cloud.
func NewSyncClientBundle(cfg *config.RuntimeConfig) (*SyncClientBundle, error) {
	// Build credential resolver chain: keychain first, env fallback.
	var resolvers []cloud.CredentialResolver
	var keychainResolver cloud.CloseableCredentialResolver

	keychainResolver, err := cloud.NewKeychainCredentialResolver(cloud.CredentialTypeAPIKey)
	if err != nil {
		log.Debugf("Keychain credential resolver not available, skipping: %v", err)
	} else {
		resolvers = append(resolvers, keychainResolver)
	}

	envResolver, err := cloud.NewEnvCredentialResolver()
	if err != nil {
		log.Debugf("Env credential resolver not available, skipping: %v", err)
	} else {
		resolvers = append(resolvers, envResolver)
	}

	if len(resolvers) == 0 {
		if keychainResolver != nil {
			if closeErr := keychainResolver.Close(); closeErr != nil {
				log.Warnf("failed to close keychain resolver: %v", closeErr)
			}
		}
		return nil, fmt.Errorf("no credential resolvers available")
	}

	chain := cloud.NewChainCredentialResolver(resolvers...)
	creds, err := chain.Resolve()
	if err != nil {
		if keychainResolver != nil {
			if closeErr := keychainResolver.Close(); closeErr != nil {
				log.Warnf("failed to close keychain resolver: %v", closeErr)
			}
		}
		return nil, fmt.Errorf("failed to resolve cloud credentials: %w", err)
	}

	cloudClient, err := cloud.NewDataPlaneClient("pmg", creds)
	if err != nil {
		if keychainResolver != nil {
			if closeErr := keychainResolver.Close(); closeErr != nil {
				log.Warnf("failed to close keychain resolver: %v", closeErr)
			}
		}
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
		if keychainResolver != nil {
			if closeErr := keychainResolver.Close(); closeErr != nil {
				log.Warnf("failed to close keychain resolver: %v", closeErr)
			}
		}
		return nil, fmt.Errorf("failed to create sync client: %w", err)
	}

	return &SyncClientBundle{
		SyncClient:       syncClient,
		cloudClient:      cloudClient,
		keychainResolver: keychainResolver,
	}, nil
}
