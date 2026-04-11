package audit

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/safedep/dry/cloud"
	"github.com/safedep/dry/cloud/endpointsync"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	appVersion "github.com/safedep/pmg/internal/version"
)

type cloudSink struct {
	syncClient   *endpointsync.SyncClient
	cloudClient  *cloud.Client
	invocationID string
}

func newCloudSink(cfg *config.RuntimeConfig) (*cloudSink, error) {
	resolver, err := cloud.NewEnvCredentialResolver()
	if err != nil {
		return nil, fmt.Errorf("failed to create credential resolver: %w", err)
	}

	creds, err := resolver.Resolve()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve cloud credentials: %w", err)
	}

	cloudClient, err := cloud.NewDataPlaneClient("pmg", creds)
	if err != nil {
		return nil, fmt.Errorf("failed to create data plane client: %w", err)
	}

	transport := endpointsync.NewGrpcTransport(cloudClient.Connection())

	sink, err := newCloudSinkWithTransport(transport, cfg.Config.Cloud.EndpointID, cfg.CloudSyncDBPath())
	if err != nil {
		if closeErr := cloudClient.Close(); closeErr != nil {
			log.Warnf("failed to close cloud client after sink init failure: %v", closeErr)
		}
		return nil, err
	}

	sink.cloudClient = cloudClient
	return sink, nil
}

func newCloudSinkWithTransport(transport endpointsync.EventTransport, endpointID, walPath string) (*cloudSink, error) {
	var identityOpts []endpointsync.EndpointIdentityOption
	if endpointID != "" {
		identityOpts = append(identityOpts, endpointsync.WithEndpointID(endpointID))
	}

	identity := endpointsync.NewEndpointIdentityResolver(identityOpts...)

	toolVersion := appVersion.Version
	if toolVersion == "" {
		toolVersion = "dev"
	}

	syncClient, err := endpointsync.NewSyncClient("pmg", toolVersion, transport, identity,
		endpointsync.WithWALPath(walPath))
	if err != nil {
		return nil, fmt.Errorf("failed to create sync client: %w", err)
	}

	invocationID, err := uuid.NewRandom()
	if err != nil {
		if closeErr := syncClient.Close(); closeErr != nil {
			log.Warnf("failed to close sync client after invocation ID generation failure: %v", closeErr)
		}
		return nil, fmt.Errorf("failed to generate invocation ID: %w", err)
	}

	return &cloudSink{
		syncClient:   syncClient,
		invocationID: invocationID.String(),
	}, nil
}

func (s *cloudSink) Handle(ctx context.Context, event AuditEvent) error {
	pmgEvents := s.translateToPmgEvents(event)
	if len(pmgEvents) == 0 {
		return nil
	}

	for _, pmgEvent := range pmgEvents {
		toolEvent, err := s.syncClient.NewEvent()
		if err != nil {
			return fmt.Errorf("failed to create tool event: %w", err)
		}

		toolEvent.SetPmgEvent(pmgEvent)
		toolEvent.SetInvocationId(s.invocationID)

		if err := s.syncClient.Emit(ctx, toolEvent); err != nil {
			if errors.Is(err, endpointsync.ErrWALFull) {
				log.Warnf("Cloud sync WAL is full, dropping event: %v", err)
				return nil
			}
			return fmt.Errorf("failed to emit cloud event: %w", err)
		}
	}

	return nil
}

func (s *cloudSink) Close() error {
	var errs []error
	if s.syncClient != nil {
		if err := s.syncClient.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.cloudClient != nil {
		if err := s.cloudClient.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
