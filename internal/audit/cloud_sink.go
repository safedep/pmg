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

	return newCloudSinkWithTransport(transport, cfg.Config.Cloud.EndpointID, cfg.CloudSyncDBPath())
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
		return nil, fmt.Errorf("failed to generate invocation ID: %w", err)
	}

	return &cloudSink{
		syncClient:   syncClient,
		invocationID: invocationID.String(),
	}, nil
}

func (s *cloudSink) Handle(ctx context.Context, event AuditEvent) error {
	pmgEvent := s.translateToPmgEvent(event)
	if pmgEvent == nil {
		return nil
	}

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

	return nil
}

func (s *cloudSink) Close() error {
	return s.syncClient.Close()
}
