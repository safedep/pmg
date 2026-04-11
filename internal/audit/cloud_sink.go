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
)

type cloudSink struct {
	syncClient   *endpointsync.SyncClient
	cloudClient  *cloud.Client
	invocationID string
}

func newCloudSink(cfg *config.RuntimeConfig) (*cloudSink, error) {
	bundle, err := NewSyncClientBundle(cfg)
	if err != nil {
		return nil, err
	}

	invocationID, err := uuid.NewRandom()
	if err != nil {
		if closeErr := bundle.Close(); closeErr != nil {
			log.Warnf("failed to close sync client bundle after invocation ID failure: %v", closeErr)
		}
		return nil, fmt.Errorf("failed to generate invocation ID: %w", err)
	}

	return &cloudSink{
		syncClient:   bundle.SyncClient,
		cloudClient:  bundle.cloudClient,
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
