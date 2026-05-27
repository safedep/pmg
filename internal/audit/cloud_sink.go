package audit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/safedep/dry/cloud/endpointsync"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
)

type cloudSink struct {
	*SyncClientBundle
	invocationID string
	envResolver  CloudSinkEnvResolver
	command      string
	workingDir   string
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

	wd, _ := os.Getwd()

	return &cloudSink{
		SyncClientBundle: bundle,
		invocationID:     invocationID.String(),
		envResolver:      NewCloudSinkEnvResolver(),
		workingDir:       wd,
	}, nil
}

func (s *cloudSink) Handle(ctx context.Context, event AuditEvent) error {
	if event.Type == EventTypeInstallStarted {
		s.command = buildCommand(event.PackageManager, event.Args)
		return nil
	}

	pmgEvents := s.translateToPmgEvents(event)
	if len(pmgEvents) == 0 {
		return nil
	}

	invocationContext := s.envResolver.Resolve(s.command, s.workingDir)

	for _, pmgEvent := range pmgEvents {
		toolEvent, err := s.syncClient.NewEvent()
		if err != nil {
			return fmt.Errorf("failed to create tool event: %w", err)
		}

		toolEvent.SetPmgEvent(pmgEvent)
		toolEvent.SetInvocationId(s.invocationID)
		toolEvent.SetInvocationContext(invocationContext)

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

func buildCommand(packageManager string, args []string) string {
	if packageManager == "" {
		return ""
	}
	if len(args) == 0 {
		return packageManager
	}
	return packageManager + " " + strings.Join(args, " ")
}

// Close delegates to the embedded SyncClientBundle.Close().
func (s *cloudSink) Close() error {
	return s.SyncClientBundle.Close()
}
