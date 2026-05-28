package audit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
	"github.com/google/uuid"
	"github.com/safedep/dry/cloud/endpointsync"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
)

type cloudSink struct {
	*SyncClientBundle
	invocationID string
	ciResolver  CloudSinkCIResolver
	command      string
	workingDir   string
}

func newCloudSink(cfg *config.RuntimeConfig, ciResolver CloudSinkCIResolver) (*cloudSink, error) {
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

	wd, err := os.Getwd()
	if err != nil {
		if closeErr := bundle.Close(); closeErr != nil {
			log.Warnf("failed to close sync client bundle after getwd failure: %v", closeErr)
		}
		return nil, fmt.Errorf("failed to get working directory: %w", err)
	}

	return &cloudSink{
		SyncClientBundle: bundle,
		invocationID:     invocationID.String(),
		ciResolver:       ciResolver,
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

	for _, pmgEvent := range pmgEvents {
		toolEvent, err := s.syncClient.NewEvent()
		if err != nil {
			return fmt.Errorf("failed to create tool event: %w", err)
		}

		toolEvent.SetPmgEvent(pmgEvent)
		toolEvent.SetInvocationId(s.invocationID)
		// Invocation context (CI, command, working dir) is set once per
		// execution on the session summary event to avoid redundancy.
		if event.Type == EventTypeSessionComplete {
			toolEvent.SetInvocationContext(s.buildInvocationContext())
		}

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

func (s *cloudSink) buildInvocationContext() *controltowerv1.EndpointInvocationContext {
	ctx := &controltowerv1.EndpointInvocationContext{}
	ctx.SetCommand(s.command)
	ctx.SetWorkingDirectory(s.workingDir)

	if s.ciResolver != nil {
		ci := &controltowerv1.EndpointCIContext{}
		ci.SetProvider(s.ciResolver.Provider())
		ci.SetRunId(s.ciResolver.RunId())
		ci.SetRepository(s.ciResolver.Repository())
		ci.SetBranch(s.ciResolver.Branch())
		ci.SetCommitSha(s.ciResolver.CommitSha())
		ci.SetActor(s.ciResolver.Actor())
		ci.SetPrNumber(s.ciResolver.PrNumber())
		if metadata := s.ciResolver.Metadata(); len(metadata) > 0 {
			ci.SetMetadata(metadata)
		}
		ctx.SetCi(ci)
	}

	return ctx
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
