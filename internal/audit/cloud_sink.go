package audit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"

	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
	"github.com/google/uuid"
	"github.com/safedep/dry/cloud/endpointsync"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
)

type cloudSink struct {
	emitter      *endpointsync.EventEmitterClient
	invocationID string
	ciResolver   CloudSinkCIResolver
	kubernetes   *cloudSinkKubernetesContext
	command      string
	workingDir   string
}

func newCloudSink(cfg *config.RuntimeConfig, ciResolver CloudSinkCIResolver) (*cloudSink, error) {
	emitter, err := endpointsync.NewEventEmitterClient("pmg", pmgToolVersion(),
		endpointsync.WithWALPath(cfg.CloudSyncDBPath()))
	if err != nil {
		return nil, err
	}

	invocationID, err := uuid.NewRandom()
	if err != nil {
		if closeErr := emitter.Close(); closeErr != nil {
			log.Warnf("failed to close event emitter after invocation ID failure: %v", closeErr)
		}
		return nil, fmt.Errorf("failed to generate invocation ID: %w", err)
	}

	wd, err := os.Getwd()
	if err != nil {
		if closeErr := emitter.Close(); closeErr != nil {
			log.Warnf("failed to close event emitter after getwd failure: %v", closeErr)
		}
		return nil, fmt.Errorf("failed to get working directory: %w", err)
	}

	return &cloudSink{
		emitter:      emitter,
		invocationID: invocationID.String(),
		ciResolver:   ciResolver,
		kubernetes:   newCloudSinkKubernetesContext(),
		workingDir:   wd,
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
		toolEvent, err := s.emitter.NewEvent()
		if err != nil {
			return fmt.Errorf("failed to create tool event: %w", err)
		}

		toolEvent.SetPmgEvent(pmgEvent)
		toolEvent.SetInvocationId(s.invocationID)
		// Invocation context (CI, command, working dir, Kubernetes) is set once
		// per execution on the session summary event. Every event shares the
		// invocation ID, so the backend joins the context without storing it on
		// each event.
		if event.Type == EventTypeSessionComplete {
			toolEvent.SetInvocationContext(s.buildInvocationContext())
		}

		if err := s.emitter.Emit(ctx, toolEvent); err != nil {
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

	if u := invokingUser(); u != nil {
		ctx.SetUsername(u.Username)
		ctx.SetUsernameUid(u.Uid)
	}

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

	if s.kubernetes != nil {
		k := &controltowerv1.EndpointKubernetesContext{}
		k.SetCluster(s.kubernetes.Cluster)
		k.SetNamespace(s.kubernetes.Namespace)
		k.SetWorkloadName(s.kubernetes.WorkloadName)
		k.SetWorkloadKind(mapKubernetesWorkloadKind(s.kubernetes.WorkloadKind))
		k.SetPodName(s.kubernetes.PodName)
		k.SetPodUid(s.kubernetes.PodUID)
		ctx.SetKubernetes(k)
	}

	return ctx
}

var auditGeteuid = os.Geteuid

// invokingUser resolves the human behind the command. SUDO_USER is honored
// only when the process is actually elevated (euid 0); otherwise any user
// could set SUDO_USER to spoof cloud-audit attribution to another account.
func invokingUser() *user.User {
	if auditGeteuid() == 0 {
		if name := os.Getenv("SUDO_USER"); name != "" {
			if u, err := user.Lookup(name); err == nil {
				return u
			}
			// No passwd entry for the sudo user (minimal containers): keep
			// the attribution sudo recorded rather than reporting root. When
			// SUDO_UID is also absent, fall back to the effective uid (0) —
			// a non-root username with uid 0 is correct and signals the
			// command ran under sudo.
			uid := os.Getenv("SUDO_UID")
			if uid == "" {
				uid = strconv.Itoa(auditGeteuid())
			}
			return &user.User{Username: name, Uid: uid}
		}
	}
	u, err := user.Current()
	if err != nil {
		return nil
	}
	return u
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

// Close releases the emitter's WAL handle.
func (s *cloudSink) Close() error {
	return s.emitter.Close()
}
