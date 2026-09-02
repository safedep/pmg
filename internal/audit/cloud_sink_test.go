package audit

import (
	"context"
	"os/user"
	"sync"
	"testing"
	"time"

	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
	servicev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/controltower/v1"
	"github.com/safedep/dry/cloud/endpointsync"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockTransport struct {
	requests []*servicev1.SyncEventsRequest
	closed   bool
}

func (m *mockTransport) Send(_ context.Context, req *servicev1.SyncEventsRequest) (*servicev1.SyncEventsResponse, error) {
	m.requests = append(m.requests, req)
	confirmed := make([]string, 0, len(req.GetEvents()))
	for _, e := range req.GetEvents() {
		confirmed = append(confirmed, e.GetEventId())
	}
	return &servicev1.SyncEventsResponse{ConfirmedEventIds: confirmed}, nil
}

func (m *mockTransport) CheckIn(_ context.Context, _ *servicev1.CheckInRequest) (*servicev1.CheckInResponse, error) {
	return &servicev1.CheckInResponse{}, nil
}

func (m *mockTransport) Close() error {
	m.closed = true
	return nil
}

func newTestCloudSink(t *testing.T) (*cloudSink, string) {
	t.Helper()
	walPath := t.TempDir() + "/test-sync.db"
	sink := newTestCloudSinkAtPath(t, walPath, cloudSyncOptions)
	return sink, walPath
}

type cloudSyncOptionsFunc func(string) []endpointsync.SyncOption

func newTestEventEmitter(walPath string, options cloudSyncOptionsFunc) (*endpointsync.EventEmitterClient, error) {
	return endpointsync.NewEventEmitterClient("pmg", "test", options(walPath)...)
}

func newTestCloudSinkAtPath(t *testing.T, walPath string, options cloudSyncOptionsFunc) *cloudSink {
	t.Helper()
	emitter, err := newTestEventEmitter(walPath, options)
	require.NoError(t, err)
	return &cloudSink{
		emitter:      emitter,
		invocationID: "test-invocation",
		workingDir:   t.TempDir(),
	}
}

// drainWAL closes the sink (mirroring the real lifecycle, where audit.Close()
// runs before a sync process starts) and syncs the WAL at walPath through a
// SyncClient backed by transport, returning the number of events synced.
func drainWAL(t *testing.T, walPath string, transport endpointsync.EventTransport) int {
	t.Helper()
	syncClient, err := endpointsync.NewSyncClient("pmg", "test", transport,
		endpointsync.NewEndpointIdentityResolver(), cloudSyncOptions(walPath)...)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, syncClient.Close())
	}()

	synced, err := syncClient.Sync(context.Background())
	require.NoError(t, err)
	return synced
}

func TestCloudSinkEmitsTranslatableEvents(t *testing.T) {
	sink, _ := newTestCloudSink(t)
	defer func() {
		require.NoError(t, sink.Close())
	}()

	err := sink.Handle(context.Background(), AuditEvent{
		Type:      EventTypeMalwareBlocked,
		Timestamp: time.Now(),
		Message:   "blocked malware package",
	})
	assert.NoError(t, err)
}

func TestCloudSinkSkipsUntranslatableEvents(t *testing.T) {
	sink, _ := newTestCloudSink(t)
	defer func() {
		require.NoError(t, sink.Close())
	}()

	err := sink.Handle(context.Background(), AuditEvent{
		Type:      EventTypeProxyHostObserved,
		Timestamp: time.Now(),
		Message:   "observed proxy host",
		Hostname:  "example.com",
	})
	assert.NoError(t, err)
}

func TestCloudSinkEmitAndSync(t *testing.T) {
	sink, walPath := newTestCloudSink(t)

	ctx := context.Background()
	err := sink.Handle(ctx, AuditEvent{
		Type:      EventTypeMalwareBlocked,
		Timestamp: time.Now(),
		Message:   "blocked malware package",
	})
	require.NoError(t, err)
	require.NoError(t, sink.Close())

	transport := &mockTransport{}
	synced := drainWAL(t, walPath, transport)

	assert.Equal(t, 1, synced)
	assert.Equal(t, 1, len(transport.requests))
}

func TestCloudSinkDeduplicatesOnlyMatchingHostObservations(t *testing.T) {
	sink, walPath := newTestCloudSink(t)
	ctx := context.Background()

	for range 3 {
		require.NoError(t, sink.Handle(ctx, AuditEvent{
			Type:     EventTypeProxyHostObserved,
			Hostname: "registry.example.com",
			Method:   "CONNECT",
		}))
	}

	require.NoError(t, sink.Handle(ctx, AuditEvent{
		Type:     EventTypeProxyHostObserved,
		Hostname: "registry.example.com",
		Method:   "GET",
	}))

	for range 2 {
		require.NoError(t, sink.Handle(ctx, AuditEvent{
			Type:      EventTypeMalwareBlocked,
			Timestamp: time.Now(),
			Message:   "blocked malware package",
		}))
	}

	require.NoError(t, sink.Close())

	transport := &mockTransport{}
	assert.Equal(t, 4, drainWAL(t, walPath, transport))

	var hostObservations int
	var packageDecisions int
	for _, req := range transport.requests {
		for _, event := range req.GetEvents() {
			switch event.GetPmgEvent().GetEventType() {
			case controltowerv1.PmgEventType_PMG_EVENT_TYPE_HOST_OBSERVATION:
				hostObservations++
			case controltowerv1.PmgEventType_PMG_EVENT_TYPE_PACKAGE_DECISION:
				packageDecisions++
			}
		}
	}

	assert.Equal(t, 2, hostObservations)
	assert.Equal(t, 2, packageDecisions)
}

func TestCloudSinkDeduplicatesAcrossInvocations(t *testing.T) {
	walPath := t.TempDir() + "/test-sync.db"

	first := newTestCloudSinkAtPath(t, walPath, cloudSyncOptions)
	require.NoError(t, first.Handle(context.Background(), AuditEvent{
		Type:     EventTypeProxyHostObserved,
		Hostname: "registry.example.com",
		Method:   "CONNECT",
	}))
	require.NoError(t, first.Close())

	second := newTestCloudSinkAtPath(t, walPath, cloudSyncOptions)
	second.invocationID = "second-invocation"
	require.NoError(t, second.Handle(context.Background(), AuditEvent{
		Type:     EventTypeProxyHostObserved,
		Hostname: "registry.example.com",
		Method:   "CONNECT",
	}))
	require.NoError(t, second.Close())

	transport := &mockTransport{}
	assert.Equal(t, 1, drainWAL(t, walPath, transport))
}

func TestCloudSinkDeduplicatesConcurrentInvocations(t *testing.T) {
	walPath := t.TempDir() + "/test-sync.db"
	first := newTestCloudSinkAtPath(t, walPath, cloudSyncOptions)
	second := newTestCloudSinkAtPath(t, walPath, cloudSyncOptions)

	start := make(chan struct{})
	errs := make(chan error, 40)
	var wg sync.WaitGroup
	for _, sink := range []*cloudSink{first, second} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range 20 {
				errs <- sink.Handle(context.Background(), AuditEvent{
					Type:     EventTypeProxyHostObserved,
					Hostname: "registry.example.com",
					Method:   "CONNECT",
				})
			}
		}()
	}

	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.NoError(t, first.Close())
	require.NoError(t, second.Close())

	transport := &mockTransport{}
	assert.Equal(t, 1, drainWAL(t, walPath, transport))
}

func TestCloudSinkFlushesRepeatCountAfterWindow(t *testing.T) {
	const window = 100 * time.Millisecond
	options := func(walPath string) []endpointsync.SyncOption {
		rule := hostObservationDedupRule()
		rule.Window = window
		return []endpointsync.SyncOption{
			endpointsync.WithWALPath(walPath),
			endpointsync.WithDedupRules(rule),
		}
	}

	walPath := t.TempDir() + "/test-sync.db"
	sink := newTestCloudSinkAtPath(t, walPath, options)
	for range 4 {
		require.NoError(t, sink.Handle(context.Background(), AuditEvent{
			Type:     EventTypeProxyHostObserved,
			Hostname: "registry.example.com",
			Method:   "CONNECT",
		}))
	}

	time.Sleep(4 * window)
	require.NoError(t, sink.Close())

	transport := &mockTransport{}
	assert.Equal(t, 2, drainWAL(t, walPath, transport))

	var repeatCounts []uint64
	for _, req := range transport.requests {
		for _, event := range req.GetEvents() {
			if context := event.GetDedupContext(); context != nil {
				repeatCounts = append(repeatCounts, context.GetRepeatCount())
			}
		}
	}
	assert.Equal(t, []uint64{3}, repeatCounts)
}

func TestCloudSinkSetsInvocationContextOnSessionComplete(t *testing.T) {
	sink, walPath := newTestCloudSink(t)

	ctx := context.Background()

	err := sink.Handle(ctx, AuditEvent{
		Type:           EventTypeInstallStarted,
		Timestamp:      time.Now(),
		PackageManager: "npm",
		Args:           []string{"install", "express"},
	})
	require.NoError(t, err)

	err = sink.Handle(ctx, AuditEvent{
		Type:      EventTypeMalwareBlocked,
		Timestamp: time.Now(),
		Message:   "blocked malware package",
	})
	require.NoError(t, err)

	err = sink.Handle(ctx, AuditEvent{
		Type:      EventTypeSessionComplete,
		Timestamp: time.Now(),
		SessionData: &SessionData{
			PackageManager: "npm",
			FlowType:       FlowTypeProxy,
			Outcome:        OutcomeSuccess,
			TotalAnalyzed:  1,
			AllowedCount:   1,
		},
	})
	require.NoError(t, err)

	require.NoError(t, sink.Close())

	transport := &mockTransport{}
	synced := drainWAL(t, walPath, transport)
	assert.Equal(t, 2, synced)
	require.Equal(t, 1, len(transport.requests))

	events := transport.requests[0].GetEvents()
	require.Equal(t, 2, len(events))

	malwareEvent := events[0]
	assert.Nil(t, malwareEvent.GetInvocationContext(), "non-session events should not have invocation context")

	sessionEvent := events[1]
	invCtx := sessionEvent.GetInvocationContext()
	require.NotNil(t, invCtx, "session complete event must have invocation context")
	assert.Contains(t, invCtx.GetCommand(), "npm")
	assert.NotEmpty(t, invCtx.GetWorkingDirectory())
	assert.NotEmpty(t, invCtx.GetUsername())
	assert.NotEmpty(t, invCtx.GetUsernameUid())
}

func TestCloudSinkSetsKubernetesContextOnSessionSummary(t *testing.T) {
	sink, walPath := newTestCloudSink(t)
	sink.kubernetes = &cloudSinkKubernetesContext{
		Cluster:      "prod-eu",
		Namespace:    "payments",
		WorkloadName: "checkout",
		WorkloadKind: "Deployment",
		PodName:      "checkout-75d84f5bdf-abc12",
		PodUID:       "pod-uid-123",
	}

	ctx := context.Background()

	require.NoError(t, sink.Handle(ctx, AuditEvent{
		Type:           EventTypeInstallStarted,
		Timestamp:      time.Now(),
		PackageManager: "npm",
		Args:           []string{"install", "express"},
	}))
	require.NoError(t, sink.Handle(ctx, AuditEvent{
		Type:      EventTypeMalwareBlocked,
		Timestamp: time.Now(),
		Message:   "blocked malware package",
	}))
	require.NoError(t, sink.Handle(ctx, AuditEvent{
		Type:      EventTypeSessionComplete,
		Timestamp: time.Now(),
		SessionData: &SessionData{
			PackageManager: "npm",
			FlowType:       FlowTypeProxy,
			Outcome:        OutcomeBlocked,
			TotalAnalyzed:  1,
			BlockedCount:   1,
		},
	}))
	require.NoError(t, sink.Close())

	transport := &mockTransport{}
	synced := drainWAL(t, walPath, transport)
	require.Equal(t, 2, synced)
	require.Equal(t, 1, len(transport.requests))

	events := transport.requests[0].GetEvents()
	require.Equal(t, 2, len(events))

	// Per-package events share the invocation ID and carry no invocation
	// context. The backend reads Kubernetes details from the summary once.
	assert.Nil(t, events[0].GetInvocationContext(), "per-package events must not duplicate invocation context")

	invCtx := events[1].GetInvocationContext()
	require.NotNil(t, invCtx, "session summary must carry invocation context")
	k8s := invCtx.GetKubernetes()
	require.NotNil(t, k8s, "session summary invocation context must include Kubernetes details")
	assert.Equal(t, "prod-eu", k8s.GetCluster())
	assert.Equal(t, "payments", k8s.GetNamespace())
	assert.Equal(t, "checkout", k8s.GetWorkloadName())
	assert.Equal(t, controltowerv1.EndpointKubernetesWorkloadKind_ENDPOINT_KUBERNETES_WORKLOAD_KIND_DEPLOYMENT, k8s.GetWorkloadKind())
	assert.Equal(t, "checkout-75d84f5bdf-abc12", k8s.GetPodName())
	assert.Equal(t, "pod-uid-123", k8s.GetPodUid())
}

func TestInvokingUserIgnoresSudoUserWhenNotElevated(t *testing.T) {
	current, err := user.Current()
	require.NoError(t, err)

	orig := auditGeteuid
	t.Cleanup(func() { auditGeteuid = orig })

	// Non-root process: SUDO_USER must be ignored, else attribution is spoofable.
	auditGeteuid = func() int { return 1000 }
	t.Setenv("SUDO_USER", "root")
	got := invokingUser()
	require.NotNil(t, got)
	assert.Equal(t, current.Username, got.Username, "SUDO_USER must not override attribution when not elevated")

	// Elevated (euid 0): SUDO_USER is trusted and used.
	auditGeteuid = func() int { return 0 }
	t.Setenv("SUDO_USER", current.Username)
	got = invokingUser()
	require.NotNil(t, got)
	assert.Equal(t, current.Username, got.Username)
}

func TestInvokingUserKeepsSudoAttributionWithoutPasswdEntry(t *testing.T) {
	orig := auditGeteuid
	t.Cleanup(func() { auditGeteuid = orig })

	auditGeteuid = func() int { return 0 }
	t.Setenv("SUDO_USER", "no-such-user-xyz")
	t.Setenv("SUDO_UID", "4242")

	got := invokingUser()
	require.NotNil(t, got)
	assert.Equal(t, "no-such-user-xyz", got.Username)
	assert.Equal(t, "4242", got.Uid)

	// Without SUDO_UID, fall back to the effective uid: a non-root username
	// with uid 0 correctly signals the command ran under sudo.
	t.Setenv("SUDO_UID", "")
	got = invokingUser()
	require.NotNil(t, got)
	assert.Equal(t, "no-such-user-xyz", got.Username)
	assert.Equal(t, "0", got.Uid)
}
