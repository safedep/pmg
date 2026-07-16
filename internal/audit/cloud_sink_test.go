package audit

import (
	"context"
	"os/user"
	"testing"
	"time"

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

func (m *mockTransport) Close() error {
	m.closed = true
	return nil
}

func newTestCloudSink(t *testing.T) (*cloudSink, string) {
	t.Helper()
	walPath := t.TempDir() + "/test-sync.db"
	emitter, err := endpointsync.NewEventEmitterClient("pmg", "test",
		endpointsync.WithWALPath(walPath))
	require.NoError(t, err)
	return &cloudSink{
		emitter:      emitter,
		invocationID: "test-invocation",
		workingDir:   t.TempDir(),
	}, walPath
}

// drainWAL closes the sink (mirroring the real lifecycle, where audit.Close()
// runs before a sync process starts) and syncs the WAL at walPath through a
// SyncClient backed by transport, returning the number of events synced.
func drainWAL(t *testing.T, walPath string, transport endpointsync.EventTransport) int {
	t.Helper()
	syncClient, err := endpointsync.NewSyncClient("pmg", "test", transport,
		endpointsync.NewEndpointIdentityResolver(), endpointsync.WithWALPath(walPath))
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
			FlowType:       FlowTypeGuard,
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
