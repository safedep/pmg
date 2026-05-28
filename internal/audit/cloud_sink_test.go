package audit

import (
	"context"
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

func newTestCloudSink(t *testing.T, transport endpointsync.EventTransport) *cloudSink {
	t.Helper()
	walPath := t.TempDir() + "/test-sync.db"
	identity := endpointsync.NewEndpointIdentityResolver()
	syncClient, err := endpointsync.NewSyncClient("pmg", "test", transport, identity,
		endpointsync.WithWALPath(walPath))
	require.NoError(t, err)
	return &cloudSink{
		SyncClientBundle: &SyncClientBundle{syncClient: syncClient},
		invocationID:     "test-invocation",
		workingDir: t.TempDir(),
	}
}

func TestCloudSinkEmitsTranslatableEvents(t *testing.T) {
	transport := &mockTransport{}

	sink := newTestCloudSink(t, transport)
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
	transport := &mockTransport{}

	sink := newTestCloudSink(t, transport)
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
	transport := &mockTransport{}

	sink := newTestCloudSink(t, transport)
	defer func() {
		require.NoError(t, sink.Close())
	}()

	ctx := context.Background()
	err := sink.Handle(ctx, AuditEvent{
		Type:      EventTypeMalwareBlocked,
		Timestamp: time.Now(),
		Message:   "blocked malware package",
	})
	require.NoError(t, err)

	synced, err := sink.syncClient.Sync(ctx)
	require.NoError(t, err)

	assert.Equal(t, 1, synced)
	assert.Equal(t, 1, len(transport.requests))
}

func TestCloudSinkSetsInvocationContextOnSessionComplete(t *testing.T) {
	transport := &mockTransport{}

	sink := newTestCloudSink(t, transport)
	defer func() {
		require.NoError(t, sink.Close())
	}()

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

	synced, err := sink.syncClient.Sync(ctx)
	require.NoError(t, err)
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
}
