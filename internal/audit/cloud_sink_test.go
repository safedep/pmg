package audit

import (
	"context"
	"testing"
	"time"

	servicev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/controltower/v1"
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

func TestCloudSinkEmitsTranslatableEvents(t *testing.T) {
	transport := &mockTransport{}
	walPath := t.TempDir() + "/test-sync.db"

	sink, err := newCloudSinkWithTransport(transport, "", walPath)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, sink.Close())
	}()

	err = sink.Handle(context.Background(), AuditEvent{
		Type:      EventTypeMalwareBlocked,
		Timestamp: time.Now(),
		Message:   "blocked malware package",
	})
	assert.NoError(t, err)
}

func TestCloudSinkSkipsUntranslatableEvents(t *testing.T) {
	transport := &mockTransport{}
	walPath := t.TempDir() + "/test-sync.db"

	sink, err := newCloudSinkWithTransport(transport, "", walPath)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, sink.Close())
	}()

	err = sink.Handle(context.Background(), AuditEvent{
		Type:      EventTypeProxyHostObserved,
		Timestamp: time.Now(),
		Message:   "observed proxy host",
		Hostname:  "example.com",
	})
	assert.NoError(t, err)
}

func TestCloudSinkEmitAndSync(t *testing.T) {
	transport := &mockTransport{}
	walPath := t.TempDir() + "/test-sync.db"

	sink, err := newCloudSinkWithTransport(transport, "", walPath)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, sink.Close())
	}()

	ctx := context.Background()
	err = sink.Handle(ctx, AuditEvent{
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
