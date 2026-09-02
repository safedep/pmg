package proxye2e

import (
	"context"
	"database/sql"
	"testing"

	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
	servicev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/controltower/v1"
	"github.com/safedep/dry/cloud/endpointsync"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingTransport stands in for SafeDep Cloud and confirms every event.
type recordingTransport struct {
	events []*servicev1.ToolEvent
}

func (r *recordingTransport) Send(_ context.Context, req *servicev1.SyncEventsRequest) (*servicev1.SyncEventsResponse, error) {
	confirmed := make([]string, 0, len(req.GetEvents()))
	for _, event := range req.GetEvents() {
		r.events = append(r.events, event)
		confirmed = append(confirmed, event.GetEventId())
	}
	return &servicev1.SyncEventsResponse{ConfirmedEventIds: confirmed}, nil
}

func (r *recordingTransport) CheckIn(_ context.Context, _ *servicev1.CheckInRequest) (*servicev1.CheckInResponse, error) {
	return &servicev1.CheckInResponse{}, nil
}

func (r *recordingTransport) Close() error { return nil }

// The real cloud audit sink writes to the WAL under the config directory, so
// the directory is isolated before RunCases captures the global config.
// Cleanups run last in, first out. The reload is registered first so it runs
// after the environment is restored.
func TestProxyFlow_HostObservationDedup(t *testing.T) {
	t.Cleanup(config.Reload)
	t.Setenv("PMG_CONFIG_DIR", t.TempDir())
	config.Reload()

	const host = "registry.example.com"
	const observations = 4

	RunCases(t, []TestCase{
		{
			Name: "repeated observations of one host collapse into one event and one carrier",
			Config: func(rc *config.RuntimeConfig) {
				rc.Config.Cloud.Enabled = true
				rc.Config.SkipEventLogging = true
			},
			Setup: func(h *Harness) {
				require.NoError(h.t, audit.Initialize(config.Get()))
				// Close leaves the closed cloud sink installed as the global
				// auditor. Install an eventlog-only auditor after the case so
				// later cases do not write to a closed WAL. The event log is
				// not initialized in tests, so that auditor is a no-op.
				h.t.Cleanup(func() {
					require.NoError(h.t, audit.Close())
					require.NoError(h.t, audit.Initialize(&config.RuntimeConfig{}))
				})
			},
			Exec: func(h *Harness) ExecResult {
				// An unknown host is tunneled, so each CONNECT is one host
				// observation. The TLS handshake with the mock fails after the
				// tunnel opens, which is fine: the observation already happened.
				// Closing idle connections forces a new tunnel per request.
				for range observations {
					_, _ = h.RawClient().Get("https://" + host + "/package")
					h.RawClient().CloseIdleConnections()
				}
				return ExecResult{}
			},
			Assert: func(t *testing.T, h *Harness, _ ExecResult) {
				assert.Contains(t, h.DialedAddrs(), host+":443")

				// The emitter stays open during the drains, as it does when
				// the daemon syncs in the background.
				walPath := config.Get().CloudSyncDBPath()

				first := drainCloudWAL(t, walPath)
				require.Len(t, first, 1)
				assertHostObservation(t, first[0], host, "CONNECT")
				assert.Nil(t, first[0].GetDedupContext())

				expireDedupWindows(t, walPath)

				carrier := drainCloudWAL(t, walPath)
				require.Len(t, carrier, 1)
				assertHostObservation(t, carrier[0], host, "CONNECT")
				require.NotNil(t, carrier[0].GetDedupContext())
				assert.EqualValues(t, observations-1, carrier[0].GetDedupContext().GetRepeatCount())
			},
		},
	})
}

// drainCloudWAL syncs the WAL against an in-process transport. The sweep reads
// the expiry from each state row, so the sync client needs no dedup rules.
func drainCloudWAL(t *testing.T, walPath string) []*servicev1.ToolEvent {
	t.Helper()

	transport := &recordingTransport{}
	client, err := endpointsync.NewSyncClient("pmg", "test", transport,
		endpointsync.NewEndpointIdentityResolver(), endpointsync.WithWALPath(walPath))
	require.NoError(t, err)

	_, err = client.Sync(context.Background())
	require.NoError(t, err)
	require.NoError(t, client.Close())
	return transport.events
}

// expireDedupWindows moves every open dedup window into the past. The
// emitter's clock is not injectable, so the test edits the DRY state table
// directly. DRY registers the sqlite driver.
func expireDedupWindows(t *testing.T, walPath string) {
	t.Helper()

	db, err := sql.Open("sqlite", walPath)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, db.Close())
	}()

	result, err := db.Exec("UPDATE dedup_state SET expires_at = 0")
	require.NoError(t, err)
	rows, err := result.RowsAffected()
	require.NoError(t, err)
	require.EqualValues(t, 1, rows)
}

func assertHostObservation(t *testing.T, event *servicev1.ToolEvent, hostname, method string) {
	t.Helper()

	pmgEvent := event.GetPmgEvent()
	require.NotNil(t, pmgEvent)
	assert.Equal(t, controltowerv1.PmgEventType_PMG_EVENT_TYPE_HOST_OBSERVATION, pmgEvent.GetEventType())
	require.NotNil(t, pmgEvent.GetHostObservation())
	assert.Equal(t, hostname, pmgEvent.GetHostObservation().GetHostname())
	assert.Equal(t, method, pmgEvent.GetHostObservation().GetMethod())
}
