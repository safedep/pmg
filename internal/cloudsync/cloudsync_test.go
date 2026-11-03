package cloudsync

import (
	"context"
	"errors"
	"testing"
	"time"

	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
	recordv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/policy/record/v1"
	servicev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/controltower/v1"
	"github.com/safedep/dry/cloud"
	"github.com/safedep/dry/cloud/configsync"
	"github.com/safedep/dry/cloud/endpointsync"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recorder struct {
	order       []string
	fetchErr    error
	syncErr     error
	checkInOpts []endpointsync.CheckInOption
}

func (r *recorder) steps(t *testing.T) steps {
	return steps{
		resolveCredentials: func() (*cloud.Credentials, func() error, error) {
			creds, err := cloud.NewAPIKeyCredential("sk_test", "acme.safedep.io")
			require.NoError(t, err)
			return creds, func() error { return nil }, nil
		},
		fetchPolicy: func(context.Context, *config.RuntimeConfig, *cloud.Credentials) (*configsync.FetchResult, error) {
			r.order = append(r.order, "policy")
			if r.fetchErr != nil {
				return nil, r.fetchErr
			}
			return &configsync.FetchResult{Status: configsync.FetchNotModified, Revision: 48}, nil
		},
		newEventClient: func(*config.RuntimeConfig, *cloud.Credentials) (eventClient, error) {
			return eventStub{r: r}, nil
		},
	}
}

type eventStub struct{ r *recorder }

func (e eventStub) Sync(context.Context) (int, error) {
	e.r.order = append(e.r.order, "events")
	return 3, e.r.syncErr
}

func (e eventStub) CheckIn(_ context.Context, opts ...endpointsync.CheckInOption) error {
	e.r.order = append(e.r.order, "check-in")
	e.r.checkInOpts = opts
	return nil
}

func (e eventStub) Close() error { return nil }

func newSyncConfig(t *testing.T) *config.RuntimeConfig {
	t.Helper()
	t.Setenv("PMG_CONFIG_DIR", t.TempDir())
	config.Reload()
	t.Cleanup(config.Reload)

	cfg := config.Get()
	cfg.Config.Cloud.Enabled = true
	cfg.Config.Cloud.Policy = true
	cfg.Config.Cloud.EndpointID = "cloudsync-test"
	cfg.Config.Cloud.AutoSync.Enabled = true
	cfg.Config.Cloud.AutoSync.MinInterval = 15 * time.Minute
	return cfg
}

func TestRunOrder(t *testing.T) {
	tests := []struct {
		name      string
		autoSync  bool
		policy    bool
		plan      Plan
		fetchErr  error
		syncErr   error
		wantOrder []string
	}{
		{
			name: "the policy fetch runs first", autoSync: true, policy: true,
			plan:      Plan{Policy: StepDue, Events: StepDue},
			wantOrder: []string{"policy", "events", "check-in"},
		},
		{
			name: "the policy fetch runs with auto_sync off", autoSync: false, policy: true,
			plan:      Plan{Policy: StepDue, Events: StepDue},
			wantOrder: []string{"policy", "check-in"},
		},
		{
			name: "no policy fetch with cloud.policy off", autoSync: true, policy: false,
			plan:      Plan{Policy: StepForce, Events: StepDue},
			wantOrder: []string{"events", "check-in"},
		},
		{
			name: "a forced drain runs with auto_sync off", autoSync: false, policy: false,
			plan:      Plan{Policy: StepForce, Events: StepForce},
			wantOrder: []string{"events", "check-in"},
		},
		{
			name: "no check-in when both steps fail", autoSync: true, policy: true,
			plan:     Plan{Policy: StepDue, Events: StepDue},
			fetchErr: errors.New("unavailable"), syncErr: errors.New("unavailable"),
			wantOrder: []string{"policy", "events"},
		},
		{
			name: "a check-in after a failed fetch and a good drain", autoSync: true, policy: true,
			plan:      Plan{Policy: StepDue, Events: StepDue},
			fetchErr:  errors.New("unavailable"),
			wantOrder: []string{"policy", "events", "check-in"},
		},
		{
			name: "nothing is due", autoSync: false, policy: false,
			plan: Plan{Policy: StepDue, Events: StepDue},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := newSyncConfig(t)
			cfg.Config.Cloud.AutoSync.Enabled = tt.autoSync
			cfg.Config.Cloud.Policy = tt.policy
			rec := &recorder{fetchErr: tt.fetchErr, syncErr: tt.syncErr}

			res, err := rec.steps(t).run(context.Background(), cfg, tt.plan)

			require.NoError(t, err)
			assert.Equal(t, tt.wantOrder, rec.order)
			assert.Equal(t, tt.fetchErr, res.PolicyErr)
		})
	}
}

func TestRunChecksThePacingUnderTheLock(t *testing.T) {
	cfg := newSyncConfig(t)
	require.NoError(t, audit.WriteLastSyncAttempt(cfg.CloudPolicyLastRunPath()))
	require.NoError(t, audit.WriteLastSyncAttempt(cfg.CloudSyncLastRunPath()))
	rec := &recorder{}

	_, err := rec.steps(t).run(context.Background(), cfg, Plan{Policy: StepDue, Events: StepDue})

	require.NoError(t, err)
	assert.Empty(t, rec.order)
}

func TestRunReportsThePolicyStateOnCheckIn(t *testing.T) {
	cfg := newSyncConfig(t)
	rec := &recorder{}

	_, err := rec.steps(t).run(context.Background(), cfg, Plan{Policy: StepForce, Events: StepForce})
	require.NoError(t, err)

	req := &servicev1.CheckInRequest{}
	applyOptions(t, req, rec.checkInOpts)
	require.Len(t, req.GetTools(), 1)
	assert.Equal(t, "pmg", req.GetTools()[0].GetToolName())
	assert.Equal(t, recordv1.ApplyState_APPLY_STATE_NONE, req.GetTools()[0].GetPolicy().GetState(),
		"the stub fetch commits no cache")
	assert.NotEmpty(t, req.GetLabels())
}

// applyOptions reads the check-in options through a stub transport, the only
// view that endpointsync gives of them.
func applyOptions(t *testing.T, req *servicev1.CheckInRequest, opts []endpointsync.CheckInOption) {
	t.Helper()
	transport := &checkInTransport{}
	client, err := endpointsync.NewSyncClient("pmg", "test", transport, staticIdentity{},
		endpointsync.WithWALPath(t.TempDir()+"/wal.db"))
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, client.Close()) })

	require.NoError(t, client.CheckInWithOptions(context.Background(), opts...))
	require.NotNil(t, transport.req)
	req.SetTools(transport.req.GetTools())
	req.SetLabels(transport.req.GetLabels())
}

func TestRunRefusesWhileAnotherSyncHoldsTheLock(t *testing.T) {
	cfg := newSyncConfig(t)
	lock := audit.NewSyncLock(cfg.CloudSyncLockPath())
	locked, err := lock.TryLock()
	require.NoError(t, err)
	require.True(t, locked)
	t.Cleanup(func() { assert.NoError(t, lock.Unlock()) })

	rec := &recorder{}
	_, err = rec.steps(t).run(context.Background(), cfg, Plan{Policy: StepForce, Events: StepForce})

	assert.ErrorIs(t, err, audit.ErrSyncInProgress)
	assert.Empty(t, rec.order)
}

func TestRunWithCloudOff(t *testing.T) {
	cfg := newSyncConfig(t)
	cfg.Config.Cloud.Enabled = false
	rec := &recorder{}

	res, err := rec.steps(t).run(context.Background(), cfg, Plan{Policy: StepForce, Events: StepForce})

	require.NoError(t, err)
	assert.False(t, res.PolicyRan)
	assert.Empty(t, rec.order)
}

type checkInTransport struct {
	req *servicev1.CheckInRequest
}

func (c *checkInTransport) Send(context.Context, *servicev1.SyncEventsRequest) (*servicev1.SyncEventsResponse, error) {
	return &servicev1.SyncEventsResponse{}, nil
}

func (c *checkInTransport) CheckIn(_ context.Context, req *servicev1.CheckInRequest) (*servicev1.CheckInResponse, error) {
	c.req = req
	return &servicev1.CheckInResponse{}, nil
}

func (c *checkInTransport) Close() error { return nil }

type staticIdentity struct{}

func (staticIdentity) Resolve() (*controltowerv1.EndpointIdentity, error) {
	return controltowerv1.EndpointIdentity_builder{Identifier: "test", MachineId: "test"}.Build(), nil
}

func TestRunReportsAClientThatDoesNotStart(t *testing.T) {
	cfg := newSyncConfig(t)
	cfg.Config.Cloud.AutoSync.Enabled = false
	rec := &recorder{}
	s := rec.steps(t)
	s.newEventClient = func(*config.RuntimeConfig, *cloud.Credentials) (eventClient, error) {
		return nil, errors.New("wal is locked")
	}

	res, err := s.run(context.Background(), cfg, Plan{Policy: StepForce, Events: StepDue})

	require.NoError(t, err)
	assert.True(t, res.PolicyRan)
	assert.NoError(t, res.PolicyErr)
	assert.False(t, res.EventsRan)
	require.Error(t, res.CheckInErr, "the check-in did not run")
	assert.Contains(t, res.CheckInErr.Error(), "wal is locked")
}
