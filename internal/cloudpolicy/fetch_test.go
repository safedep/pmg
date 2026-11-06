package cloudpolicy

import (
	"context"
	"errors"
	"testing"
	"time"

	recordv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/policy/record/v1"
	specv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/policy/spec/v1"
	policyv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/controltower/policy/v1"
	"github.com/safedep/dry/cloud"
	"github.com/safedep/dry/cloud/configsync"
	"github.com/safedep/dry/cloud/endpointsync"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/audit"
	"github.com/safedep/pmg/internal/cloudpolicy/cloudpolicytest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// stubServer answers each fetch with the next reply and records the
// requests.
type stubServer struct {
	replies  []*policyv1.GetResolvedPolicyResponse
	err      error
	requests []*policyv1.GetResolvedPolicyRequest
}

func (s *stubServer) GetResolvedPolicy(_ context.Context, req *policyv1.GetResolvedPolicyRequest) (*policyv1.GetResolvedPolicyResponse, error) {
	s.requests = append(s.requests, req)
	if s.err != nil {
		return nil, s.err
	}
	if len(s.replies) == 0 {
		return nil, errors.New("no reply left")
	}
	reply := s.replies[0]
	s.replies = s.replies[1:]
	return reply, nil
}

func (s *stubServer) factory(*configsync.Store) (configsync.Transport, func(), error) {
	return s, nil, nil
}

func modified(t *testing.T, policy *specv1.ResolvedPolicy, header cloudpolicytest.Header) *policyv1.GetResolvedPolicyResponse {
	t.Helper()
	raw, err := cloudpolicytest.Marshal(policy, header)
	require.NoError(t, err)
	return policyv1.GetResolvedPolicyResponse_builder{
		Status:         policyv1.ResolvedPolicyStatus_RESOLVED_POLICY_STATUS_MODIFIED,
		ResolvedPolicy: raw,
		Digest:         configsync.Digest(raw),
		Revision:       header.Revision,
	}.Build()
}

func testCredentials(t *testing.T) *cloud.Credentials {
	t.Helper()
	creds, err := cloud.NewAPIKeyCredential("sk_test", testTenant)
	require.NoError(t, err)
	return creds
}

func header(t *testing.T, revision uint64) cloudpolicytest.Header {
	return cloudpolicytest.Header{Tenant: testTenant, MachineID: testMachineID(t), Revision: revision, DefaultPolicyRevision: 12}
}

func TestFetchCommitsTheHeldPolicy(t *testing.T) {
	cfg := newTestConfig(t)
	server := &stubServer{replies: []*policyv1.GetResolvedPolicyResponse{
		modified(t, cloudpolicytest.Policy(blockEvil()), header(t, 48)),
	}}

	res, err := fetch(context.Background(), cfg, testCredentials(t), server.factory)
	require.NoError(t, err)
	assert.Equal(t, configsync.FetchModified, res.Status)
	assert.Equal(t, uint64(48), res.Revision)

	require.Len(t, server.requests, 1)
	req := server.requests[0]
	assert.Empty(t, req.GetDigest(), "an empty cache sends no digest")
	assert.Equal(t, ToolName, req.GetToolName())
	assert.Equal(t, testMachineID(t), req.GetEndpoint().GetMachineId())
	assert.Equal(t, testEndpointID, req.GetEndpoint().GetIdentifier())
	labels := map[string]string{}
	for _, l := range req.GetLabels() {
		labels[l.GetKey()] = l.GetValue()
	}
	assert.Contains(t, labels, endpointsync.LabelReportedOS)
	assert.Contains(t, labels, endpointsync.LabelReportedArch)

	st := Load(cfg, testTenant)
	assert.Equal(t, recordv1.ApplyState_APPLY_STATE_APPLIED, st.State)
	assert.Equal(t, 1, st.BlockEntries)
}

func TestFetchSendsTheHeldDigest(t *testing.T) {
	cfg := newTestConfig(t)
	first := modified(t, cloudpolicytest.Policy(blockEvil()), header(t, 48))
	server := &stubServer{replies: []*policyv1.GetResolvedPolicyResponse{
		first,
		policyv1.GetResolvedPolicyResponse_builder{
			Status: policyv1.ResolvedPolicyStatus_RESOLVED_POLICY_STATUS_NOT_MODIFIED,
			Digest: first.GetDigest(),
		}.Build(),
	}}

	_, err := fetch(context.Background(), cfg, testCredentials(t), server.factory)
	require.NoError(t, err)
	res, err := fetch(context.Background(), cfg, testCredentials(t), server.factory)
	require.NoError(t, err)

	assert.Equal(t, configsync.FetchNotModified, res.Status)
	require.Len(t, server.requests, 2)
	assert.Equal(t, first.GetDigest(), server.requests[1].GetDigest())
}

func TestFetchRejectsAPolicyOfAnotherMachine(t *testing.T) {
	cfg := newTestConfig(t)
	other := header(t, 49)
	other.MachineID = "another-machine"
	server := &stubServer{replies: []*policyv1.GetResolvedPolicyResponse{
		modified(t, cloudpolicytest.Policy(blockEvil()), header(t, 48)),
		modified(t, cloudpolicytest.Policy(), other),
	}}

	_, err := fetch(context.Background(), cfg, testCredentials(t), server.factory)
	require.NoError(t, err)
	_, err = fetch(context.Background(), cfg, testCredentials(t), server.factory)
	require.ErrorIs(t, err, configsync.ErrRejected)

	st := Load(cfg, testTenant)
	assert.Equal(t, recordv1.ApplyState_APPLY_STATE_REJECTED, st.State)
	require.NotNil(t, st.Applied)
	assert.Equal(t, uint64(48), st.Applied.Revision, "pmg keeps the policy that it applied")
	assert.Equal(t, 1, st.BlockEntries)
	assert.Contains(t, st.RejectedReason(), "machine")
}

func TestFetchErrorKeepsTheCache(t *testing.T) {
	cfg := newTestConfig(t)
	server := &stubServer{replies: []*policyv1.GetResolvedPolicyResponse{
		modified(t, cloudpolicytest.Policy(blockEvil()), header(t, 48)),
	}}
	_, err := fetch(context.Background(), cfg, testCredentials(t), server.factory)
	require.NoError(t, err)

	server.err = status.Error(codes.Unavailable, "try later")
	_, err = fetch(context.Background(), cfg, testCredentials(t), server.factory)
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err))

	st := Load(cfg, testTenant)
	assert.Equal(t, recordv1.ApplyState_APPLY_STATE_APPLIED, st.State)
	assert.Equal(t, 1, st.BlockEntries)
}

func TestFetchKeepsTheLastValidCapability(t *testing.T) {
	cfg := newTestConfig(t)
	tooLong := 400 * 24 * time.Hour
	server := &stubServer{replies: []*policyv1.GetResolvedPolicyResponse{
		modified(t, cloudpolicytest.WithCooldown(cloudpolicytest.Policy(), 72*time.Hour), header(t, 48)),
		modified(t, cloudpolicytest.WithCooldown(cloudpolicytest.Policy(blockEvil()), tooLong), header(t, 49)),
		modified(t, cloudpolicytest.WithCooldown(cloudpolicytest.Policy(), tooLong), header(t, 50)),
	}}

	for range 3 {
		_, err := fetch(context.Background(), cfg, testCredentials(t), server.factory)
		require.NoError(t, err)
	}

	st := Load(cfg, testTenant)
	require.NotNil(t, st.Applied)
	assert.Equal(t, uint64(50), st.Applied.Revision)
	assert.Equal(t, []string{"package_admission"}, st.Projection.Restored,
		"a capability that fails in two policies in a row keeps its last valid value")

	target := cfg.Config
	Apply(cfg, &target, st)
	assert.Equal(t, config.DependencyCooldownConfig{Enabled: true, Days: 3}, target.DependencyCooldown)
}

func TestFetchRecordsEachAttempt(t *testing.T) {
	cfg := newTestConfig(t)
	assert.True(t, audit.PolicyFetchDue(cfg), "pmg fetches when it never fetched")

	server := &stubServer{err: status.Error(codes.Unavailable, "try later")}
	_, err := fetchAndRecord(context.Background(), cfg, testCredentials(t), server.factory)
	require.Error(t, err)

	assert.False(t, audit.PolicyFetchDue(cfg), "a failed fetch waits for the policy pacing too")
}
