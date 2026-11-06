package cloudpolicy

import (
	recordv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/policy/record/v1"
	servicev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/controltower/v1"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/audit"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ToolPolicyState returns the cloud policy state of pmg for the check-in. It
// returns nil when cloud.enabled is off, because then pmg does not check in.
// With cloud.policy off, the state is APPLY_STATE_DISABLED.
func ToolPolicyState(st *Status) *servicev1.ToolPolicyState {
	if st == nil || !st.CloudOn {
		return nil
	}

	report := recordv1.ApplyReport_builder{
		State:          st.State,
		RejectedReason: st.RejectedReason(),
		Exceptions:     st.Exceptions(),
	}

	if st.State != recordv1.ApplyState_APPLY_STATE_DISABLED {
		if st.Applied != nil {
			report.Revision = st.Applied.Revision
			report.DefaultPolicyRevision = st.Applied.DefaultPolicyRevision
			report.Digest = st.Applied.Digest
		}
		if state := st.CacheState; state != nil {
			if !state.FetchedAt.IsZero() {
				report.FetchedAt = timestamppb.New(state.FetchedAt)
			}
			// stored_at is the commit of the current file. When pmg applies
			// the previous file, it does not know when that file applied.
			if st.Applied != nil && !st.FromPrevious && !state.StoredAt.IsZero() {
				report.AppliedAt = timestamppb.New(state.StoredAt)
			}
		}
	} else {
		report.Exceptions = nil
	}

	return servicev1.ToolPolicyState_builder{
		ToolName:    ToolName,
		ToolVersion: audit.ToolVersion(),
		Policy:      report.Build(),
	}.Build()
}

// CheckInState loads the cache and applies it to a copy of the config, then
// returns the state for a check-in. Only Apply finds the fields that
// global_lockdown keeps, so a report from Load alone tells the cloud that
// pmg enforces a value that it does not enforce.
func CheckInState(cfg *config.RuntimeConfig, tenant string) *servicev1.ToolPolicyState {
	st := Load(cfg, tenant)
	target := cfg.Config
	Apply(cfg, &target, st)
	return ToolPolicyState(st)
}
