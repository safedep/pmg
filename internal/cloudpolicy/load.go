package cloudpolicy

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"time"

	recordv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/policy/record/v1"
	specv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/policy/spec/v1"
	"github.com/safedep/dry/cloud/configsync"
	"github.com/safedep/dry/log"
	"github.com/safedep/dry/policy/match"
	"github.com/safedep/dry/policy/project"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/audit"
	"github.com/safedep/pmg/internal/cloudauth"
	"github.com/safedep/pmg/internal/platform"
)

// StaleAfter is the age of the last successful fetch after which pmg reports
// the cache as stale. It still applies a stale cache. From M2, cloud.yml sets
// it.
const StaleAfter = 7 * 24 * time.Hour

// Status is what pmg knows about its cloud policy after a load.
type Status struct {
	// PolicyOn is cloud.policy, and CloudOn is cloud.enabled.
	PolicyOn bool
	CloudOn  bool

	State recordv1.ApplyState

	// Tenant is the tenant of the login, or "" with no login.
	Tenant string

	// CacheDir is the cache folder that pmg read the policy from, or the
	// folder of pmg when no cache applies.
	CacheDir string

	// CacheState is the state.json of CacheDir, or nil when pmg cannot read
	// it.
	CacheState *configsync.State

	// Applied names the policy that pmg applies, or nil.
	Applied *AppliedHeader

	// FromPrevious is true when the current policy file failed a check and
	// pmg applies the previous file. CurrentErr tells why.
	FromPrevious bool
	CurrentErr   error

	// LoadErr tells why no cache applies.
	LoadErr error

	// Projection is the decoded policy that pmg applies.
	Projection *project.Projection

	// Dropped are the rules that the index dropped.
	Dropped []match.Dropped

	// Keys are the pmg keys that the cloud layer set.
	Keys []config.CloudKey

	// Locked are the contract paths that global_lockdown kept from the cloud.
	Locked []string

	// BlockEntries and TrustEntries count the cloud rules in the index.
	BlockEntries int
	TrustEntries int

	index            *match.Index
	cooldownCitation *recordv1.DecisionCitation
}

// Exceptions returns the fields that pmg does not apply as the policy says:
// the exceptions of the projection, each dropped rule, and each path that
// global_lockdown kept.
func (s *Status) Exceptions() []*recordv1.FieldException {
	if s == nil {
		return nil
	}

	var out []*recordv1.FieldException
	if s.Projection != nil {
		for _, e := range s.Projection.Exceptions {
			out = append(out, e.FieldException())
		}
	}
	for _, d := range s.Dropped {
		if d.Rule.Origin.Kind != match.OriginCloud {
			continue
		}
		out = append(out, recordv1.FieldException_builder{
			Path:   PathPackageRules,
			Reason: recordv1.FieldExceptionReason_FIELD_EXCEPTION_REASON_DROPPED_RULE,
			Detail: fmt.Sprintf("rule %s: %v", d.Rule.ID, d.Err),
		}.Build())
	}
	for _, path := range s.Locked {
		out = append(out, recordv1.FieldException_builder{
			Path:   path,
			Reason: recordv1.FieldExceptionReason_FIELD_EXCEPTION_REASON_LOCKED,
			Detail: "global_lockdown keeps the value of the managed config file",
		}.Build())
	}
	return out
}

// RejectedReason tells why pmg did not apply the last policy that it
// fetched, when the state is REJECTED.
func (s *Status) RejectedReason() string {
	if s == nil || s.State != recordv1.ApplyState_APPLY_STATE_REJECTED {
		return ""
	}
	if s.CacheState.LastFetchRejected() {
		return s.CacheState.Rejected.Reason
	}
	if s.CurrentErr != nil {
		return s.CurrentErr.Error()
	}
	if s.LoadErr != nil {
		return s.LoadErr.Error()
	}
	return ""
}

// CacheAge is the time since the last successful fetch. It is zero when no
// fetch succeeded.
func (s *Status) CacheAge(now time.Time) time.Duration {
	if s == nil || s.CacheState == nil || s.CacheState.FetchedAt.IsZero() {
		return 0
	}
	return now.Sub(s.CacheState.FetchedAt)
}

// Load reads the policy cache of cfg and builds the package rule index. It
// does not change cfg. tenant is the tenant of the login, or "" with no
// login: then pmg skips only the tenant check, because only a fetch with a
// login writes the cache.
//
// Load never fails. A cache that pmg cannot use leaves the tool baseline,
// and the Status tells why. The rules of blocked_packages apply in every
// state.
func Load(cfg *config.RuntimeConfig, tenant string) *Status {
	st := &Status{
		PolicyOn: cfg.Config.Cloud.Policy,
		CloudOn:  cfg.Config.Cloud.Enabled,
		State:    recordv1.ApplyState_APPLY_STATE_DISABLED,
		Tenant:   tenant,
		CacheDir: cfg.CloudPolicyCacheDir(),
	}

	local := cfg.BlockedRules()

	if cfg.CloudPolicyEnabled() && cfg.ConfigDir() != "" {
		loadCache(cfg, st)
	}

	var cloud []match.Rule
	if st.Projection != nil {
		cloud = st.Projection.Rules
	}
	st.index, st.Dropped = newIndex(cloud, local)
	for _, d := range st.Dropped {
		log.Warnf("cloud policy: dropped rule %s (%s): %v", d.Rule.ID, d.Rule.PURL, d.Err)
	}
	for _, rule := range st.index.Rules() {
		if rule.Origin.Kind != match.OriginCloud {
			continue
		}
		switch rule.Effect {
		case match.EffectBlock:
			st.BlockEntries++
		case match.EffectTrust:
			st.TrustEntries++
		}
	}
	return st
}

// loadCache loads the first usable cache folder into st.
func loadCache(cfg *config.RuntimeConfig, st *Status) {
	st.State = recordv1.ApplyState_APPLY_STATE_NONE

	machineID, err := machineID(cfg)
	if err != nil {
		st.LoadErr = err
		log.Warnf("cloud policy: %v", err)
		return
	}
	expect := project.Expect{
		Tenant:      st.Tenant,
		SubjectKind: specv1.SubjectKind_SUBJECT_KIND_ENDPOINT,
		MachineID:   machineID,
	}

	var storeOpts []configsync.StoreOption
	if st.Tenant != "" {
		storeOpts = append(storeOpts, configsync.WithTenant(st.Tenant))
	}

	for i, dir := range cacheDirs(cfg) {
		store, err := configsync.NewStore(dir, storeOpts...)
		if err != nil {
			st.LoadErr = err
			continue
		}

		var last *project.Projection
		loaded, err := store.Load(func(raw []byte) (configsync.Accepted, error) {
			proj, err := project.Decode(raw, expect)
			if err != nil {
				return configsync.Accepted{}, err
			}
			last = proj
			return configsync.Accepted{}, nil
		})

		state, stateErr := store.State()
		if err != nil {
			// The first folder sets the status, so a sudo run that finds no
			// cache in either folder reports the folder of the invoking user.
			if i == 0 || st.CacheState == nil {
				st.CacheDir = dir
				st.LoadErr = err
				if stateErr == nil {
					st.CacheState = state
				}
			}
			continue
		}

		st.CacheDir = dir
		st.CacheState = loaded.State
		st.LoadErr = nil
		st.FromPrevious = loaded.FromPrevious
		st.CurrentErr = loaded.CurrentErr
		restoreCapabilities(store, loaded, last, expect)
		st.Projection = last
		st.Applied = &AppliedHeader{
			Tenant:                last.Header.Tenant,
			Digest:                loaded.Digest,
			Revision:              last.Header.Revision,
			DefaultPolicyRevision: last.Header.DefaultPolicyRevision,
		}
		break
	}

	st.State = applyState(st, time.Now())
	if st.LoadErr != nil && !errors.Is(st.LoadErr, configsync.ErrNoCache) {
		log.Warnf("cloud policy: cannot read the policy cache: %v", st.LoadErr)
	} else if st.LoadErr != nil {
		log.Debugf("cloud policy: no usable policy cache: %v", st.LoadErr)
	}
	if st.CurrentErr != nil {
		log.Warnf("cloud policy: the current policy file failed (%v). pmg applies revision %d", st.CurrentErr, st.Applied.Revision)
	}
}

// restoreCapabilities takes each capability that failed in the loaded policy
// from the policy file that capability_sources names for it. When Load fell
// back to the previous file, capability_sources describes the current file,
// so it does not apply.
func restoreCapabilities(store *configsync.Store, loaded *configsync.Loaded, proj *project.Projection, expect project.Expect) {
	if loaded.FromPrevious || len(proj.FailedCapabilities) == 0 {
		return
	}
	for _, capability := range proj.FailedCapabilities {
		digest, ok := loaded.State.CapabilitySources[capability]
		if !ok {
			continue
		}
		raw, err := store.ReadPolicy(digest)
		if err != nil {
			log.Warnf("cloud policy: cannot read the source of %s: %v", capability, err)
			continue
		}
		prev, err := project.Decode(raw, expect)
		if err != nil {
			log.Warnf("cloud policy: the source of %s does not decode: %v", capability, err)
			continue
		}
		proj.Restore(prev)
	}
}

// applyState is the ApplyState of a status after a load with cloud.policy
// on.
func applyState(st *Status, now time.Time) recordv1.ApplyState {
	switch {
	case st.Projection == nil && st.CacheState.HasPolicy() && !errors.Is(st.LoadErr, configsync.ErrTenantMismatch):
		return recordv1.ApplyState_APPLY_STATE_REJECTED
	case st.Projection == nil:
		return recordv1.ApplyState_APPLY_STATE_NONE
	case st.FromPrevious, st.CacheState.LastFetchRejected():
		return recordv1.ApplyState_APPLY_STATE_REJECTED
	case st.CacheAge(now) > StaleAfter, st.CacheState.FetchedAt.IsZero():
		return recordv1.ApplyState_APPLY_STATE_STALE
	default:
		return recordv1.ApplyState_APPLY_STATE_APPLIED
	}
}

// machineID returns the machine id of the endpoint, from the identity that
// the check-in sends. The header of the policy must carry it.
func machineID(cfg *config.RuntimeConfig) (string, error) {
	endpoint, err := audit.NewEndpointIdentityResolver(cfg).Resolve()
	if err != nil {
		return "", fmt.Errorf("cannot resolve the endpoint identity: %w", err)
	}
	return endpoint.GetMachineId(), nil
}

// cacheDirs returns the cache folders that pmg reads, in order. Under sudo,
// pmg reads the cache of the invoking user first, read-only, because root
// usually has no cloud login and its own cache stays empty. Then it reads
// its own cache.
func cacheDirs(cfg *config.RuntimeConfig) []string {
	own := cfg.CloudPolicyCacheDir()
	if !platform.IsSudo() {
		return []string{own}
	}

	invoking, err := user.Lookup(os.Getenv("SUDO_USER"))
	if err != nil || invoking.HomeDir == "" {
		log.Debugf("cloud policy: cannot find the home of the sudo user: %v", err)
		return []string{own}
	}
	dir := filepath.Join(platform.HomeDirs(invoking.HomeDir).Config, "safedep", "pmg", "cloud-policy")
	if dir == own {
		return []string{own}
	}
	return []string{dir, own}
}

// loginTenant returns the tenant of the cloud login, or "" with no login.
func loginTenant() string {
	creds, closeResolver, err := cloudauth.ResolveCredentials()
	if err != nil {
		log.Debugf("cloud policy: no cloud login: %v", err)
		return ""
	}
	defer func() {
		if err := closeResolver(); err != nil {
			log.Warnf("cloud policy: failed to close the credential resolver: %v", err)
		}
	}()

	tenant, err := creds.GetTenantDomain()
	if err != nil {
		log.Debugf("cloud policy: the login has no tenant: %v", err)
		return ""
	}
	return tenant
}
