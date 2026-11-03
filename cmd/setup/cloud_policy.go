package setup

import (
	"fmt"
	"sort"
	"strings"
	"time"

	recordv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/policy/record/v1"
	"github.com/safedep/dry/policy/match"
	"github.com/safedep/dry/policy/project"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/cloudpolicy"
	"github.com/safedep/pmg/internal/doctor"
)

const (
	checkCloudPolicy = "cloud-policy"
	categoryCloud    = "Cloud"
)

// cloudPolicyStatus returns the status of the cloud policy that the root
// command loaded, or loads it again when no command did.
func cloudPolicyStatus(cfg *config.RuntimeConfig) *cloudpolicy.Status {
	if st := cloudpolicy.Global().Status(); st != nil {
		return st
	}
	return cloudpolicy.Load(cfg, "")
}

// cloudPolicyResults returns the doctor results of the cloud policy. The
// check runs only when cloud.policy is on. It passes when the state is
// APPLIED with no exception. It warns for every other state, for each
// exception, and for a key that global_lockdown kept.
func cloudPolicyResults(st *cloudpolicy.Status, now time.Time) []doctor.CheckResult {
	if st == nil || !st.PolicyOn {
		return nil
	}

	warn := func(message, fix string) doctor.CheckResult {
		return doctor.CheckResult{Status: doctor.StatusWarn, Message: message, Fix: fix}
	}

	if !st.CloudOn {
		return []doctor.CheckResult{warn(
			"cloud.policy is on, but cloud.enabled is false. pmg does not fetch the policy",
			"Set cloud.enabled: true in config")}
	}

	var results []doctor.CheckResult
	switch {
	case st.State == recordv1.ApplyState_APPLY_STATE_NONE:
		results = append(results, warn(
			"cloud policy is on, but no policy cache exists. pmg fetches it after the next command",
			"Run: pmg cloud sync"))
	case st.Applied == nil:
		results = append(results, warn(
			"the policy cache cannot be used. pmg applies the tool baseline",
			"Run: pmg cloud sync"))
	default:
		status := doctor.StatusPass
		if st.State != recordv1.ApplyState_APPLY_STATE_APPLIED || len(st.Exceptions()) > 0 {
			status = doctor.StatusWarn
		}
		results = append(results, doctor.CheckResult{Status: status, Message: cloudPolicySummary(st, now)})
	}

	if st.State == recordv1.ApplyState_APPLY_STATE_STALE && st.Applied != nil {
		age := "of unknown age"
		if st.CacheAge(now) > 0 {
			age = formatAge(st.CacheAge(now)) + " old"
		}
		results = append(results, warn(
			fmt.Sprintf("the policy cache is %s. The last policy still applies", age),
			"Run: pmg cloud sync"))
	}

	if st.State == recordv1.ApplyState_APPLY_STATE_REJECTED {
		results = append(results, warn(rejectedMessage(st), "Ask your security admin to check the policy"))
	}

	for _, line := range exceptionLines(st) {
		results = append(results, warn(line, ""))
	}
	return results
}

// cloudPolicySummary is the main line of the check, as in "on · tenant
// acme.safedep.io · revision 52 applied · cache 12m old".
func cloudPolicySummary(st *cloudpolicy.Status, now time.Time) string {
	parts := []string{"on"}
	tenant := st.Tenant
	if tenant == "" {
		tenant = st.Applied.Tenant
	}
	if tenant != "" {
		parts = append(parts, "tenant "+tenant)
	}
	parts = append(parts, fmt.Sprintf("revision %d applied", st.Applied.Revision))
	if age := st.CacheAge(now); age > 0 {
		parts = append(parts, "cache "+formatAge(age)+" old")
	}
	return strings.Join(parts, " · ")
}

func rejectedMessage(st *cloudpolicy.Status) string {
	applies := "the tool baseline"
	if st.Applied != nil {
		applies = fmt.Sprintf("revision %d", st.Applied.Revision)
	}

	state := st.CacheState
	if state.LastFetchRejected() {
		return fmt.Sprintf("revision %d was rejected: %s. pmg applies %s",
			state.Rejected.Revision, state.Rejected.Reason, applies)
	}
	if state != nil && st.FromPrevious {
		return fmt.Sprintf("revision %d failed its check: %s. pmg applies %s", state.Revision, st.RejectedReason(), applies)
	}
	return fmt.Sprintf("the policy cache failed its check: %s. pmg applies %s", st.RejectedReason(), applies)
}

// exceptionLines groups the exceptions of the policy for people: the
// dropped rules by their reason, each unknown field, and each path that
// global_lockdown kept.
func exceptionLines(st *cloudpolicy.Status) []string {
	type group struct {
		noun string
		ids  []string
	}
	groups := map[string]*group{}
	var keys []string
	addDropped := func(effect match.Effect, id, reason string) {
		noun := "package rules"
		switch effect {
		case match.EffectTrust:
			noun = "trust entries"
		case match.EffectBlock:
			noun = "block entries"
		}
		key := noun + "|" + reason
		if groups[key] == nil {
			groups[key] = &group{noun: noun}
			keys = append(keys, key)
		}
		groups[key].ids = append(groups[key].ids, id)
	}

	var lines []string
	if st.Projection != nil {
		for _, e := range st.Projection.Exceptions {
			switch e.Kind {
			case project.ExceptionDroppedRule:
				addDropped(droppedEffect(e.Detail), e.RuleID, e.Detail)
			case project.ExceptionUnknownField:
				if e.RuleID == "" {
					lines = append(lines, fmt.Sprintf("unknown field %s. pmg applies the rest of the policy", e.Path))
				}
			default:
				lines = append(lines, fmt.Sprintf("%s: %s", e.Path, e.Detail))
			}
		}
	}
	for _, d := range st.Dropped {
		if d.Rule.Origin.Kind == match.OriginCloud {
			addDropped(d.Rule.Effect, d.Rule.ID, d.Err.Error())
		}
	}

	sort.Strings(keys)
	for _, key := range keys {
		g := groups[key]
		reason := strings.TrimPrefix(key, g.noun+"|")
		lines = append(lines, fmt.Sprintf("%d %s dropped (%s): %s", len(g.ids), g.noun, reason, strings.Join(g.ids, ", ")))
	}
	for _, path := range st.Locked {
		lines = append(lines, fmt.Sprintf("global_lockdown keeps the managed config value of %s", path))
	}
	return lines
}

// droppedEffect returns the effect of a rule that the projection dropped. The
// projection never drops a block entry, so a dropped rule is a trust entry,
// or a rule with an effect that pmg does not know.
func droppedEffect(detail string) match.Effect {
	if strings.HasPrefix(detail, match.ErrUnknownEffect.Error()) {
		return match.EffectNone
	}
	return match.EffectTrust
}

// formatAge renders an age in the largest whole unit: minutes, hours or
// days.
func formatAge(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// cloudPolicyInfo is the cloud policy in the status JSON.
type cloudPolicyInfo struct {
	Enabled               bool               `json:"enabled"`
	State                 string             `json:"state"`
	Tenant                string             `json:"tenant,omitempty"`
	Revision              uint64             `json:"revision,omitempty"`
	DefaultPolicyRevision uint64             `json:"default_policy_revision,omitempty"`
	Digest                string             `json:"digest,omitempty"`
	FetchedAt             string             `json:"fetched_at,omitempty"`
	StoredAt              string             `json:"stored_at,omitempty"`
	CacheDir              string             `json:"cache_dir,omitempty"`
	BlockEntries          int                `json:"block_entries"`
	TrustEntries          int                `json:"trust_entries"`
	Keys                  []cloudPolicyKey   `json:"keys,omitempty"`
	Locked                []string           `json:"locked,omitempty"`
	Exceptions            []cloudPolicyIssue `json:"exceptions,omitempty"`
	RejectedReason        string             `json:"rejected_reason,omitempty"`
}

type cloudPolicyKey struct {
	Key  string `json:"key"`
	Path string `json:"path"`
}

type cloudPolicyIssue struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

// collectCloudPolicyInfo describes the cloud policy for the status JSON.
func collectCloudPolicyInfo(st *cloudpolicy.Status) *cloudPolicyInfo {
	if st == nil {
		return nil
	}

	info := &cloudPolicyInfo{
		Enabled:        st.PolicyOn,
		State:          strings.ToLower(strings.TrimPrefix(st.State.String(), "APPLY_STATE_")),
		Tenant:         st.Tenant,
		BlockEntries:   st.BlockEntries,
		TrustEntries:   st.TrustEntries,
		Locked:         st.Locked,
		RejectedReason: st.RejectedReason(),
	}
	if st.State == recordv1.ApplyState_APPLY_STATE_DISABLED {
		return info
	}

	info.CacheDir = st.CacheDir
	if st.Applied != nil {
		if info.Tenant == "" {
			info.Tenant = st.Applied.Tenant
		}
		info.Revision = st.Applied.Revision
		info.DefaultPolicyRevision = st.Applied.DefaultPolicyRevision
		info.Digest = st.Applied.Digest
	}
	if state := st.CacheState; state != nil {
		if !state.FetchedAt.IsZero() {
			info.FetchedAt = state.FetchedAt.Format(time.RFC3339)
		}
		if !state.StoredAt.IsZero() {
			info.StoredAt = state.StoredAt.Format(time.RFC3339)
		}
	}
	for _, k := range st.Keys {
		info.Keys = append(info.Keys, cloudPolicyKey{Key: k.Key, Path: k.Path})
	}
	for _, e := range st.Exceptions() {
		info.Exceptions = append(info.Exceptions, cloudPolicyIssue{
			Path:   e.GetPath(),
			Reason: strings.ToLower(strings.TrimPrefix(e.GetReason().String(), "FIELD_EXCEPTION_REASON_")),
			Detail: e.GetDetail(),
		})
	}
	return info
}

// describeCloudPolicy is the cloud policy section of pmg setup info.
func describeCloudPolicy(st *cloudpolicy.Status, now time.Time) map[string]string {
	info := collectCloudPolicyInfo(st)
	entries := map[string]string{
		"Enabled": fmt.Sprintf("%t", info.Enabled),
		"State":   info.State,
	}
	if st.State == recordv1.ApplyState_APPLY_STATE_DISABLED {
		return entries
	}

	entries["Cache Folder"] = info.CacheDir
	if info.Tenant != "" {
		entries["Tenant"] = info.Tenant
	}
	if st.Applied != nil {
		entries["Revision"] = fmt.Sprintf("%d (default policy revision %d)", info.Revision, info.DefaultPolicyRevision)
		entries["Package Rules"] = fmt.Sprintf("%d block, %d trust", info.BlockEntries, info.TrustEntries)
	}
	if age := st.CacheAge(now); age > 0 {
		entries["Cache Age"] = formatAge(age)
	}
	for _, k := range info.Keys {
		entries["Set By Policy"] = strings.TrimPrefix(entries["Set By Policy"]+", "+k.Key, ", ")
	}
	if len(info.Exceptions) > 0 {
		entries["Exceptions"] = fmt.Sprintf("%d (run pmg setup doctor)", len(info.Exceptions))
	}
	return entries
}
