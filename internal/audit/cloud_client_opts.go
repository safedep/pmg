package audit

import (
	"slices"
	"strconv"
	"strings"
	"time"

	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
	servicev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/controltower/v1"
	"github.com/safedep/dry/cloud/endpointsync"
)

// A retry loop or a script can hit one denied destination thousands of
// times in one run. The local event log keeps every decision. The cloud
// sink delivers the first of a window and the count, as for host
// observations.
//
// A sandboxed run sends the overrides of the saved project overlay every
// time, and a routine denial gives the same violation report on every run.
// Their rules collapse the repeats of separate runs.
const (
	hostObservationDedupWindow  = 15 * time.Minute
	networkPolicyDedupWindow    = 15 * time.Minute
	sandboxOverrideDedupWindow  = 15 * time.Minute
	sandboxViolationDedupWindow = 15 * time.Minute
)

// pmgDedupRule builds the dedup rule of one PMG event type. key reports
// false when the payload is missing.
func pmgDedupRule(
	name string,
	window time.Duration,
	eventType controltowerv1.PmgEventType,
	key func(*controltowerv1.PmgEvent) ([]string, bool),
) endpointsync.DedupRule {
	return endpointsync.DedupRule{
		Name:   name,
		Window: window,
		Key: func(event *servicev1.ToolEvent) ([]string, bool) {
			pmgEvent := event.GetPmgEvent()
			if pmgEvent == nil || pmgEvent.GetEventType() != eventType {
				return nil, false
			}
			return key(pmgEvent)
		},
	}
}

func hostObservationDedupRule() endpointsync.DedupRule {
	return pmgDedupRule("pmg-host-observation", hostObservationDedupWindow,
		controltowerv1.PmgEventType_PMG_EVENT_TYPE_HOST_OBSERVATION,
		func(event *controltowerv1.PmgEvent) ([]string, bool) {
			observation := event.GetHostObservation()
			if observation == nil {
				return nil, false
			}
			return hostObservationDedupKey(observation), true
		})
}

func networkPolicyDedupRule() endpointsync.DedupRule {
	return pmgDedupRule("pmg-network-policy-decision", networkPolicyDedupWindow,
		controltowerv1.PmgEventType_PMG_EVENT_TYPE_NETWORK_POLICY_DECISION,
		func(event *controltowerv1.PmgEvent) ([]string, bool) {
			decision := event.GetNetworkPolicyDecision()
			if decision == nil {
				return nil, false
			}
			return networkPolicyDedupKey(decision), true
		})
}

func sandboxOverrideDedupRule() endpointsync.DedupRule {
	return pmgDedupRule("pmg-sandbox-override", sandboxOverrideDedupWindow,
		controltowerv1.PmgEventType_PMG_EVENT_TYPE_SANDBOX_OVERRIDE,
		func(event *controltowerv1.PmgEvent) ([]string, bool) {
			override := event.GetSandboxOverride()
			if override == nil {
				return nil, false
			}
			return sandboxOverrideDedupKey(override), true
		})
}

func sandboxViolationDedupRule() endpointsync.DedupRule {
	return pmgDedupRule("pmg-sandbox-violation", sandboxViolationDedupWindow,
		controltowerv1.PmgEventType_PMG_EVENT_TYPE_SANDBOX_VIOLATION,
		func(event *controltowerv1.PmgEvent) ([]string, bool) {
			report := event.GetSandboxViolationReport()
			if report == nil {
				return nil, false
			}
			return sandboxViolationDedupKey(report), true
		})
}

// sandboxOverrideDedupKey sorts the overrides, because the translation lists
// them in map order, which changes from run to run.
func sandboxOverrideDedupKey(override *controltowerv1.PmgSandboxOverride) []string {
	return append([]string{override.GetSandboxProfile()}, slices.Sorted(slices.Values(override.GetOverrides()))...)
}

// sandboxViolationDedupKey keys a report by its setup and its set of
// denials. The hit count of a denial changes from run to run, and the order
// depends on the working directory, so neither is in the key. The rule
// follows from the profile and the target.
func sandboxViolationDedupKey(report *controltowerv1.PmgSandboxViolationReport) []string {
	denials := make([]string, 0, len(report.GetViolations()))
	for _, v := range report.GetViolations() {
		denials = append(denials, strings.Join([]string{
			v.GetKind().String(),
			v.GetPath(),
			v.GetExecutable(),
			v.GetHost(),
			strconv.FormatUint(uint64(v.GetPort()), 10),
			v.GetProcess(),
		}, "\x00"))
	}
	slices.Sort(denials)

	return append([]string{
		report.GetDriver().String(),
		report.GetSandboxProfile(),
		report.GetExitStatus().String(),
		strconv.FormatUint(uint64(report.GetDistinctCount()), 10),
	}, denials...)
}

// networkPolicyDedupKey keeps a denial and an observation of one
// destination apart, and one client from another, as hostObservationDedupKey
// does.
func networkPolicyDedupKey(decision *controltowerv1.PmgNetworkPolicyDecision) []string {
	client := decision.GetClient()
	return []string{
		decision.GetHostname(),
		strconv.FormatUint(uint64(decision.GetPort()), 10),
		decision.GetRule(),
		decision.GetAction().String(),
		decision.GetMode().String(),
		decision.GetEntryPoint().String(),
		programOf(client),
		client.GetAddress(),
	}
}

// hostObservationDedupKey separates the clients of one host, so the surviving
// event names the right one. The pid changes with every run of the same
// program, so it is not part of the key.
func hostObservationDedupKey(observation *controltowerv1.PmgHostObservation) []string {
	client := observation.GetClient()
	return []string{
		observation.GetHostname(),
		observation.GetMethod(),
		strconv.FormatUint(uint64(observation.GetPort()), 10),
		observation.GetEntryPoint().String(),
		programOf(client),
		client.GetAddress(),
	}
}

// programOf names the program behind a client. The executable is the
// kernel's verified name. Without one, the comm is the process's own
// choice, and still keeps two programs apart.
func programOf(client *controltowerv1.PmgProxyClient) string {
	if exe := client.GetExecutable(); exe != "" {
		return exe
	}
	if comm := client.GetComm(); comm != "" {
		return "comm:" + comm
	}
	return ""
}

func cloudSyncOptions(walPath string) []endpointsync.SyncOption {
	return []endpointsync.SyncOption{
		endpointsync.WithWALPath(walPath),
		endpointsync.WithDedupRules(
			hostObservationDedupRule(),
			networkPolicyDedupRule(),
			sandboxOverrideDedupRule(),
			sandboxViolationDedupRule(),
		),
	}
}
