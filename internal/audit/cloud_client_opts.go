package audit

import (
	"strconv"
	"time"

	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
	servicev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/controltower/v1"
	"github.com/safedep/dry/cloud/endpointsync"
)

// A retry loop or a script can hit one denied destination thousands of
// times in one run. The local event log keeps every decision. The cloud
// sink delivers the first of a window and the count, as for host
// observations.
const (
	hostObservationDedupWindow = 15 * time.Minute
	networkPolicyDedupWindow   = 15 * time.Minute
)

func hostObservationDedupRule() endpointsync.DedupRule {
	return endpointsync.DedupRule{
		Name:   "pmg-host-observation",
		Window: hostObservationDedupWindow,
		Key: func(event *servicev1.ToolEvent) ([]string, bool) {
			pmgEvent := event.GetPmgEvent()
			if pmgEvent == nil || pmgEvent.GetEventType() != controltowerv1.PmgEventType_PMG_EVENT_TYPE_HOST_OBSERVATION {
				return nil, false
			}

			observation := pmgEvent.GetHostObservation()
			if observation == nil {
				return nil, false
			}

			return hostObservationDedupKey(observation), true
		},
	}
}

func networkPolicyDedupRule() endpointsync.DedupRule {
	return endpointsync.DedupRule{
		Name:   "pmg-network-policy-decision",
		Window: networkPolicyDedupWindow,
		Key: func(event *servicev1.ToolEvent) ([]string, bool) {
			pmgEvent := event.GetPmgEvent()
			if pmgEvent == nil || pmgEvent.GetEventType() != controltowerv1.PmgEventType_PMG_EVENT_TYPE_NETWORK_POLICY_DECISION {
				return nil, false
			}

			decision := pmgEvent.GetNetworkPolicyDecision()
			if decision == nil {
				return nil, false
			}

			return networkPolicyDedupKey(decision), true
		},
	}
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
		endpointsync.WithDedupRules(hostObservationDedupRule(), networkPolicyDedupRule()),
	}
}
