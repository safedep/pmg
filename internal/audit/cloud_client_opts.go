package audit

import (
	"time"

	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
	servicev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/controltower/v1"
	"github.com/safedep/dry/cloud/endpointsync"
)

const hostObservationDedupWindow = 15 * time.Minute

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

			return []string{observation.GetHostname(), observation.GetMethod()}, true
		},
	}
}

func cloudSyncOptions(walPath string) []endpointsync.SyncOption {
	return []endpointsync.SyncOption{
		endpointsync.WithWALPath(walPath),
		endpointsync.WithDedupRules(hostObservationDedupRule()),
	}
}
