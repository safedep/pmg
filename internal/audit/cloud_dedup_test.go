package audit

import (
	"testing"
	"time"

	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
	servicev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/controltower/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHostObservationDedupRule(t *testing.T) {
	rule := hostObservationDedupRule()

	assert.Equal(t, "pmg-host-observation", rule.Name)
	assert.Equal(t, 15*time.Minute, rule.Window)

	tests := []struct {
		name      string
		event     *servicev1.ToolEvent
		wantParts []string
		wantMatch bool
	}{
		{
			name: "host observation",
			event: toolEventWithPmgEvent(&controltowerv1.PmgEvent{
				EventType: controltowerv1.PmgEventType_PMG_EVENT_TYPE_HOST_OBSERVATION,
				HostObservation: &controltowerv1.PmgHostObservation{
					Hostname: "registry.example.com",
					Method:   "CONNECT",
				},
			}),
			wantParts: []string{"registry.example.com", "CONNECT"},
			wantMatch: true,
		},
		{
			name: "package decision",
			event: toolEventWithPmgEvent(&controltowerv1.PmgEvent{
				EventType:       controltowerv1.PmgEventType_PMG_EVENT_TYPE_PACKAGE_DECISION,
				PackageDecision: &controltowerv1.PmgPackageDecision{},
			}),
		},
		{
			name:  "missing PMG event",
			event: &servicev1.ToolEvent{},
		},
		{
			name: "missing host observation payload",
			event: toolEventWithPmgEvent(&controltowerv1.PmgEvent{
				EventType: controltowerv1.PmgEventType_PMG_EVENT_TYPE_HOST_OBSERVATION,
			}),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parts, matched := rule.Key(tc.event)
			assert.Equal(t, tc.wantMatch, matched)
			assert.Equal(t, tc.wantParts, parts)
		})
	}
}

func toolEventWithPmgEvent(event *controltowerv1.PmgEvent) *servicev1.ToolEvent {
	toolEvent := &servicev1.ToolEvent{}
	toolEvent.SetPmgEvent(event)
	return toolEvent
}

func TestCloudSyncOptionsAreValid(t *testing.T) {
	client, err := newTestEventEmitter(t.TempDir()+"/cloud-sync.db", cloudSyncOptions)
	require.NoError(t, err)
	require.NoError(t, client.Close())
}
