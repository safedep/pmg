package audit

import (
	"testing"
	"time"

	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
	servicev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/controltower/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
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
			wantParts: []string{"registry.example.com", "CONNECT", "0", "PMG_PROXY_ENTRY_POINT_UNSPECIFIED", "", ""},
			wantMatch: true,
		},
		{
			name: "host observation with a client",
			event: toolEventWithPmgEvent(&controltowerv1.PmgEvent{
				EventType: controltowerv1.PmgEventType_PMG_EVENT_TYPE_HOST_OBSERVATION,
				HostObservation: hostObservationOf("registry.example.com", 443, controltowerv1.PmgProxyEntryPoint_PMG_PROXY_ENTRY_POINT_REDIRECTED_HOST,
					&controltowerv1.PmgProxyClient{Pid: proto.Uint32(42), Comm: proto.String("curl"), Executable: proto.String("/usr/bin/curl")}),
			}),
			wantParts: []string{"registry.example.com", "CONNECT", "443", "PMG_PROXY_ENTRY_POINT_REDIRECTED_HOST", "/usr/bin/curl", ""},
			wantMatch: true,
		},
		{
			name: "host observation from a container",
			event: toolEventWithPmgEvent(&controltowerv1.PmgEvent{
				EventType: controltowerv1.PmgEventType_PMG_EVENT_TYPE_HOST_OBSERVATION,
				HostObservation: hostObservationOf("registry.example.com", 443, controltowerv1.PmgProxyEntryPoint_PMG_PROXY_ENTRY_POINT_REDIRECTED_NAMESPACE,
					&controltowerv1.PmgProxyClient{Address: proto.String("172.17.0.2")}),
			}),
			wantParts: []string{"registry.example.com", "CONNECT", "443", "PMG_PROXY_ENTRY_POINT_REDIRECTED_NAMESPACE", "", "172.17.0.2"},
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

func hostObservationOf(hostname string, port uint32, entry controltowerv1.PmgProxyEntryPoint, client *controltowerv1.PmgProxyClient) *controltowerv1.PmgHostObservation {
	obs := &controltowerv1.PmgHostObservation{}
	obs.SetHostname(hostname)
	obs.SetMethod("CONNECT")
	obs.SetPort(port)
	obs.SetEntryPoint(entry)
	obs.SetClient(client)
	return obs
}

func TestHostObservationDedupKeySeparatesClients(t *testing.T) {
	same := func(a, b *controltowerv1.PmgProxyClient) bool {
		return assert.ObjectsAreEqual(
			hostObservationDedupKey(hostObservationOf("h", 443, controltowerv1.PmgProxyEntryPoint_PMG_PROXY_ENTRY_POINT_REDIRECTED_HOST, a)),
			hostObservationDedupKey(hostObservationOf("h", 443, controltowerv1.PmgProxyEntryPoint_PMG_PROXY_ENTRY_POINT_REDIRECTED_HOST, b)))
	}
	curl := &controltowerv1.PmgProxyClient{Pid: proto.Uint32(1), Comm: proto.String("curl"), Executable: proto.String("/usr/bin/curl")}
	curlAgain := &controltowerv1.PmgProxyClient{Pid: proto.Uint32(2), Comm: proto.String("renamed"), Executable: proto.String("/usr/bin/curl")}
	node := &controltowerv1.PmgProxyClient{Pid: proto.Uint32(3), Comm: proto.String("node"), Executable: proto.String("/usr/bin/node")}

	assert.True(t, same(curl, curlAgain), "a new run of the same program, under any comm, is the same client")
	assert.False(t, same(curl, node), "another program is another client")
	assert.False(t, same(curl, &controltowerv1.PmgProxyClient{}), "a program and an unknown client differ")
}

func toolEventWithPmgEvent(event *controltowerv1.PmgEvent) *servicev1.ToolEvent {
	toolEvent := &servicev1.ToolEvent{}
	toolEvent.SetPmgEvent(event)
	return toolEvent
}

func TestCloudSyncOptionsAreValid(t *testing.T) {
	client, err := newTestEventEmitter(t.TempDir() + "/cloud-sync.db")
	require.NoError(t, err)
	require.NoError(t, client.Close())
}
