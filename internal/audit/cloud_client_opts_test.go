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

	namedCurl := &controltowerv1.PmgProxyClient{Comm: proto.String("curl")}
	namedWget := &controltowerv1.PmgProxyClient{Comm: proto.String("wget")}

	assert.True(t, same(curl, curlAgain), "a new run of the same program, under any comm, is the same client")
	assert.False(t, same(curl, node), "another program is another client")
	assert.False(t, same(curl, &controltowerv1.PmgProxyClient{}), "a program and an unknown client differ")
	assert.False(t, same(namedCurl, namedWget), "without an executable the comm keeps two programs apart")
	assert.False(t, same(curl, namedCurl), "a verified name and a self-reported one differ")
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

func TestSandboxOverrideDedupRule(t *testing.T) {
	rule := sandboxOverrideDedupRule()

	assert.Equal(t, "pmg-sandbox-override", rule.Name)
	assert.Equal(t, 15*time.Minute, rule.Window)

	overrideEvent := func(profile string, overrides ...string) *servicev1.ToolEvent {
		override := &controltowerv1.PmgSandboxOverride{}
		override.SetSandboxProfile(profile)
		override.SetOverrides(overrides)
		return toolEventWithPmgEvent(&controltowerv1.PmgEvent{
			EventType:       controltowerv1.PmgEventType_PMG_EVENT_TYPE_SANDBOX_OVERRIDE,
			SandboxOverride: override,
		})
	}

	tests := []struct {
		name      string
		event     *servicev1.ToolEvent
		wantParts []string
		wantMatch bool
	}{
		{
			name:      "overrides are sorted",
			event:     overrideEvent("pnpm+overlay", "value:/tmp", "type:read"),
			wantParts: []string{"pnpm+overlay", "type:read", "value:/tmp"},
			wantMatch: true,
		},
		{
			name:      "another profile has another key",
			event:     overrideEvent("npm+overlay", "type:read", "value:/tmp"),
			wantParts: []string{"npm+overlay", "type:read", "value:/tmp"},
			wantMatch: true,
		},
		{
			name: "missing sandbox override payload",
			event: toolEventWithPmgEvent(&controltowerv1.PmgEvent{
				EventType: controltowerv1.PmgEventType_PMG_EVENT_TYPE_SANDBOX_OVERRIDE,
			}),
		},
		{
			name: "host observation is not covered",
			event: toolEventWithPmgEvent(&controltowerv1.PmgEvent{
				EventType:       controltowerv1.PmgEventType_PMG_EVENT_TYPE_HOST_OBSERVATION,
				HostObservation: &controltowerv1.PmgHostObservation{Hostname: "registry.example.com"},
			}),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parts, ok := rule.Key(tc.event)
			require.Equal(t, tc.wantMatch, ok)
			assert.Equal(t, tc.wantParts, parts)
		})
	}
}

func TestSandboxViolationDedupKey(t *testing.T) {
	sshRead := func(count uint32) *controltowerv1.PmgSandboxViolation {
		v := &controltowerv1.PmgSandboxViolation{}
		v.SetKind(controltowerv1.PmgSandboxViolationKind_PMG_SANDBOX_VIOLATION_KIND_FILESYSTEM_READ)
		v.SetPath("/Users/dev/.ssh/id_rsa")
		v.SetRule("/Users/dev/.ssh")
		v.SetProcess("node")
		v.SetCount(count)
		return v
	}
	connect := func(process string) *controltowerv1.PmgSandboxViolation {
		v := &controltowerv1.PmgSandboxViolation{}
		v.SetKind(controltowerv1.PmgSandboxViolationKind_PMG_SANDBOX_VIOLATION_KIND_NETWORK_CONNECT)
		v.SetHost("1.2.3.4")
		v.SetPort(443)
		v.SetProcess(process)
		v.SetCount(1)
		return v
	}
	report := func(exit controltowerv1.PmgSandboxExitStatus, violations ...*controltowerv1.PmgSandboxViolation) *controltowerv1.PmgSandboxViolationReport {
		r := &controltowerv1.PmgSandboxViolationReport{}
		r.SetDriver(controltowerv1.PmgSandboxDriver_PMG_SANDBOX_DRIVER_SEATBELT)
		r.SetSandboxProfile("npm-restrictive")
		r.SetExitStatus(exit)
		r.SetViolations(violations)
		r.SetDistinctCount(uint32(len(violations)))
		return r
	}
	success := controltowerv1.PmgSandboxExitStatus_PMG_SANDBOX_EXIT_STATUS_SUCCESS
	failed := controltowerv1.PmgSandboxExitStatus_PMG_SANDBOX_EXIT_STATUS_FAILED

	base := sandboxViolationDedupKey(report(success, sshRead(3), connect("curl")))

	assert.Equal(t, base, sandboxViolationDedupKey(report(success, connect("curl"), sshRead(9))),
		"another hit count or order is the same report")
	assert.NotEqual(t, base, sandboxViolationDedupKey(report(failed, sshRead(3), connect("curl"))),
		"another exit status is another report")
	assert.NotEqual(t, base, sandboxViolationDedupKey(report(success, sshRead(3), connect("wget"))),
		"another program is another report")
	assert.NotEqual(t, base, sandboxViolationDedupKey(report(success, sshRead(3))),
		"another set of denials is another report")
}

func TestSandboxViolationDedupRule(t *testing.T) {
	rule := sandboxViolationDedupRule()

	assert.Equal(t, "pmg-sandbox-violation", rule.Name)
	assert.Equal(t, 15*time.Minute, rule.Window)

	_, ok := rule.Key(toolEventWithPmgEvent(&controltowerv1.PmgEvent{
		EventType: controltowerv1.PmgEventType_PMG_EVENT_TYPE_SANDBOX_VIOLATION,
	}))
	assert.False(t, ok, "a missing report payload is not covered")

	_, ok = rule.Key(toolEventWithPmgEvent(&controltowerv1.PmgEvent{
		EventType:       controltowerv1.PmgEventType_PMG_EVENT_TYPE_SANDBOX_OVERRIDE,
		SandboxOverride: &controltowerv1.PmgSandboxOverride{},
	}))
	assert.False(t, ok, "a sandbox override is not covered")
}

func TestNetworkPolicyDedupRule(t *testing.T) {
	rule := networkPolicyDedupRule()

	assert.Equal(t, "pmg-network-policy-decision", rule.Name)
	assert.Equal(t, 15*time.Minute, rule.Window)

	denied := &controltowerv1.PmgNetworkPolicyDecision{}
	denied.SetHostname("evil.example")
	denied.SetPort(443)
	denied.SetRule("*:*")
	denied.SetAction(controltowerv1.PmgNetworkPolicyAction_PMG_NETWORK_POLICY_ACTION_DENIED)
	denied.SetMode(controltowerv1.PmgNetworkPolicyMode_PMG_NETWORK_POLICY_MODE_ENFORCE)
	denied.SetEntryPoint(controltowerv1.PmgProxyEntryPoint_PMG_PROXY_ENTRY_POINT_REDIRECTED_HOST)
	denied.SetClient(&controltowerv1.PmgProxyClient{Pid: proto.Uint32(42), Comm: proto.String("curl"), Executable: proto.String("/usr/bin/curl")})
	observed := proto.Clone(denied).(*controltowerv1.PmgNetworkPolicyDecision)
	observed.SetAction(controltowerv1.PmgNetworkPolicyAction_PMG_NETWORK_POLICY_ACTION_OBSERVED)
	observed.SetMode(controltowerv1.PmgNetworkPolicyMode_PMG_NETWORK_POLICY_MODE_AUDIT)

	tests := []struct {
		name      string
		event     *servicev1.ToolEvent
		wantParts []string
		wantMatch bool
	}{
		{
			name: "denied decision",
			event: toolEventWithPmgEvent(&controltowerv1.PmgEvent{
				EventType:             controltowerv1.PmgEventType_PMG_EVENT_TYPE_NETWORK_POLICY_DECISION,
				NetworkPolicyDecision: denied,
			}),
			wantParts: []string{"evil.example", "443", "*:*", "PMG_NETWORK_POLICY_ACTION_DENIED", "PMG_NETWORK_POLICY_MODE_ENFORCE", "PMG_PROXY_ENTRY_POINT_REDIRECTED_HOST", "/usr/bin/curl", ""},
			wantMatch: true,
		},
		{
			name: "observed decision of the same destination has another key",
			event: toolEventWithPmgEvent(&controltowerv1.PmgEvent{
				EventType:             controltowerv1.PmgEventType_PMG_EVENT_TYPE_NETWORK_POLICY_DECISION,
				NetworkPolicyDecision: observed,
			}),
			wantParts: []string{"evil.example", "443", "*:*", "PMG_NETWORK_POLICY_ACTION_OBSERVED", "PMG_NETWORK_POLICY_MODE_AUDIT", "PMG_PROXY_ENTRY_POINT_REDIRECTED_HOST", "/usr/bin/curl", ""},
			wantMatch: true,
		},
		{
			name: "host observation is not covered",
			event: toolEventWithPmgEvent(&controltowerv1.PmgEvent{
				EventType:       controltowerv1.PmgEventType_PMG_EVENT_TYPE_HOST_OBSERVATION,
				HostObservation: &controltowerv1.PmgHostObservation{Hostname: "registry.example.com"},
			}),
			wantMatch: false,
		},
		{
			name:      "no pmg event",
			event:     &servicev1.ToolEvent{},
			wantMatch: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parts, ok := rule.Key(tc.event)
			require.Equal(t, tc.wantMatch, ok)
			assert.Equal(t, tc.wantParts, parts)
		})
	}
}
