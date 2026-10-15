package flows

import (
	"net/netip"
	"testing"

	"github.com/safedep/pmg/proxy"
	"github.com/safedep/pmg/sandbox"
	"github.com/safedep/pmg/sandbox/executor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNetworkDecisionLogReport(t *testing.T) {
	l := newNetworkDecisionLog(&executor.Resolution{Policy: &sandbox.SandboxPolicy{Name: "ci"}})
	assert.Nil(t, l.report())

	curl := proxy.Origin{PID: 7, Comm: "curl", Exe: "/usr/bin/curl", EntryPoint: proxy.EntryPointRedirectedHost}
	l.record(proxy.NetworkDecision{Host: "evil.example", Port: 443, Rule: "*:*", Enforced: true, Origin: curl})
	l.record(proxy.NetworkDecision{Host: "evil.example", Port: 443, Rule: "*:*", Enforced: true, Origin: curl})
	l.record(proxy.NetworkDecision{Host: "cdn.example", Port: 80, Rule: "*:80", Enforced: true,
		Origin: proxy.Origin{Address: netip.MustParseAddr("172.17.0.2"), EntryPoint: proxy.EntryPointRedirectedNamespace}})

	report := l.report()
	require.NotNil(t, report)
	assert.True(t, report.Enforced)
	require.Len(t, report.Denials, 2)
	assert.Equal(t, "cdn.example:80", report.Denials[0].Destination)
	assert.Equal(t, "172.17.0.2", report.Denials[0].Client)
	assert.Equal(t, "evil.example:443", report.Denials[1].Destination)
	assert.Equal(t, "/usr/bin/curl", report.Denials[1].Client)
	assert.Equal(t, 2, report.Denials[1].Count)
	assert.Equal(t, "*:*", report.Denials[1].Rule)
}

func TestNetworkDecisionLogAuditIsNotAViolation(t *testing.T) {
	l := newNetworkDecisionLog(nil)
	l.record(proxy.NetworkDecision{Host: "evil.example", Port: 443, Rule: "*:*", Enforced: false})

	report := l.report()
	require.NotNil(t, report)
	assert.False(t, report.Enforced)
	assert.Equal(t, "", report.Denials[0].Client)
}
