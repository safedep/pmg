package proxye2e

import (
	"net/http"
	"net/netip"
	"testing"

	"github.com/safedep/pmg/proxy/netpolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ipLiterals is a policy with deny_ip_literals and the given rules.
func ipLiterals(t *testing.T, allow, deny []string, enforce bool) Option {
	t.Helper()

	p, err := netpolicy.New(allow, deny, netpolicy.DenyIPLiterals())
	require.NoError(t, err)
	return WithNetworkPolicy(p, enforce)
}

// assertOneDecision checks the one destination of the case. The harness
// keeps denials and destinations apart, so an allowed destination is read
// from the destinations. The proxy records a rule only for a denial.
func assertOneDecision(t *testing.T, h *Harness, host, rule string, allowed, enforced bool) {
	t.Helper()
	decisions := h.NetworkDecisions()
	if allowed {
		assert.Empty(t, decisions)
		decisions = h.Destinations()
	}
	require.Len(t, decisions, 1)
	assert.Equal(t, host, decisions[0].Host)
	assert.Equal(t, rule, decisions[0].Rule)
	assert.Equal(t, allowed, decisions[0].Allowed)
	assert.Equal(t, enforced, decisions[0].Enforced)
}

// deny_ip_literals denies a destination that is an address and not a name,
// at every entry point, unless a rule names that exact address.
func TestProxyFlow_NetworkPolicyDenyIPLiterals(t *testing.T) {
	unnamed := &StaticOriginalDestination{Addr: netip.MustParseAddrPort("10.0.0.5:443")}

	RunCases(t, []TestCase{
		{
			Name:    "CONNECT to an address is refused under a catch-all allow",
			Options: []Option{ipLiterals(t, []string{"*:*"}, nil, true)},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{h.rawConnect("193.32.204.199:80")}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.Equal(t, http.StatusForbidden, res.Requests[0].StatusCode)
				assert.Empty(t, h.DialedAddrs())
				assertOneDecision(t, h, "193.32.204.199", netpolicy.IPLiteralRule, false, true)
			},
		},
		{
			Name: "without the key the same CONNECT goes through",
			Options: []Option{func() Option {
				p, err := netpolicy.New([]string{"*:*"}, nil)
				require.NoError(t, err)
				return WithNetworkPolicy(p, true)
			}()},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{h.rawConnect("193.32.204.199:80")}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.Equal(t, http.StatusOK, res.Requests[0].StatusCode)
				assertOneDecision(t, h, "193.32.204.199", "", true, false)
			},
		},
		{
			Name:    "an allow rule that names the address wins",
			Options: []Option{ipLiterals(t, []string{"10.0.0.5:5000"}, []string{"*:*"}, true)},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{h.rawConnect("10.0.0.5:5000")}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.Equal(t, http.StatusOK, res.Requests[0].StatusCode)
				assertOneDecision(t, h, "10.0.0.5", "", true, false)
			},
		},
		{
			Name:    "plain HTTP to an address gets 403 that names the address and the rule",
			Options: []Option{ipLiterals(t, nil, nil, true)},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{h.get("http://193.32.204.199/?c=monami", nil)}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.Equal(t, http.StatusForbidden, res.Requests[0].StatusCode)
				assert.Contains(t, res.Requests[0].Body, "193.32.204.199:80")
				assert.Empty(t, h.DialedAddrs())
				assertOneDecision(t, h, "193.32.204.199", netpolicy.IPLiteralRule, false, true)
			},
		},
		{
			Name:    "a name is decided by the rules as before",
			Options: []Option{ipLiterals(t, []string{"plain.example:80"}, []string{"*:*"}, true)},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{h.get("http://plain.example/x", nil)}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.NotEqual(t, http.StatusForbidden, res.Requests[0].StatusCode)
				assertOneDecision(t, h, "plain.example", "", true, false)
			},
		},
		{
			Name:    "loopback stays with the rules",
			Options: []Option{ipLiterals(t, nil, nil, true)},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{h.rawConnect("127.0.0.1:9999")}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.Equal(t, http.StatusOK, res.Requests[0].StatusCode)
				assertOneDecision(t, h, "127.0.0.1", "", true, false)
			},
		},
		{
			Name:    "audit records the address denial and lets the connection through",
			Options: []Option{ipLiterals(t, nil, nil, false)},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{h.rawConnect("193.32.204.199:80")}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.Equal(t, http.StatusOK, res.Requests[0].StatusCode)
				assertOneDecision(t, h, "193.32.204.199", netpolicy.IPLiteralRule, false, false)
			},
		},
		{
			Name:    "a redirected TLS connection with no server name is recorded as an address denial",
			Options: []Option{WithTransparent(unnamed), ipLiterals(t, []string{"*:*"}, nil, true)},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{{Err: h.RedirectedTLSWithoutServerName()}}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.Error(t, res.Requests[0].Err, "the proxy drops a connection it cannot name")
				assert.Empty(t, h.DialedAddrs())
				assertOneDecision(t, h, "10.0.0.5", netpolicy.IPLiteralRule, false, true)
			},
		},
		{
			Name:    "under audit a redirected TLS connection with no server name is still dropped and recorded",
			Options: []Option{WithTransparent(unnamed), ipLiterals(t, []string{"*:*"}, nil, false)},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{{Err: h.RedirectedTLSWithoutServerName()}}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.Error(t, res.Requests[0].Err, "audit changes the record, not the drop")
				assert.Empty(t, h.DialedAddrs())
				assertOneDecision(t, h, "10.0.0.5", netpolicy.IPLiteralRule, false, false)
			},
		},
		{
			Name:    "a redirected plain HTTP request with an address Host is refused",
			Options: []Option{WithTransparent(unnamed), ipLiterals(t, []string{"*:*"}, nil, true)},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{h.RedirectedHTTP("193.32.204.199", "/exfil")}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.Equal(t, http.StatusForbidden, res.Requests[0].StatusCode)
				assert.Empty(t, h.DialedAddrs())
				assertOneDecision(t, h, "193.32.204.199", netpolicy.IPLiteralRule, false, true)
			},
		},
		{
			Name:    "without the key a redirected TLS connection with no server name is dropped and not recorded",
			Options: []Option{WithTransparent(unnamed), registryOnly(t, true)},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{{Err: h.RedirectedTLSWithoutServerName()}}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.Error(t, res.Requests[0].Err)
				assert.Empty(t, h.DialedAddrs())
				assert.Empty(t, h.NetworkDecisions())
			},
		},
	})
}
