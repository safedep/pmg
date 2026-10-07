package proxye2e

import (
	"net/http"
	"testing"

	"github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// npmOnlyEgress enforces the rules a locked npm profile ships, through the
// real sandbox matcher, so the cases check the shipped decision order.
func npmOnlyEgress(t *testing.T) Option {
	t.Helper()

	m, err := sandbox.NewOutboundMatcher(sandbox.NetworkPolicy{
		AllowOutbound: []string{"registry.npmjs.org:443", "plain.example:80"},
		DenyOutbound:  []string{"*:*"},
	})
	require.NoError(t, err)

	return WithEgress(m)
}

// getWithHost sends one GET to rawURL with a different Host header. Inside a
// MITM tunnel goproxy builds the upstream URL from that header.
func (h *Harness) getWithHost(rawURL, host string) RequestOutcome {
	h.t.Helper()

	out := RequestOutcome{URL: rawURL}

	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		out.Err = err
		return out
	}
	req.Host = host

	resp, err := h.client.Do(req)
	if err != nil {
		out.Err = err
		return out
	}
	return readOutcome(resp, out)
}

func TestProxyFlow_EgressRules(t *testing.T) {
	RunCases(t, []TestCase{
		{
			Name:    "allowed host passes through MITM",
			Options: []Option{npmOnlyEgress(t)},
			Setup: func(h *Harness) {
				h.Registry.AddNpm(NpmPackage{Name: "left-pad", DistTagLatest: "1.0.0",
					Versions: []NpmVersion{{Version: "1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetNpm("left-pad", "1.0.0", Clean())
			},
			Exec: func(h *Harness) ExecResult { return h.Npm().Install("left-pad", "1.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.Len(t, res.Requests, 2)
				for _, r := range res.Requests {
					require.NoError(t, r.Err)
					assert.Equal(t, http.StatusOK, r.StatusCode, r.URL)
				}
				assert.True(t, h.Registry.DownloadedTarball("left-pad", "1.0.0"))
			},
		},
		{
			Name:    "CONNECT to a denied host is refused before any dial",
			Options: []Option{npmOnlyEgress(t)},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{h.get("https://evil.example/x", nil)}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.Len(t, res.Requests, 1)
				require.Error(t, res.Requests[0].Err)
				// net/http reports a refused CONNECT with the status text only.
				assert.Contains(t, res.Requests[0].Err.Error(), "Forbidden")
				assert.Empty(t, h.DialedAddrs())
			},
		},
		{
			Name:    "CONNECT to an IP literal is refused when only names are allowed",
			Options: []Option{npmOnlyEgress(t)},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{h.get("https://104.16.0.35/left-pad", nil)}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.Error(t, res.Requests[0].Err)
				assert.Empty(t, h.DialedAddrs())
			},
		},
		{
			Name:    "plain HTTP to a denied host gets 403 with the destination",
			Options: []Option{npmOnlyEgress(t)},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{h.get("http://evil.example/x", nil)}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.Equal(t, http.StatusForbidden, res.Requests[0].StatusCode)
				assert.Contains(t, res.Requests[0].Body, "evil.example:80")
				assert.Empty(t, h.DialedAddrs())
			},
		},
		{
			Name:    "plain HTTP to an allowed host on the default port passes",
			Options: []Option{npmOnlyEgress(t)},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{h.get("http://plain.example/x", nil)}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.NotEqual(t, http.StatusForbidden, res.Requests[0].StatusCode)
				assert.Contains(t, h.DialedAddrs(), "plain.example:80")
			},
		},
		{
			Name:    "MITM request with a changed Host to a denied host gets 403",
			Options: []Option{npmOnlyEgress(t)},
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{
					h.getWithHost("https://registry.npmjs.org/left-pad", "evil.example"),
				}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.Equal(t, http.StatusForbidden, res.Requests[0].StatusCode)
				assert.Contains(t, res.Requests[0].Body, "evil.example:443")
				assert.NotContains(t, h.DialedAddrs(), "evil.example:443")
			},
		},
		{
			Name: "no egress policy forwards every host",
			Exec: func(h *Harness) ExecResult {
				return ExecResult{Requests: []RequestOutcome{h.get("http://evil.example/x", nil)}}
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.NotEqual(t, http.StatusForbidden, res.Requests[0].StatusCode)
				assert.Contains(t, h.DialedAddrs(), "evil.example:80")
			},
		},
	})
}
