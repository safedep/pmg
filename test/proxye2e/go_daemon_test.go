package proxye2e

import (
	"net/http"
	"testing"

	"github.com/safedep/pmg/proxy/certmanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The persistent proxy analyzes Go without a `pmg go` run. Under kernel
// enforcement go reaches the proxy as a redirected client. These cases prove
// that the built-in module proxy and a Go proxy from proxy.registries get the
// same verdicts as during `pmg go`.
func TestProxyFlow_GoDaemon(t *testing.T) {
	RunCases(t, []TestCase{
		{
			Name:    "redirected TLS to proxy.golang.org blocks a malicious module zip",
			Options: []Option{WithTransparent(nil)},
			Setup: func(h *Harness) {
				h.Registry.AddGoModule(GoModule{Path: "example.com/evil",
					Versions: []GoVersion{{Version: "v1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetGo("example.com/evil", "v1.0.0", VerifiedMalware())
			},
			Exec: func(h *Harness) ExecResult {
				var res ExecResult
				res.add(h.RedirectedTLS("proxy.golang.org", "/example.com/evil/@v/v1.0.0.zip"))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.True(t, res.Blocked())
				assert.Equal(t, 1, h.Analyzer.AnalyzedCount("example.com/evil", "v1.0.0"))
				assert.False(t, h.Registry.DownloadedGoZip("example.com/evil", "v1.0.0"))
				assert.Equal(t, 1, h.Stats().BlockedCount)
			},
		},
		{
			Name:    "redirected TLS to proxy.golang.org serves a clean module zip",
			Options: []Option{WithTransparent(nil)},
			Setup: func(h *Harness) {
				h.Registry.AddGoModule(GoModule{Path: "example.com/m",
					Versions: []GoVersion{{Version: "v1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetGo("example.com/m", "v1.0.0", Clean())
			},
			Exec: func(h *Harness) ExecResult {
				var res ExecResult
				res.add(h.RedirectedTLS("proxy.golang.org", "/example.com/m/@v/v1.0.0.zip"))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.Equal(t, http.StatusOK, res.Requests[0].StatusCode)
				assert.Equal(t, 1, h.Analyzer.AnalyzedCount("example.com/m", "v1.0.0"))
				assert.True(t, h.Registry.DownloadedGoZip("example.com/m", "v1.0.0"))
			},
		},
		{
			Name:    "redirected TLS to proxy.golang.org applies the cooldown to a module zip",
			Options: []Option{WithTransparent(nil)},
			Config:  cooldownEnabled(7),
			Setup: func(h *Harness) {
				h.Registry.AddGoModule(GoModule{Path: "example.com/fresh",
					Versions: []GoVersion{{Version: "v1.1.0", PublishedAt: recent()}}})
				h.Analyzer.SetGo("example.com/fresh", "v1.1.0", Clean())
			},
			Exec: func(h *Harness) ExecResult {
				var res ExecResult
				res.add(h.RedirectedTLS("proxy.golang.org", "/example.com/fresh/@v/v1.1.0.zip"))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.True(t, res.Blocked())
				assert.False(t, h.Registry.DownloadedGoZip("example.com/fresh", "v1.1.0"))
				assert.Equal(t, 1, h.Stats().CooldownBlockedCount)
				assert.Empty(t, h.Analyzer.Calls(), "the cooldown blocks before malware analysis")
			},
		},
		{
			Name:    "redirected TLS to sum.golang.org is spliced with its real certificate",
			Options: []Option{WithTransparent(nil)},
			Exec: func(h *Harness) ExecResult {
				cert, err := h.RedirectedTLSPeerCert("sum.golang.org")
				out := RequestOutcome{URL: "https://sum.golang.org", Err: err}
				if err == nil {
					out.Body = cert.Issuer.CommonName
				}
				var res ExecResult
				res.add(out)
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.NotEqual(t, certmanager.CACommonName, res.Requests[0].Body,
					"go verifies the checksum database itself, so PMG never decrypts it")
				assert.Contains(t, h.DialedAddrs(), "sum.golang.org:443")
			},
		},
		{
			Name:   "a Go proxy from proxy.registries is analyzed under its base path",
			Config: customRegistry("company-go", "go", "https://goproxy.corp.test/goproxy"),
			Setup: func(h *Harness) {
				h.Registry.AddGoModule(GoModule{Path: "example.com/evil",
					Versions: []GoVersion{{Version: "v1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetGo("example.com/evil", "v1.0.0", VerifiedMalware())
			},
			Exec: func(h *Harness) ExecResult {
				var res ExecResult
				res.add(h.Go().DownloadZipVia("https://goproxy.corp.test/goproxy", "example.com/evil", "v1.0.0"))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.True(t, res.Blocked())
				assert.Equal(t, 1, h.Analyzer.AnalyzedCount("example.com/evil", "v1.0.0"))
				assert.False(t, h.Registry.Requested("goproxy.corp.test", "/goproxy/example.com/evil/@v/v1.0.0.zip"))
			},
		},
	})
}
