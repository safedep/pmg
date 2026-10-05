package proxye2e

import (
	"net/http"
	"testing"

	"github.com/safedep/pmg/proxy/certmanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A client the kernel redirected to the proxy does not speak the proxy
// protocol. It sends a TLS ClientHello or an origin-form request straight to
// the listener. These cases prove the transparent listener gives such a
// client the same verdicts as a proxy-aware one.
func TestProxyFlow_TransparentRedirect(t *testing.T) {
	// The mock address is only known once the harness exists, so Setup fills
	// the resolver in.
	plainResolver := &StaticOriginalDestination{}

	RunCases(t, []TestCase{
		{
			Name:    "redirected TLS to a registry host is terminated and malware is blocked",
			Options: []Option{WithTransparent(nil)},
			Setup: func(h *Harness) {
				h.Registry.AddNpm(NpmPackage{Name: "evil", DistTagLatest: "1.0.0",
					Versions: []NpmVersion{{Version: "1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetNpm("evil", "1.0.0", VerifiedMalware())
			},
			Exec: func(h *Harness) ExecResult {
				var res ExecResult
				res.add(h.RedirectedTLS("registry.npmjs.org", "/evil/-/evil-1.0.0.tgz"))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.True(t, res.Blocked())
				assert.Equal(t, 1, h.Analyzer.AnalyzedCount("evil", "1.0.0"))
				assert.False(t, h.Registry.DownloadedTarball("evil", "1.0.0"))
				assert.Equal(t, 1, h.Stats().BlockedCount)
			},
		},
		{
			Name:    "redirected TLS to a registry host serves a clean tarball",
			Options: []Option{WithTransparent(nil)},
			Setup: func(h *Harness) {
				h.Registry.AddNpm(NpmPackage{Name: "left-pad", DistTagLatest: "1.0.0",
					Versions: []NpmVersion{{Version: "1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetNpm("left-pad", "1.0.0", Clean())
			},
			Exec: func(h *Harness) ExecResult {
				var res ExecResult
				res.add(h.RedirectedTLS("registry.npmjs.org", "/left-pad/-/left-pad-1.0.0.tgz"))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.Equal(t, http.StatusOK, res.Requests[0].StatusCode)
				assert.Equal(t, 1, h.Analyzer.AnalyzedCount("left-pad", "1.0.0"))
				assert.True(t, h.Registry.DownloadedTarball("left-pad", "1.0.0"))
			},
		},
		{
			Name:    "a ClientHello split across two records is still terminated and blocked",
			Options: []Option{WithTransparent(nil)},
			Setup: func(h *Harness) {
				h.Registry.AddNpm(NpmPackage{Name: "evil", DistTagLatest: "1.0.0",
					Versions: []NpmVersion{{Version: "1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetNpm("evil", "1.0.0", VerifiedMalware())
			},
			Exec: func(h *Harness) ExecResult {
				var res ExecResult
				res.add(h.RedirectedTLSFragmented("registry.npmjs.org", "/evil/-/evil-1.0.0.tgz"))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.True(t, res.Blocked(), "fragmentation must not splice the connection past the interceptors")
				assert.False(t, h.Registry.DownloadedTarball("evil", "1.0.0"))
				assert.NotContains(t, h.DialedAddrs(), "registry.npmjs.org:443", "no splice to the registry")
			},
		},
		{
			Name:    "redirected plain HTTP is analyzed and forwarded as plain HTTP",
			Options: []Option{WithTransparent(nil)},
			Setup: func(h *Harness) {
				h.Registry.AddNpm(NpmPackage{Name: "evil", DistTagLatest: "1.0.0",
					Versions: []NpmVersion{{Version: "1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetNpm("evil", "1.0.0", VerifiedMalware())
			},
			Exec: func(h *Harness) ExecResult {
				var res ExecResult
				res.add(h.RedirectedHTTP("registry.npmjs.org", "/evil/-/evil-1.0.0.tgz"))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.True(t, res.Blocked())
				assert.False(t, h.Registry.DownloadedTarball("evil", "1.0.0"))
			},
		},
		{
			Name:    "redirected plain HTTP without Host is refused",
			Options: []Option{WithTransparent(plainResolver)},
			Setup: func(h *Harness) {
				plainResolver.Addr = h.MockPlainRegistryAddrPort()
			},
			Exec: func(h *Harness) ExecResult {
				var res ExecResult
				res.add(h.RedirectedHTTP("", "/left-pad"))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				// The interceptors match names. An IP would pass a registry
				// without analysis, so the kernel entry never stands in for
				// the Host header.
				assert.Equal(t, http.StatusBadRequest, res.Requests[0].StatusCode)
				assert.Empty(t, h.DialedAddrs(), "nothing is forwarded")
			},
		},
		{
			Name:    "a redirected request that names the proxy itself is refused",
			Options: []Option{WithTransparent(nil)},
			Exec: func(h *Harness) ExecResult {
				var res ExecResult
				res.add(h.RedirectedHTTP(h.proxy.Address(), "/"))
				res.add(h.RedirectedHTTP("localhost:80", "/"))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				for _, r := range res.Requests {
					require.NoError(t, r.Err)
					assert.Equal(t, http.StatusBadRequest, r.StatusCode, r.URL)
				}
				assert.Empty(t, h.DialedAddrs(), "the proxy never forwards to itself")
			},
		},
		{
			Name:    "redirected TLS to a non-registry host is spliced with its real certificate",
			Options: []Option{WithTransparent(nil)},
			Exec: func(h *Harness) ExecResult {
				cert, err := h.RedirectedTLSPeerCert("github.com")
				var res ExecResult
				out := RequestOutcome{URL: "https://github.com", Err: err}
				if err == nil {
					out.Body = cert.Issuer.CommonName
				}
				res.add(out)
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.NoError(t, res.Requests[0].Err)
				assert.NotEqual(t, certmanager.CACommonName, res.Requests[0].Body,
					"a non-registry host must keep the upstream certificate")
				assert.Contains(t, h.DialedAddrs(), "github.com:443")
			},
		},
	})
}

// A redirected TLS client without SNI gives the proxy no name to decide on.
// The original destination is only an IP, and an IP never matches a
// registry, so the connection is dropped instead of spliced.
func TestProxyFlow_TransparentNoSNIIsDropped(t *testing.T) {
	applyConfig(t, nil)

	resolver := &StaticOriginalDestination{}
	h := New(t, WithTransparent(resolver))
	defer h.Close()
	resolver.Addr = h.MockRegistryAddrPort()

	_, err := h.RedirectedTLSPeerCert("")
	require.Error(t, err)
	assert.Empty(t, h.DialedAddrs(), "a nameless connection is never spliced to the registry IP")
}

// The same holds without a kernel entry.
func TestProxyFlow_TransparentNoSNINoDestinationIsDropped(t *testing.T) {
	applyConfig(t, nil)

	h := New(t, WithTransparent(nil))
	defer h.Close()

	_, err := h.RedirectedTLSPeerCert("")
	require.Error(t, err)
	assert.Empty(t, h.DialedAddrs())
}
