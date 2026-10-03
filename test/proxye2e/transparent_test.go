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
			Name:    "redirected plain HTTP without Host uses the original destination",
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
				// The mock knows no registry at its own IP, so it answers 404.
				// The request reached it, which proves the fallback.
				assert.Equal(t, http.StatusNotFound, res.Requests[0].StatusCode)
				assert.Contains(t, h.DialedAddrs(), h.Registry.plainAddr())
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

// A redirected TLS client without SNI gives the proxy no name. The original
// destination from the kernel is the only way to reach the right server.
func TestProxyFlow_TransparentNoSNIUsesOriginalDestination(t *testing.T) {
	applyConfig(t, nil)

	// The harness address is only known after New, so build the resolver in
	// two steps: a placeholder first, then the real address.
	resolver := &StaticOriginalDestination{}
	h := New(t, WithTransparent(resolver))
	defer h.Close()
	resolver.Addr = h.MockRegistryAddrPort()

	cert, err := h.RedirectedTLSPeerCert("")
	require.NoError(t, err)
	assert.NotEqual(t, certmanager.CACommonName, cert.Issuer.CommonName)
	assert.Contains(t, h.DialedAddrs(), h.Registry.addr())
}

// A redirected TLS client without SNI and without a kernel entry cannot be
// routed. The proxy closes the connection instead of guessing.
func TestProxyFlow_TransparentNoSNINoDestinationIsDropped(t *testing.T) {
	applyConfig(t, nil)

	h := New(t, WithTransparent(nil))
	defer h.Close()

	_, err := h.RedirectedTLSPeerCert("")
	require.Error(t, err)
	assert.Empty(t, h.DialedAddrs())
}
