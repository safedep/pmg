package interceptors

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func cargoIndexBody(lines ...string) []byte {
	return []byte(strings.Join(lines, "\n") + "\n")
}

func cargoIndexLineJSON(name, version string, publishedAt time.Time) string {
	return fmt.Sprintf(`{"name":%q,"vers":%q,"deps":[],"cksum":"abc","yanked":false,"pubtime":%q}`,
		name, version, publishedAt.UTC().Format("2006-01-02T15:04:05Z"))
}

var (
	cratesIOIndex    = &cargoRegistryEndpoints[0]
	cratesIODownload = &cargoRegistryEndpoints[1]
)

func newBuiltInCargoCooldownHandler(stats *AnalysisStatsCollector, upstreamOrigin string) *cargoCooldownHandler {
	return newCargoCooldownHandler(stats, registrySet{entries: cargoRegistryEndpoints}, upstreamOrigin)
}

func runCargoIndexModifier(t *testing.T, h *cargoCooldownHandler, crate string, days int, body []byte) (int, http.Header, []byte) {
	t.Helper()

	ctx := &proxy.RequestContext{RequestID: "test", Headers: http.Header{}}

	resp, err := h.HandleIndexRequest(ctx, cratesIOIndex, crate, days, "")
	require.NoError(t, err)
	require.Equal(t, proxy.ActionModifyResponse, resp.Action)
	require.NotNil(t, resp.ResponseModifier)

	headers := http.Header{}
	headers.Set("ETag", `"abc"`)
	headers.Set("Last-Modified", "Mon, 02 Jan 2006 15:04:05 GMT")

	status, outHeaders, outBody, err := resp.ResponseModifier(http.StatusOK, headers, body)
	require.NoError(t, err)

	return status, outHeaders, outBody
}

func TestCargoCooldownHandleIndexRequest(t *testing.T) {
	oldTime := time.Now().Add(-100 * 24 * time.Hour)
	recentTime := time.Now().Add(-24 * time.Hour)

	t.Run("strips in-window versions and cache validators", func(t *testing.T) {
		h := newBuiltInCargoCooldownHandler(NewAnalysisStatsCollector(), "")

		body := cargoIndexBody(
			cargoIndexLineJSON("serde", "1.0.0", oldTime),
			cargoIndexLineJSON("serde", "2.0.0", recentTime),
		)

		status, headers, out := runCargoIndexModifier(t, h, "serde", 7, body)

		assert.Equal(t, http.StatusOK, status)
		assert.Contains(t, string(out), `"vers":"1.0.0"`)
		assert.NotContains(t, string(out), `"vers":"2.0.0"`)
		assert.Equal(t, "no-store", headers.Get("Cache-Control"))
		assert.Empty(t, headers.Get("ETag"))
		assert.Empty(t, headers.Get("Last-Modified"))
	})

	t.Run("keeps body and validators when nothing is in window", func(t *testing.T) {
		h := newBuiltInCargoCooldownHandler(NewAnalysisStatsCollector(), "")

		body := cargoIndexBody(cargoIndexLineJSON("serde", "1.0.0", oldTime))

		_, headers, out := runCargoIndexModifier(t, h, "serde", 7, body)

		assert.Equal(t, body, out)
		assert.NotEmpty(t, headers.Get("ETag"))
	})

	t.Run("lines without pubtime survive", func(t *testing.T) {
		h := newBuiltInCargoCooldownHandler(NewAnalysisStatsCollector(), "")

		body := cargoIndexBody(
			`{"name":"serde","vers":"0.9.0","deps":[],"cksum":"abc","yanked":false}`,
			cargoIndexLineJSON("serde", "2.0.0", recentTime),
		)

		_, _, out := runCargoIndexModifier(t, h, "serde", 7, body)

		assert.Contains(t, string(out), `"vers":"0.9.0"`)
		assert.NotContains(t, string(out), `"vers":"2.0.0"`)
	})

	t.Run("records publish times for the download check", func(t *testing.T) {
		h := newBuiltInCargoCooldownHandler(NewAnalysisStatsCollector(), "")

		body := cargoIndexBody(cargoIndexLineJSON("Inflector", "2.0.0", recentTime))
		runCargoIndexModifier(t, h, "inflector", 7, body)

		ctx := &proxy.RequestContext{RequestID: "test"}
		resp, handled := h.CheckCrateDownload(ctx, cratesIODownload, "Inflector", "2.0.0", 7)
		require.True(t, handled)
		assert.Equal(t, proxy.ActionBlock, resp.Action)
	})

	t.Run("records a cooldown stat when stripping", func(t *testing.T) {
		stats := NewAnalysisStatsCollector()
		h := newBuiltInCargoCooldownHandler(stats, "")

		body := cargoIndexBody(
			cargoIndexLineJSON("serde", "1.0.0", oldTime),
			cargoIndexLineJSON("serde", "2.0.0", recentTime),
		)
		runCargoIndexModifier(t, h, "serde", 7, body)

		withheld := stats.GetCooldownWithheld()
		require.Len(t, withheld, 1)
		assert.Equal(t, "serde", withheld[0].Name)
	})

	t.Run("pubtime-less survivors are not reported as a definite block", func(t *testing.T) {
		stats := NewAnalysisStatsCollector()
		h := newBuiltInCargoCooldownHandler(stats, "")

		body := cargoIndexBody(
			`{"name":"serde","vers":"0.9.0","deps":[],"cksum":"abc","yanked":false}`,
			cargoIndexLineJSON("serde", "2.0.0", recentTime),
		)
		runCargoIndexModifier(t, h, "serde", 7, body)

		assert.Empty(t, stats.GetCooldownBlocks(), "an installable pubtime-less version remains, not a definite block")
		assert.Len(t, stats.GetCooldownWithheld(), 1)
	})

	t.Run("non-200 response passes through", func(t *testing.T) {
		h := newBuiltInCargoCooldownHandler(NewAnalysisStatsCollector(), "")

		ctx := &proxy.RequestContext{RequestID: "test", Headers: http.Header{}}
		resp, err := h.HandleIndexRequest(ctx, cratesIOIndex, "serde", 7, "")
		require.NoError(t, err)

		status, _, out, err := resp.ResponseModifier(http.StatusNotFound, http.Header{}, []byte("not found"))
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, status)
		assert.Equal(t, []byte("not found"), out)
	})
}

func TestCargoCooldownCheckCrateDownloadSideFetch(t *testing.T) {
	publishTime := time.Now().Add(-24 * time.Hour)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Only index.crates.io serves the index. A fetch from
		// static.crates.io must not stand in for it.
		if req.URL.Path == "/index.crates.io/3/f/foo" {
			_, err := w.Write(cargoIndexBody(cargoIndexLineJSON("foo", "1.1.0", publishTime)))
			require.NoError(t, err)
			return
		}
		http.NotFound(w, req)
	}))
	defer server.Close()

	ctx := &proxy.RequestContext{RequestID: "test"}

	t.Run("blocks using out-of-band publish time on cache miss", func(t *testing.T) {
		h := newBuiltInCargoCooldownHandler(NewAnalysisStatsCollector(), server.URL)

		resp, handled := h.CheckCrateDownload(ctx, cratesIODownload, "foo", "1.1.0", 7)
		require.True(t, handled)
		assert.Equal(t, proxy.ActionBlock, resp.Action)
		assert.Equal(t, http.StatusForbidden, resp.BlockCode)
		assert.Equal(t, proxy.BlockReasonDependencyCooldown, resp.BlockReason)

		require.NotNil(t, resp.BlockContext)
		assert.Equal(t, packagev1.Ecosystem_ECOSYSTEM_CARGO, resp.BlockContext.Ecosystem)
		assert.Equal(t, "foo", resp.BlockContext.PackageName)
		assert.Equal(t, "1.1.0", resp.BlockContext.PackageVersion)
		assert.Equal(t, 7, resp.BlockContext.CooldownDays)
		assert.Equal(t, 1, resp.BlockContext.CooldownDaysAgo)
		assert.Equal(t, 6, resp.BlockContext.CooldownDaysLeft)
	})

	t.Run("allows an out-of-window version", func(t *testing.T) {
		h := newBuiltInCargoCooldownHandler(NewAnalysisStatsCollector(), server.URL)

		_, handled := h.CheckCrateDownload(ctx, cratesIODownload, "foo", "1.1.0", 1)
		assert.False(t, handled)
	})

	t.Run("fails open when the out-of-band fetch fails", func(t *testing.T) {
		h := newBuiltInCargoCooldownHandler(NewAnalysisStatsCollector(), server.URL)

		_, handled := h.CheckCrateDownload(ctx, cratesIODownload, "unknown", "9.9.9", 7)
		assert.False(t, handled)
	})
}

// customCargoRegistry returns a registry set with the built-in crates.io
// endpoints and one custom registry whose download endpoint comes before its
// index endpoint, as an Artifactory registry can be configured.
func customCargoRegistry(t *testing.T) registrySet {
	t.Helper()
	catalog, err := NewRegistryCatalog([]config.ProxyRegistryConfig{{
		Name:      "company-cargo",
		Ecosystem: config.ProxyRegistryEcosystemCargo,
		Endpoints: []config.ProxyRegistryEndpointConfig{
			{URL: "https://cargo.example.test/dl"},
			{URL: "https://cargo.example.test/index"},
		},
	}}, nil)
	require.NoError(t, err)
	return catalog.registrySet(packagev1.Ecosystem_ECOSYSTEM_CARGO)
}

func TestCargoCooldownCustomRegistryFetch(t *testing.T) {
	publishTime := time.Now().Add(-24 * time.Hour)

	var requests []*http.Request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requests = append(requests, req)
		switch req.URL.Path {
		case "/cargo.example.test/index/3/f/foo":
			_, err := w.Write(cargoIndexBody(cargoIndexLineJSON("foo", "1.1.0", publishTime)))
			require.NoError(t, err)
		case "/cargo.example.test/dl/3/f/foo":
			// A download endpoint can answer an unknown path with 200 and an
			// error page. It must not pass as an index file.
			_, err := w.Write([]byte(`{"errors":[{"detail":"not found"}]}`))
			require.NoError(t, err)
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	registries := customCargoRegistry(t)
	download := &registries.entries[len(registries.entries)-2]
	require.Equal(t, "/dl", download.BasePath)

	ctx := &proxy.RequestContext{RequestID: "test", Headers: http.Header{"Authorization": []string{"Bearer secret"}}}

	h := newCargoCooldownHandler(NewAnalysisStatsCollector(), registries, server.URL)
	resp, handled := h.CheckCrateDownload(ctx, download, "foo", "1.1.0", 7)
	require.True(t, handled)
	assert.Equal(t, proxy.ActionBlock, resp.Action)

	paths := make([]string, len(requests))
	for index, req := range requests {
		paths[index] = req.URL.Path
		assert.Equal(t, "Bearer secret", req.Header.Get("Authorization"), "a custom registry gets the token of the request")
	}
	assert.Equal(t, []string{"/cargo.example.test/dl/3/f/foo", "/cargo.example.test/index/3/f/foo"}, paths,
		"only the endpoints of the registry, in config order")

	requests = nil
	_, handled = h.CheckCrateDownload(ctx, download, "foo", "1.1.0", 7)
	require.True(t, handled)
	assert.Empty(t, requests, "the publish time is cached")

	_, handled = h.CheckCrateDownload(ctx, download, "fooo", "1.0.0", 7)
	assert.False(t, handled)
	require.NotEmpty(t, requests)
	assert.Equal(t, "/cargo.example.test/index/fo/oo/fooo", requests[0].URL.Path, "the endpoint that served the index is tried first")
}

func TestCargoCooldownBuiltInFetchSendsNoAuthorization(t *testing.T) {
	var authorization []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		authorization = append(authorization, req.Header.Get("Authorization"))
		http.NotFound(w, req)
	}))
	defer server.Close()

	ctx := &proxy.RequestContext{RequestID: "test", Headers: http.Header{"Authorization": []string{"Bearer secret"}}}
	h := newBuiltInCargoCooldownHandler(NewAnalysisStatsCollector(), server.URL)
	_, handled := h.CheckCrateDownload(ctx, cratesIODownload, "foo", "1.1.0", 7)
	assert.False(t, handled)
	require.NotEmpty(t, authorization)
	for _, value := range authorization {
		assert.Empty(t, value)
	}
}

func TestCargoCooldownKeepsPublishTimesPerRegistry(t *testing.T) {
	registries := customCargoRegistry(t)
	custom := &registries.entries[len(registries.entries)-1]
	h := newCargoCooldownHandler(NewAnalysisStatsCollector(), registries, "http://127.0.0.1:1")

	h.recordPublishTimes(cargoRegistryKey(custom), "foo", map[string]time.Time{"1.0.0": time.Now()})

	ctx := &proxy.RequestContext{RequestID: "test", Headers: http.Header{}}
	_, handled := h.CheckCrateDownload(ctx, cratesIODownload, "foo", "1.0.0", 7)
	assert.False(t, handled, "a publish time from another registry does not apply to crates.io")

	resp, handled := h.CheckCrateDownload(ctx, custom, "foo", "1.0.0", 7)
	require.True(t, handled)
	assert.Equal(t, proxy.ActionBlock, resp.Action)
}

func TestCargoCooldownIndexCandidates(t *testing.T) {
	h := newBuiltInCargoCooldownHandler(NewAnalysisStatsCollector(), "")
	assert.Equal(t, []*registryEndpoint{cratesIOIndex, cratesIODownload}, h.indexCandidates("crates.io"),
		"with no endpoint remembered, every endpoint is a candidate in config order")

	h.indexEndpoints["crates.io"] = cratesIODownload
	assert.Equal(t, []*registryEndpoint{cratesIODownload, cratesIOIndex}, h.indexCandidates("crates.io"))
}

func TestCargoCooldownIndexBaseURL(t *testing.T) {
	registries := customCargoRegistry(t)
	custom := &registries.entries[len(registries.entries)-1]

	h := newCargoCooldownHandler(NewAnalysisStatsCollector(), registries, "")
	assert.Equal(t, "https://index.crates.io", h.indexBaseURL(cratesIOIndex))
	assert.Equal(t, "https://cargo.example.test/index", h.indexBaseURL(custom))

	h = newCargoCooldownHandler(NewAnalysisStatsCollector(), registries, "http://127.0.0.1:8080")
	assert.Equal(t, "http://127.0.0.1:8080/index.crates.io", h.indexBaseURL(cratesIOIndex))
	assert.Equal(t, "http://127.0.0.1:8080/cargo.example.test/index", h.indexBaseURL(custom))
}
