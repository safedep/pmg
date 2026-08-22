package interceptors

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
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

func runCargoIndexModifier(t *testing.T, h *cargoCooldownHandler, crate string, days int, body []byte) (int, http.Header, []byte) {
	t.Helper()

	ctx := &proxy.RequestContext{RequestID: "test", Headers: http.Header{}}

	resp, err := h.HandleIndexRequest(ctx, crate, days, "")
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
		h := newCargoCooldownHandler(NewAnalysisStatsCollector(), "")

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
		h := newCargoCooldownHandler(NewAnalysisStatsCollector(), "")

		body := cargoIndexBody(cargoIndexLineJSON("serde", "1.0.0", oldTime))

		_, headers, out := runCargoIndexModifier(t, h, "serde", 7, body)

		assert.Equal(t, body, out)
		assert.NotEmpty(t, headers.Get("ETag"))
	})

	t.Run("lines without pubtime survive", func(t *testing.T) {
		h := newCargoCooldownHandler(NewAnalysisStatsCollector(), "")

		body := cargoIndexBody(
			`{"name":"serde","vers":"0.9.0","deps":[],"cksum":"abc","yanked":false}`,
			cargoIndexLineJSON("serde", "2.0.0", recentTime),
		)

		_, _, out := runCargoIndexModifier(t, h, "serde", 7, body)

		assert.Contains(t, string(out), `"vers":"0.9.0"`)
		assert.NotContains(t, string(out), `"vers":"2.0.0"`)
	})

	t.Run("records publish times for the download check", func(t *testing.T) {
		h := newCargoCooldownHandler(NewAnalysisStatsCollector(), "")

		body := cargoIndexBody(cargoIndexLineJSON("Inflector", "2.0.0", recentTime))
		runCargoIndexModifier(t, h, "inflector", 7, body)

		ctx := &proxy.RequestContext{RequestID: "test"}
		resp, handled := h.CheckCrateDownload(ctx, "Inflector", "2.0.0", 7)
		require.True(t, handled)
		assert.Equal(t, proxy.ActionBlock, resp.Action)
	})

	t.Run("records a cooldown stat when stripping", func(t *testing.T) {
		stats := NewAnalysisStatsCollector()
		h := newCargoCooldownHandler(stats, "")

		body := cargoIndexBody(
			cargoIndexLineJSON("serde", "1.0.0", oldTime),
			cargoIndexLineJSON("serde", "2.0.0", recentTime),
		)
		runCargoIndexModifier(t, h, "serde", 7, body)

		withheld := stats.GetCooldownWithheld()
		require.Len(t, withheld, 1)
		assert.Equal(t, "serde", withheld[0].Name)
	})

	t.Run("non-200 response passes through", func(t *testing.T) {
		h := newCargoCooldownHandler(NewAnalysisStatsCollector(), "")

		ctx := &proxy.RequestContext{RequestID: "test", Headers: http.Header{}}
		resp, err := h.HandleIndexRequest(ctx, "serde", 7, "")
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
		if req.URL.Path == "/3/f/foo" {
			_, err := w.Write(cargoIndexBody(cargoIndexLineJSON("foo", "1.1.0", publishTime)))
			require.NoError(t, err)
			return
		}
		http.NotFound(w, req)
	}))
	defer server.Close()

	ctx := &proxy.RequestContext{RequestID: "test"}

	t.Run("blocks using out-of-band publish time on cache miss", func(t *testing.T) {
		h := newCargoCooldownHandler(NewAnalysisStatsCollector(), server.URL)

		resp, handled := h.CheckCrateDownload(ctx, "foo", "1.1.0", 7)
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
		h := newCargoCooldownHandler(NewAnalysisStatsCollector(), server.URL)

		_, handled := h.CheckCrateDownload(ctx, "foo", "1.1.0", 1)
		assert.False(t, handled)
	})

	t.Run("fails open when the out-of-band fetch fails", func(t *testing.T) {
		h := newCargoCooldownHandler(NewAnalysisStatsCollector(), server.URL)

		_, handled := h.CheckCrateDownload(ctx, "unknown", "9.9.9", 7)
		assert.False(t, handled)
	})
}
