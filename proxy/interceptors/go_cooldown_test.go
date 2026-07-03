package interceptors

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/safedep/pmg/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGoCooldownCheckZipDownloadSideFetch(t *testing.T) {
	publishTime := time.Now().Add(-24 * time.Hour)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/example.com/fresh/@v/v1.1.0.info":
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(map[string]string{
				"Version": "v1.1.0",
				"Time":    publishTime.UTC().Format(time.RFC3339),
			})
			require.NoError(t, err)
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	ctx := &proxy.RequestContext{RequestID: "test"}

	t.Run("blocks using out-of-band publish time on cache miss", func(t *testing.T) {
		h := newGoCooldownHandler(NewAnalysisStatsCollector())

		resp, handled := h.CheckZipDownload(ctx, server.URL, "example.com/fresh", "v1.1.0", 7)
		require.True(t, handled)
		assert.Equal(t, proxy.ActionBlock, resp.Action)
		assert.Equal(t, http.StatusForbidden, resp.BlockCode)
	})

	t.Run("fails open when the out-of-band fetch fails", func(t *testing.T) {
		h := newGoCooldownHandler(NewAnalysisStatsCollector())

		_, handled := h.CheckZipDownload(ctx, server.URL, "example.com/unknown", "v9.9.9", 7)
		assert.False(t, handled)
	})

	t.Run("fails open without a base URL", func(t *testing.T) {
		h := newGoCooldownHandler(NewAnalysisStatsCollector())

		_, handled := h.CheckZipDownload(ctx, "", "example.com/fresh", "v1.1.0", 7)
		assert.False(t, handled)
	})
}
