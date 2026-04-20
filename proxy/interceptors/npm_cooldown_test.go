package interceptors

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setCooldownConfig(t *testing.T, cfg config.DependencyCooldownConfig) {
	t.Helper()
	orig := config.Get().Config.DependencyCooldown
	t.Cleanup(func() { config.Get().Config.DependencyCooldown = orig })
	config.Get().Config.DependencyCooldown = cfg
}

func mustParseURL(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic("mustParseURL: " + err.Error())
	}
	return u
}

func TestParseNpmMetadataTime(t *testing.T) {
	handler := newNpmCooldownHandler(nil)

	tests := []struct {
		name          string
		body          []byte
		expectedCount int
		expectError   bool
	}{
		{
			name: "valid metadata with 3 versions",
			body: []byte(`{
				"time": {
					"created": "2020-01-01T00:00:00.000Z",
					"modified": "2024-01-01T00:00:00.000Z",
					"1.0.0": "2020-06-01T00:00:00.000Z",
					"1.0.1": "2021-06-01T00:00:00.000Z",
					"1.0.2": "2022-06-01T00:00:00.000Z"
				}
			}`),
			expectedCount: 3,
		},
		{
			name:          "metadata without time field",
			body:          []byte(`{"name":"foo","version":"1.0.0"}`),
			expectedCount: 0,
		},
		{
			name:          "only skip keys",
			body:          []byte(`{"time":{"created":"2020-01-01T00:00:00.000Z","modified":"2024-01-01T00:00:00.000Z"}}`),
			expectedCount: 0,
		},
		{
			name:        "invalid JSON",
			body:        []byte(`not-json`),
			expectError: true,
		},
		{
			name: "unparseable dates skipped",
			body: []byte(`{
				"time": {
					"1.0.0": "not-a-date",
					"1.0.1": "2022-06-01T00:00:00.000Z"
				}
			}`),
			expectedCount: 1,
		},
		{
			name: "RFC3339 without millis",
			body: []byte(`{
				"time": {
					"1.0.0": "2022-06-01T00:00:00Z"
				}
			}`),
			expectedCount: 1,
		},
		{
			name: "millis precision",
			body: []byte(`{
				"time": {
					"1.0.0": "2022-06-01T00:00:00.000Z"
				}
			}`),
			expectedCount: 1,
		},
		{
			name:        "empty body",
			body:        []byte(``),
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dates, err := handler.parseMetadataTime(tc.body)
			if tc.expectError {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expectedCount, len(dates))
		})
	}
}

func TestParseNpmMetadataTime_CorrectDates(t *testing.T) {
	handler := newNpmCooldownHandler(nil)

	body := []byte(`{
		"time": {
			"created": "2021-01-01T00:00:00.000Z",
			"modified": "2024-01-01T00:00:00.000Z",
			"4.17.20": "2021-02-17T12:00:00.000Z",
			"4.17.21": "2021-05-19T12:00:00.000Z"
		}
	}`)

	dates, err := handler.parseMetadataTime(body)
	require.NoError(t, err)

	assert.Equal(t, 2, len(dates))

	d4_17_20, ok := dates["4.17.20"]
	require.True(t, ok, "expected 4.17.20 in dates")
	assert.Equal(t, 2021, d4_17_20.Year())
	assert.Equal(t, time.February, d4_17_20.Month())
	assert.Equal(t, 17, d4_17_20.Day())

	d4_17_21, ok := dates["4.17.21"]
	require.True(t, ok, "expected 4.17.21 in dates")
	assert.Equal(t, 2021, d4_17_21.Year())
	assert.Equal(t, time.May, d4_17_21.Month())
	assert.Equal(t, 19, d4_17_21.Day())

	_, hasCreated := dates["created"]
	assert.False(t, hasCreated)
	_, hasModified := dates["modified"]
	assert.False(t, hasModified)
}

func buildTestPackument(versions map[string]time.Time, distTags map[string]string) []byte {
	timeMap := map[string]string{
		"created":  "2020-01-01T00:00:00.000Z",
		"modified": "2024-01-01T00:00:00.000Z",
	}
	versionsMap := map[string]any{}
	for v, t := range versions {
		timeMap[v] = t.Format(time.RFC3339)
		versionsMap[v] = map[string]any{"version": v}
	}

	packument := map[string]any{
		"name":      "testpkg",
		"time":      timeMap,
		"versions":  versionsMap,
		"dist-tags": distTags,
	}
	b, _ := json.Marshal(packument)
	return b
}

func TestStripCooldownVersions_MixedVersions(t *testing.T) {
	handler := newNpmCooldownHandler(nil)
	now := time.Now()
	versions := map[string]time.Time{
		"1.0.0": now.Add(-30 * 24 * time.Hour), // old
		"1.0.1": now.Add(-10 * 24 * time.Hour), // old
		"1.0.2": now.Add(-1 * 24 * time.Hour),  // too new (within 5d cooldown)
	}
	distTags := map[string]string{"latest": "1.0.2"}
	body := buildTestPackument(versions, distTags)

	dates, err := handler.parseMetadataTime(body)
	require.NoError(t, err)

	newBody, stripped, remaining := handler.stripCooldownVersions(body, dates, 5)
	assert.Equal(t, 1, stripped)
	assert.Equal(t, 2, remaining)

	var result map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(newBody, &result))

	var resultVersions map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(result["versions"], &resultVersions))
	assert.NotContains(t, resultVersions, "1.0.2")
	assert.Contains(t, resultVersions, "1.0.0")
	assert.Contains(t, resultVersions, "1.0.1")

	var resultDistTags map[string]string
	require.NoError(t, json.Unmarshal(result["dist-tags"], &resultDistTags))
	// latest should be updated to an older eligible version
	assert.NotEqual(t, "1.0.2", resultDistTags["latest"])

	var resultTime map[string]string
	require.NoError(t, json.Unmarshal(result["time"], &resultTime))
	assert.Contains(t, resultTime, "created")
	assert.Contains(t, resultTime, "modified")
}

func TestStripCooldownVersions_AllVersionsTooNew(t *testing.T) {
	handler := newNpmCooldownHandler(nil)
	now := time.Now()
	versions := map[string]time.Time{
		"1.0.0": now.Add(-1 * 24 * time.Hour), // too new
		"1.0.1": now.Add(-2 * 24 * time.Hour), // too new
	}
	distTags := map[string]string{"latest": "1.0.1"}
	body := buildTestPackument(versions, distTags)

	dates, err := handler.parseMetadataTime(body)
	require.NoError(t, err)

	newBody, stripped, remaining := handler.stripCooldownVersions(body, dates, 5)
	assert.Equal(t, 2, stripped)
	assert.Equal(t, 0, remaining)

	var result map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(newBody, &result))

	var resultDistTags map[string]string
	require.NoError(t, json.Unmarshal(result["dist-tags"], &resultDistTags))
	// No eligible version exists, dist-tag should be removed
	assert.Empty(t, resultDistTags)
}

func TestStripCooldownVersions_NoVersionsTooNew(t *testing.T) {
	handler := newNpmCooldownHandler(nil)
	now := time.Now()
	versions := map[string]time.Time{
		"1.0.0": now.Add(-10 * 24 * time.Hour), // old enough
		"1.0.1": now.Add(-20 * 24 * time.Hour), // old enough
	}
	distTags := map[string]string{"latest": "1.0.0"}
	body := buildTestPackument(versions, distTags)

	dates, err := handler.parseMetadataTime(body)
	require.NoError(t, err)

	newBody, stripped, remaining := handler.stripCooldownVersions(body, dates, 5)
	assert.Equal(t, 0, stripped)
	assert.Equal(t, 2, remaining)
	assert.Equal(t, body, newBody) // body unchanged
}

func TestStripCooldownVersions_SingleVersionInCooldown(t *testing.T) {
	handler := newNpmCooldownHandler(nil)
	now := time.Now()
	versions := map[string]time.Time{
		"1.0.0": now.Add(-1 * 24 * time.Hour), // too new
	}
	distTags := map[string]string{"latest": "1.0.0"}
	body := buildTestPackument(versions, distTags)

	dates, err := handler.parseMetadataTime(body)
	require.NoError(t, err)

	_, stripped, remaining := handler.stripCooldownVersions(body, dates, 5)
	assert.Equal(t, 1, stripped)
	assert.Equal(t, 0, remaining)
}

func TestStripCooldownVersions_MalformedJSON(t *testing.T) {
	handler := newNpmCooldownHandler(nil)
	body := []byte(`not-json`)
	dates := map[string]time.Time{"1.0.0": time.Now().Add(-1 * time.Hour)}

	newBody, stripped, _ := handler.stripCooldownVersions(body, dates, 5)
	assert.Equal(t, 0, stripped)
	assert.Equal(t, body, newBody)
}

func makeTestRequestContext(rawURL string) *proxy.RequestContext {
	u := mustParseURL(rawURL)
	return &proxy.RequestContext{
		URL:       u,
		Method:    "GET",
		Headers:   http.Header{},
		Hostname:  u.Host,
		RequestID: "test-req-1",
		StartTime: time.Now(),
	}
}

func TestNpmCooldown_HandleMetadataRequest_OverridesHeaders(t *testing.T) {
	collector := NewAnalysisStatsCollector()
	handler := newNpmCooldownHandler(collector)

	ctx := makeTestRequestContext("https://registry.npmjs.org/lodash")
	ctx.Headers.Set("Accept", "application/vnd.npm.install-v1+json")
	ctx.Headers.Set("Accept-Encoding", "gzip")

	resp, err := handler.HandleMetadataRequest(ctx, "lodash", 5)
	require.NoError(t, err)
	assert.Equal(t, proxy.ActionModifyResponse, resp.Action)
	assert.Equal(t, "application/json", ctx.Headers.Get("Accept"))
	assert.Equal(t, "identity", ctx.Headers.Get("Accept-Encoding"))
	assert.Equal(t, "no-cache", ctx.Headers.Get("Cache-Control"))
}

func TestNpmCooldown_HandleMetadataRequest_StripsRecentVersions(t *testing.T) {
	now := time.Now()
	versions := map[string]time.Time{
		"1.0.0": now.Add(-30 * 24 * time.Hour), // old
		"1.0.1": now.Add(-1 * 24 * time.Hour),  // too new
	}
	distTags := map[string]string{"latest": "1.0.1"}
	body := buildTestPackument(versions, distTags)

	collector := NewAnalysisStatsCollector()
	handler := newNpmCooldownHandler(collector)
	ctx := makeTestRequestContext("https://registry.npmjs.org/testpkg")

	resp, err := handler.HandleMetadataRequest(ctx, "testpkg", 5)
	require.NoError(t, err)
	require.NotNil(t, resp.ResponseModifier)

	newStatus, newHeaders, newBody, err := resp.ResponseModifier(200, http.Header{}, body)
	require.NoError(t, err)
	assert.Equal(t, 200, newStatus)
	_ = newHeaders

	var result map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(newBody, &result))

	var resultVersions map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(result["versions"], &resultVersions))
	assert.Contains(t, resultVersions, "1.0.0")
	assert.NotContains(t, resultVersions, "1.0.1")

	var resultDistTags map[string]string
	require.NoError(t, json.Unmarshal(result["dist-tags"], &resultDistTags))
	assert.Equal(t, "1.0.0", resultDistTags["latest"])
}

func TestNpmCooldown_HandleMetadataRequest_NoVersionsInCooldown(t *testing.T) {
	now := time.Now()
	versions := map[string]time.Time{
		"1.0.0": now.Add(-30 * 24 * time.Hour), // old
		"1.0.1": now.Add(-20 * 24 * time.Hour), // old
	}
	distTags := map[string]string{"latest": "1.0.1"}
	body := buildTestPackument(versions, distTags)

	collector := NewAnalysisStatsCollector()
	handler := newNpmCooldownHandler(collector)
	ctx := makeTestRequestContext("https://registry.npmjs.org/testpkg")

	resp, err := handler.HandleMetadataRequest(ctx, "testpkg", 5)
	require.NoError(t, err)
	require.NotNil(t, resp.ResponseModifier)

	_, _, newBody, err := resp.ResponseModifier(200, http.Header{}, body)
	require.NoError(t, err)
	assert.Equal(t, body, newBody)
}

func TestNpmCooldown_HandleMetadataRequest_AllVersionsInCooldown_RecordsStats(t *testing.T) {
	now := time.Now()
	versions := map[string]time.Time{
		"1.0.0": now.Add(-1 * 24 * time.Hour), // too new
	}
	distTags := map[string]string{"latest": "1.0.0"}
	body := buildTestPackument(versions, distTags)

	collector := NewAnalysisStatsCollector()
	handler := newNpmCooldownHandler(collector)
	ctx := makeTestRequestContext("https://registry.npmjs.org/newpkg")

	resp, err := handler.HandleMetadataRequest(ctx, "newpkg", 5)
	require.NoError(t, err)
	require.NotNil(t, resp.ResponseModifier)

	_, _, _, err = resp.ResponseModifier(200, http.Header{}, body)
	require.NoError(t, err)

	blocks := collector.GetCooldownBlocks()
	require.Len(t, blocks, 1)
	assert.Equal(t, "newpkg", blocks[0].Name)
	assert.Equal(t, "1.0.0", blocks[0].Version)
	assert.Equal(t, 5, blocks[0].CooldownDays)

	stats := collector.GetStats()
	assert.Equal(t, 1, stats.CooldownBlockedCount)
	assert.Equal(t, 1, stats.BlockedCount)
}

func TestNpmCooldown_HandleMetadataRequest_AllVersionsInCooldown_ReportsOldestVersion(t *testing.T) {
	now := time.Now()
	versions := map[string]time.Time{
		"1.0.0": now.Add(-90 * 24 * time.Hour), // oldest — closest to exiting cooldown
		"2.0.0": now.Add(-30 * 24 * time.Hour),
		"2.1.0": now.Add(-1 * 24 * time.Hour), // newest — farthest from exiting cooldown
	}
	distTags := map[string]string{"latest": "2.1.0"}
	body := buildTestPackument(versions, distTags)

	collector := NewAnalysisStatsCollector()
	handler := newNpmCooldownHandler(collector)
	ctx := makeTestRequestContext("https://registry.npmjs.org/multipkg")

	resp, err := handler.HandleMetadataRequest(ctx, "multipkg", 100)
	require.NoError(t, err)

	_, _, _, err = resp.ResponseModifier(200, http.Header{}, body)
	require.NoError(t, err)

	blocks := collector.GetCooldownBlocks()
	require.Len(t, blocks, 1)
	assert.Equal(t, "1.0.0", blocks[0].Version, "should report oldest version (closest to exiting cooldown)")
}

func TestNpmCooldown_HandleMetadataRequest_MalformedJSON_FailOpen(t *testing.T) {
	body := []byte(`not-json`)
	collector := NewAnalysisStatsCollector()
	handler := newNpmCooldownHandler(collector)
	ctx := makeTestRequestContext("https://registry.npmjs.org/badpkg")

	resp, err := handler.HandleMetadataRequest(ctx, "badpkg", 5)
	require.NoError(t, err)
	require.NotNil(t, resp.ResponseModifier)

	_, _, newBody, err := resp.ResponseModifier(200, http.Header{}, body)
	require.NoError(t, err)
	assert.Equal(t, body, newBody)
}

func TestNpmCooldown_InterceptorDelegation_CooldownEnabled(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: true, Days: 5})

	interceptor := NewNpmRegistryInterceptor(nil, NewInMemoryAnalysisCache(), NewAnalysisStatsCollector(), make(chan *ConfirmationRequest, 1))

	ctx := makeTestRequestContext("https://registry.npmjs.org/lodash")
	ctx.Hostname = "registry.npmjs.org"
	ctx.Headers.Set("Accept", "application/vnd.npm.install-v1+json")

	resp, err := interceptor.HandleRequest(ctx)
	require.NoError(t, err)
	assert.Equal(t, proxy.ActionModifyResponse, resp.Action)
	assert.Equal(t, "application/json", ctx.Headers.Get("Accept"))
}

func TestNpmCooldown_InterceptorDelegation_CooldownDisabled(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: false, Days: 5})

	interceptor := NewNpmRegistryInterceptor(nil, NewInMemoryAnalysisCache(), NewAnalysisStatsCollector(), make(chan *ConfirmationRequest, 1))

	ctx := makeTestRequestContext("https://registry.npmjs.org/lodash")
	ctx.Hostname = "registry.npmjs.org"
	ctx.Headers.Set("Accept", "application/vnd.npm.install-v1+json")

	resp, err := interceptor.HandleRequest(ctx)
	require.NoError(t, err)
	assert.Equal(t, proxy.ActionAllow, resp.Action)
	// Accept header should NOT be modified when cooldown is disabled
	assert.Equal(t, "application/vnd.npm.install-v1+json", ctx.Headers.Get("Accept"))
}

func TestNpmCooldown_TarballRequestBypassesCooldown(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: true, Days: 5})

	// Use InsecureInstallation to skip the analyzer (which would fail without a real backend)
	origInsecure := config.Get().InsecureInstallation
	config.Get().InsecureInstallation = true
	t.Cleanup(func() { config.Get().InsecureInstallation = origInsecure })

	interceptor := NewNpmRegistryInterceptor(nil, NewInMemoryAnalysisCache(), NewAnalysisStatsCollector(), make(chan *ConfirmationRequest, 1))

	// Tarball URL has a version component
	ctx := makeTestRequestContext("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
	ctx.Hostname = "registry.npmjs.org"

	resp, err := interceptor.HandleRequest(ctx)
	require.NoError(t, err)
	// Tarball should be allowed (bypasses cooldown, goes to analysis)
	assert.Equal(t, proxy.ActionAllow, resp.Action)
	// Accept header should not be set to application/json for tarball requests
	assert.NotEqual(t, proxy.ActionModifyResponse, resp.Action)
}
