package interceptors

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setCooldownConfig sets the global cooldown config for the duration of a test
// and restores the original value via t.Cleanup.
func setCooldownConfig(t *testing.T, cfg config.DependencyCooldownConfig) {
	t.Helper()
	orig := config.Get().Config.DependencyCooldown
	t.Cleanup(func() { config.Get().Config.DependencyCooldown = orig })
	config.Get().Config.DependencyCooldown = cfg
}

// TestParseNpmMetadataTime verifies that publish dates are correctly extracted from
// the "time" field of NPM package metadata, with skip keys omitted.
func TestParseNpmMetadataTime(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		expectCount int
		expectErr   bool
	}{
		{
			name: "valid metadata with multiple versions",
			body: `{
				"name": "lodash",
				"time": {
					"created":  "2012-04-23T16:52:34.248Z",
					"modified": "2024-01-15T10:30:00.000Z",
					"1.0.0":    "2012-04-23T16:52:34.248Z",
					"2.0.0":    "2013-05-10T12:00:00.000Z",
					"4.17.21":  "2021-02-20T15:42:16.000Z"
				}
			}`,
			expectCount: 3,
			expectErr:   false,
		},
		{
			name:        "metadata without time field",
			body:        `{"name": "lodash"}`,
			expectCount: 0,
			expectErr:   false,
		},
		{
			name: "only skip keys present in time",
			body: `{
				"time": {
					"created":  "2012-04-23T16:52:34.248Z",
					"modified": "2024-01-15T10:30:00.000Z"
				}
			}`,
			expectCount: 0,
			expectErr:   false,
		},
		{
			name:        "invalid JSON body",
			body:        `not valid json`,
			expectCount: 0,
			expectErr:   true,
		},
		{
			name: "unparseable date values are skipped",
			body: `{
				"time": {
					"1.0.0": "2024-01-15T10:30:00.000Z",
					"2.0.0": "not-a-date-at-all"
				}
			}`,
			expectCount: 1,
			expectErr:   false,
		},
		{
			name: "RFC3339 format without milliseconds is accepted",
			body: `{
				"time": {
					"1.0.0": "2024-01-15T10:30:00Z"
				}
			}`,
			expectCount: 1,
			expectErr:   false,
		},
		{
			name: "millisecond precision format is accepted",
			body: `{
				"time": {
					"1.0.0": "2024-01-15T10:30:00.000Z"
				}
			}`,
			expectCount: 1,
			expectErr:   false,
		},
		{
			name:        "empty body",
			body:        ``,
			expectCount: 0,
			expectErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dates, err := parseNpmMetadataTime([]byte(tt.body))
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Len(t, dates, tt.expectCount)
			}
		})
	}
}

// TestParseNpmMetadataTime_CorrectDates verifies that the parsed dates match the
// exact timestamps from the metadata JSON.
func TestParseNpmMetadataTime_CorrectDates(t *testing.T) {
	body := `{
		"name": "lodash",
		"time": {
			"created":  "2012-04-23T16:52:34.248Z",
			"modified": "2024-01-15T10:30:00.000Z",
			"4.17.20":  "2021-01-07T14:24:45.000Z",
			"4.17.21":  "2021-02-20T15:42:16.000Z"
		}
	}`

	dates, err := parseNpmMetadataTime([]byte(body))
	require.NoError(t, err)
	require.Len(t, dates, 2)

	expected4_17_20, err := time.Parse("2006-01-02T15:04:05.000Z", "2021-01-07T14:24:45.000Z")
	require.NoError(t, err)
	assert.Equal(t, expected4_17_20, dates["4.17.20"])

	expected4_17_21, err := time.Parse("2006-01-02T15:04:05.000Z", "2021-02-20T15:42:16.000Z")
	require.NoError(t, err)
	assert.Equal(t, expected4_17_21, dates["4.17.21"])

	_, hasCreated := dates["created"]
	assert.False(t, hasCreated, "created key must be skipped")

	_, hasModified := dates["modified"]
	assert.False(t, hasModified, "modified key must be skipped")
}

// TestNpmCooldown_BlocksRecentPackage verifies that a metadata response for a package
// with a recently published version strips that version from the response.
func TestNpmCooldown_BlocksRecentPackage(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: true, Days: 5})

	interceptor := NewNpmRegistryInterceptor(nil, NewInMemoryAnalysisCache(), nil, nil)

	ctx := &proxy.RequestContext{
		Hostname: "registry.npmjs.org",
		URL:      mustParseURL("https://registry.npmjs.org/lodash"),
	}

	resp, err := interceptor.HandleRequest(ctx)
	require.NoError(t, err)
	require.Equal(t, proxy.ActionModifyResponse, resp.Action)

	recentDate := time.Now().Add(-2 * 24 * time.Hour).UTC().Format(time.RFC3339)
	body, _ := json.Marshal(map[string]any{
		"name":      "lodash",
		"dist-tags": map[string]string{"latest": "4.18.0"},
		"versions":  map[string]any{"4.17.21": map[string]string{"version": "4.17.21"}, "4.18.0": map[string]string{"version": "4.18.0"}},
		"time":      map[string]string{"4.17.21": "2021-02-20T15:42:16.000Z", "4.18.0": recentDate},
	})

	_, _, outBody, err := resp.ResponseModifier(http.StatusOK, http.Header{}, body)
	require.NoError(t, err)

	var result map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(outBody, &result))

	var versions map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(result["versions"], &versions))
	assert.NotContains(t, versions, "4.18.0", "recent version should be stripped")
	assert.Contains(t, versions, "4.17.21")

	var distTags map[string]string
	require.NoError(t, json.Unmarshal(result["dist-tags"], &distTags))
	assert.Equal(t, "4.17.21", distTags["latest"], "dist-tags.latest should point to oldest eligible version")
}

// TestNpmCooldown_AllowsOldPackage verifies that a metadata response with no versions
// in the cooldown window is returned unchanged.
func TestNpmCooldown_AllowsOldPackage(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: true, Days: 5})

	interceptor := NewNpmRegistryInterceptor(nil, NewInMemoryAnalysisCache(), nil, nil)

	ctx := &proxy.RequestContext{
		Hostname: "registry.npmjs.org",
		URL:      mustParseURL("https://registry.npmjs.org/lodash"),
	}

	resp, err := interceptor.HandleRequest(ctx)
	require.NoError(t, err)
	require.Equal(t, proxy.ActionModifyResponse, resp.Action)

	body, _ := json.Marshal(map[string]any{
		"name":      "lodash",
		"dist-tags": map[string]string{"latest": "4.17.21"},
		"versions":  map[string]any{"4.17.21": map[string]string{"version": "4.17.21"}},
		"time":      map[string]string{"4.17.21": "2021-02-20T15:42:16.000Z"},
	})

	_, _, outBody, err := resp.ResponseModifier(http.StatusOK, http.Header{}, body)
	require.NoError(t, err)
	assert.Equal(t, body, outBody, "body should be unchanged when no versions are in cooldown")
}

// TestNpmCooldown_DisabledByConfig verifies that when cooldown is disabled, metadata
// requests are allowed through without modification.
func TestNpmCooldown_DisabledByConfig(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: false, Days: 5})

	interceptor := NewNpmRegistryInterceptor(nil, NewInMemoryAnalysisCache(), nil, nil)

	ctx := &proxy.RequestContext{
		Hostname: "registry.npmjs.org",
		URL:      mustParseURL("https://registry.npmjs.org/lodash"),
	}

	resp, err := interceptor.HandleRequest(ctx)
	require.NoError(t, err)
	// Cooldown disabled: metadata requests must be allowed through without a modifier
	assert.Equal(t, proxy.ActionAllow, resp.Action)
	assert.Nil(t, resp.ResponseModifier)
}

// TestNpmCooldown_MetadataResponseRegistersModifier verifies that a metadata request
// when cooldown is enabled returns ActionModifyResponse with a modifier set.
func TestNpmCooldown_MetadataResponseRegistersModifier(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: true, Days: 5})

	interceptor := NewNpmRegistryInterceptor(nil, NewInMemoryAnalysisCache(), nil, nil)

	ctx := &proxy.RequestContext{
		Hostname: "registry.npmjs.org",
		URL:      mustParseURL("https://registry.npmjs.org/lodash"),
	}

	resp, err := interceptor.HandleRequest(ctx)
	require.NoError(t, err)
	assert.Equal(t, proxy.ActionModifyResponse, resp.Action)
	assert.NotNil(t, resp.ResponseModifier, "response modifier must be set for metadata requests when cooldown is enabled")
}

// TestNpmCooldown_MetadataStripsRecentVersions verifies that the metadata modifier
// removes versions within the cooldown window from "versions", "time", and fixes "dist-tags".
// This is the key behavior for npm update: npm's resolver never sees the too-new versions
// and naturally falls back to the latest eligible version.
func TestNpmCooldown_MetadataStripsRecentVersions(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: true, Days: 5})

	interceptor := NewNpmRegistryInterceptor(nil, NewInMemoryAnalysisCache(), NewAnalysisStatsCollector(), nil)

	ctx := &proxy.RequestContext{
		Hostname: "registry.npmjs.org",
		URL:      mustParseURL("https://registry.npmjs.org/some-pkg"),
	}

	resp, err := interceptor.HandleRequest(ctx)
	require.NoError(t, err)
	require.NotNil(t, resp.ResponseModifier)

	// Build metadata where 1.3.0 was published 1 day ago (within cooldown)
	recentDate := time.Now().Add(-1 * 24 * time.Hour).UTC().Format("2006-01-02T15:04:05.000Z")
	oldDate := "2024-01-15T10:30:00.000Z"

	metadata := map[string]interface{}{
		"name": "some-pkg",
		"dist-tags": map[string]string{
			"latest": "1.3.0",
		},
		"time": map[string]string{
			"created":  "2023-01-01T00:00:00.000Z",
			"modified": recentDate,
			"1.0.0":    oldDate,
			"1.2.0":    "2024-06-01T00:00:00.000Z",
			"1.3.0":    recentDate,
		},
		"versions": map[string]interface{}{
			"1.0.0": map[string]string{"version": "1.0.0"},
			"1.2.0": map[string]string{"version": "1.2.0"},
			"1.3.0": map[string]string{"version": "1.3.0"},
		},
	}
	body, err := json.Marshal(metadata)
	require.NoError(t, err)

	_, _, outBody, modErr := resp.ResponseModifier(http.StatusOK, http.Header{}, body)
	require.NoError(t, modErr)

	// Parse the modified body
	var result map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(outBody, &result))

	// 1.3.0 should be stripped from "versions"
	var versions map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(result["versions"], &versions))
	assert.Contains(t, versions, "1.0.0")
	assert.Contains(t, versions, "1.2.0")
	assert.NotContains(t, versions, "1.3.0", "1.3.0 should be stripped from versions")

	// 1.3.0 should be stripped from "time"
	var timeMap map[string]string
	require.NoError(t, json.Unmarshal(result["time"], &timeMap))
	assert.Contains(t, timeMap, "1.0.0")
	assert.Contains(t, timeMap, "1.2.0")
	assert.NotContains(t, timeMap, "1.3.0", "1.3.0 should be stripped from time")
	assert.Contains(t, timeMap, "created", "created should be preserved")

	// dist-tags.latest should be updated to 1.2.0 (latest non-cooldown version)
	var distTags map[string]string
	require.NoError(t, json.Unmarshal(result["dist-tags"], &distTags))
	assert.Equal(t, "1.2.0", distTags["latest"], "dist-tags.latest should point to latest non-cooldown version")

}

// TestStripCooldownVersions_AllVersionsTooNew verifies behavior when every version
// is within the cooldown window — all versions are stripped.
func TestStripCooldownVersions_AllVersionsTooNew(t *testing.T) {
	now := time.Now()
	dates := map[string]time.Time{
		"1.0.0": now.Add(-1 * 24 * time.Hour),
		"1.1.0": now.Add(-2 * 24 * time.Hour),
	}

	body, _ := json.Marshal(map[string]interface{}{
		"name": "new-pkg",
		"dist-tags": map[string]string{
			"latest": "1.1.0",
		},
		"versions": map[string]interface{}{
			"1.0.0": map[string]string{"version": "1.0.0"},
			"1.1.0": map[string]string{"version": "1.1.0"},
		},
		"time": map[string]string{
			"1.0.0": now.Add(-1 * 24 * time.Hour).Format(time.RFC3339),
			"1.1.0": now.Add(-2 * 24 * time.Hour).Format(time.RFC3339),
		},
	})

	result, stripped, remaining := stripCooldownVersions(body, dates, 5)
	assert.Equal(t, 2, stripped)
	assert.Equal(t, 0, remaining)

	var parsed map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(result, &parsed))

	var versions map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(parsed["versions"], &versions))
	assert.Empty(t, versions, "all versions should be stripped")

	// dist-tags should be empty since no eligible version exists
	var distTags map[string]string
	require.NoError(t, json.Unmarshal(parsed["dist-tags"], &distTags))
	assert.Empty(t, distTags)
}

// TestStripCooldownVersions_NoVersionsTooNew verifies that when no versions are
// within the cooldown window, the body is returned unchanged.
func TestStripCooldownVersions_NoVersionsTooNew(t *testing.T) {
	dates := map[string]time.Time{
		"1.0.0": time.Now().Add(-30 * 24 * time.Hour),
		"1.1.0": time.Now().Add(-20 * 24 * time.Hour),
	}

	body := []byte(`{"name":"pkg","versions":{"1.0.0":{},"1.1.0":{}},"time":{"1.0.0":"2024-01-01T00:00:00Z","1.1.0":"2024-02-01T00:00:00Z"}}`)

	result, stripped, remaining := stripCooldownVersions(body, dates, 5)
	assert.Equal(t, 0, stripped)
	assert.Equal(t, 2, remaining)
	assert.Equal(t, body, result, "body should be unchanged when no versions are in cooldown")
}


func mustParseURL(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		log.Errorf("mustParseURL: %s" + err.Error())
		return nil
	}

	return u
}
