package interceptors

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildTestPEP691Response builds a PEP 691 JSON Simple API response for testing.
// versions maps version string to upload time for a single .tar.gz file per version.
func buildTestPEP691Response(versions map[string]time.Time) []byte {
	type fileEntry struct {
		Filename   string            `json:"filename"`
		URL        string            `json:"url"`
		UploadTime string            `json:"upload-time"`
		Hashes     map[string]string `json:"hashes"`
	}

	files := make([]fileEntry, 0, len(versions))
	for version, t := range versions {
		files = append(files, fileEntry{
			Filename:   fmt.Sprintf("testpkg-%s.tar.gz", version),
			URL:        fmt.Sprintf("https://files.pythonhosted.org/packages/testpkg-%s.tar.gz", version),
			UploadTime: t.UTC().Format(time.RFC3339Nano),
			Hashes:     map[string]string{"sha256": "abc123"},
		})
	}

	resp := map[string]any{
		"meta":  map[string]string{"api-version": "1.0"},
		"name":  "testpkg",
		"files": files,
	}
	b, _ := json.Marshal(resp)
	return b
}

func TestParsePEP691Files_ValidResponse(t *testing.T) {
	handler := newPypiCooldownHandler(nil)
	now := time.Now().UTC().Truncate(time.Second)
	day := 24 * time.Hour

	versions := map[string]time.Time{
		"1.0.0": now.Add(-30 * day),
		"2.0.0": now.Add(-10 * day),
	}
	body := buildTestPEP691Response(versions)

	dates, err := handler.parsePEP691Files(body)
	require.NoError(t, err)
	assert.Len(t, dates, 2)
	assert.Contains(t, dates, "1.0.0")
	assert.Contains(t, dates, "2.0.0")
}

func TestParsePEP691Files_MultipleFilesPerVersion(t *testing.T) {
	handler := newPypiCooldownHandler(nil)
	now := time.Now().UTC().Truncate(time.Second)
	day := 24 * time.Hour

	// Two files for 1.0.0: sdist uploaded 5 days ago, wheel uploaded 3 days ago.
	// parsePEP691Files must use the earliest (5 days ago).
	sdistTime := now.Add(-5 * day)
	wheelTime := now.Add(-3 * day)

	body, _ := json.Marshal(map[string]any{
		"meta": map[string]string{"api-version": "1.0"},
		"name": "testpkg",
		"files": []map[string]any{
			{
				"filename":    "testpkg-1.0.0.tar.gz",
				"url":         "https://files.pythonhosted.org/packages/testpkg-1.0.0.tar.gz",
				"upload-time": sdistTime.Format(time.RFC3339Nano),
				"hashes":      map[string]string{"sha256": "abc"},
			},
			{
				"filename":    "testpkg-1.0.0-py3-none-any.whl",
				"url":         "https://files.pythonhosted.org/packages/testpkg-1.0.0-py3-none-any.whl",
				"upload-time": wheelTime.Format(time.RFC3339Nano),
				"hashes":      map[string]string{"sha256": "def"},
			},
		},
	})

	dates, err := handler.parsePEP691Files(body)
	require.NoError(t, err)
	require.Contains(t, dates, "1.0.0")
	// Should use the earliest upload-time (sdist, 5 days ago)
	assert.WithinDuration(t, sdistTime, dates["1.0.0"], time.Second)
}

func TestParsePEP691Files_MissingUploadTime(t *testing.T) {
	handler := newPypiCooldownHandler(nil)

	body, _ := json.Marshal(map[string]any{
		"meta": map[string]string{"api-version": "1.0"},
		"name": "testpkg",
		"files": []map[string]any{
			{
				"filename": "testpkg-1.0.0.tar.gz",
				"url":      "https://files.pythonhosted.org/packages/testpkg-1.0.0.tar.gz",
				"hashes":   map[string]string{"sha256": "abc"},
			},
			{
				"filename":    "testpkg-2.0.0.tar.gz",
				"url":         "https://files.pythonhosted.org/packages/testpkg-2.0.0.tar.gz",
				"upload-time": time.Now().Add(-10 * 24 * time.Hour).UTC().Format(time.RFC3339Nano),
				"hashes":      map[string]string{"sha256": "def"},
			},
		},
	})

	dates, err := handler.parsePEP691Files(body)
	require.NoError(t, err)
	assert.NotContains(t, dates, "1.0.0")
	assert.Contains(t, dates, "2.0.0")
}

func TestParsePEP691Files_YankedFiles(t *testing.T) {
	handler := newPypiCooldownHandler(nil)
	now := time.Now().UTC()

	body, _ := json.Marshal(map[string]any{
		"meta": map[string]string{"api-version": "1.0"},
		"name": "testpkg",
		"files": []map[string]any{
			{
				"filename":    "testpkg-1.0.0.tar.gz",
				"url":         "https://files.pythonhosted.org/packages/testpkg-1.0.0.tar.gz",
				"upload-time": now.Add(-2 * 24 * time.Hour).Format(time.RFC3339Nano),
				"hashes":      map[string]string{"sha256": "abc"},
				"yanked":      true,
			},
		},
	})

	dates, err := handler.parsePEP691Files(body)
	require.NoError(t, err)
	// Yanked file is still parsed — cooldown applies, pip handles yanked behaviour
	assert.Contains(t, dates, "1.0.0")
}

func TestParsePEP691Files_InvalidJSON(t *testing.T) {
	handler := newPypiCooldownHandler(nil)
	_, err := handler.parsePEP691Files([]byte(`not-json`))
	assert.Error(t, err)
}

func TestParsePEP691Files_EmptyFiles(t *testing.T) {
	handler := newPypiCooldownHandler(nil)
	body, _ := json.Marshal(map[string]any{
		"meta":  map[string]string{"api-version": "1.0"},
		"name":  "testpkg",
		"files": []any{},
	})

	dates, err := handler.parsePEP691Files(body)
	require.NoError(t, err)
	assert.Empty(t, dates)
}

func TestStripCooldownFiles_MixedVersions(t *testing.T) {
	handler := newPypiCooldownHandler(nil)
	now := time.Now()
	day := 24 * time.Hour

	versions := map[string]time.Time{
		"1.0.0": now.Add(-30 * day), // old — eligible
		"2.0.0": now.Add(-1 * day),  // too new (5d cooldown)
	}
	body := buildTestPEP691Response(versions)

	dates, err := handler.parsePEP691Files(body)
	require.NoError(t, err)

	newBody, stripped, remaining := handler.stripCooldownFiles(body, dates, 5)
	assert.Equal(t, 1, stripped)
	assert.Equal(t, 1, remaining)

	var result struct {
		Files []struct {
			Filename string `json:"filename"`
		} `json:"files"`
	}
	require.NoError(t, json.Unmarshal(newBody, &result))

	filenames := make([]string, 0, len(result.Files))
	for _, f := range result.Files {
		filenames = append(filenames, f.Filename)
	}
	assert.Contains(t, filenames, "testpkg-1.0.0.tar.gz")
	assert.NotContains(t, filenames, "testpkg-2.0.0.tar.gz")
}

func TestStripCooldownFiles_AllVersionsTooNew(t *testing.T) {
	handler := newPypiCooldownHandler(nil)
	now := time.Now()
	day := 24 * time.Hour

	versions := map[string]time.Time{
		"1.0.0": now.Add(-1 * day),
		"2.0.0": now.Add(-2 * day),
	}
	body := buildTestPEP691Response(versions)

	dates, err := handler.parsePEP691Files(body)
	require.NoError(t, err)

	newBody, stripped, remaining := handler.stripCooldownFiles(body, dates, 5)
	assert.Equal(t, 2, stripped)
	assert.Equal(t, 0, remaining)

	var result struct {
		Files []json.RawMessage `json:"files"`
	}
	require.NoError(t, json.Unmarshal(newBody, &result))
	assert.Empty(t, result.Files)
}

func TestStripCooldownFiles_NoVersionsTooNew(t *testing.T) {
	handler := newPypiCooldownHandler(nil)
	now := time.Now()
	day := 24 * time.Hour

	versions := map[string]time.Time{
		"1.0.0": now.Add(-10 * day),
		"2.0.0": now.Add(-20 * day),
	}
	body := buildTestPEP691Response(versions)

	dates, err := handler.parsePEP691Files(body)
	require.NoError(t, err)

	newBody, stripped, remaining := handler.stripCooldownFiles(body, dates, 5)
	assert.Equal(t, 0, stripped)
	assert.Equal(t, 2, remaining)
	assert.Equal(t, body, newBody)
}

func TestStripCooldownFiles_SingleVersionInCooldown(t *testing.T) {
	handler := newPypiCooldownHandler(nil)
	now := time.Now()

	versions := map[string]time.Time{
		"1.0.0": now.Add(-1 * 24 * time.Hour),
	}
	body := buildTestPEP691Response(versions)

	dates, err := handler.parsePEP691Files(body)
	require.NoError(t, err)

	_, stripped, remaining := handler.stripCooldownFiles(body, dates, 5)
	assert.Equal(t, 1, stripped)
	assert.Equal(t, 0, remaining)
}

func TestStripCooldownFiles_MultipleFilesPerVersion_AllStripped(t *testing.T) {
	handler := newPypiCooldownHandler(nil)
	now := time.Now()

	body, _ := json.Marshal(map[string]any{
		"meta": map[string]string{"api-version": "1.0"},
		"name": "testpkg",
		"files": []map[string]any{
			{
				"filename":    "testpkg-1.0.0.tar.gz",
				"url":         "https://files.pythonhosted.org/packages/testpkg-1.0.0.tar.gz",
				"upload-time": now.Add(-1 * 24 * time.Hour).UTC().Format(time.RFC3339Nano),
				"hashes":      map[string]string{"sha256": "abc"},
			},
			{
				"filename":    "testpkg-1.0.0-py3-none-any.whl",
				"url":         "https://files.pythonhosted.org/packages/testpkg-1.0.0-py3-none-any.whl",
				"upload-time": now.Add(-2 * 24 * time.Hour).UTC().Format(time.RFC3339Nano),
				"hashes":      map[string]string{"sha256": "def"},
			},
		},
	})

	dates, err := handler.parsePEP691Files(body)
	require.NoError(t, err)

	newBody, stripped, remaining := handler.stripCooldownFiles(body, dates, 5)
	assert.Equal(t, 1, stripped)  // 1 version stripped
	assert.Equal(t, 0, remaining)

	var result struct {
		Files []json.RawMessage `json:"files"`
	}
	require.NoError(t, json.Unmarshal(newBody, &result))
	assert.Empty(t, result.Files) // both files (sdist + wheel) removed
}

func TestStripCooldownFiles_MalformedJSON(t *testing.T) {
	handler := newPypiCooldownHandler(nil)
	body := []byte(`not-json`)
	dates := map[string]time.Time{"1.0.0": time.Now().Add(-1 * time.Hour)}

	newBody, stripped, _ := handler.stripCooldownFiles(body, dates, 5)
	assert.Equal(t, 0, stripped)
	assert.Equal(t, body, newBody)
}

func TestStripCooldownFiles_UnparseableFilename_KeepFile(t *testing.T) {
	handler := newPypiCooldownHandler(nil)
	now := time.Now()

	// .egg is an unsupported extension — parseFilename will fail
	// The file must be kept (fail-open), not stripped
	body, _ := json.Marshal(map[string]any{
		"meta": map[string]string{"api-version": "1.0"},
		"name": "testpkg",
		"files": []map[string]any{
			{
				"filename":    "testpkg-1.0.0.egg",
				"url":         "https://files.pythonhosted.org/packages/testpkg-1.0.0.egg",
				"upload-time": now.Add(-1 * 24 * time.Hour).UTC().Format(time.RFC3339Nano),
				"hashes":      map[string]string{"sha256": "abc"},
			},
		},
	})

	// parsePEP691Files will skip the .egg file (no version extracted),
	// so dates will be empty — nothing to strip
	dates, err := handler.parsePEP691Files(body)
	require.NoError(t, err)
	assert.Empty(t, dates)

	// Force tooNew to include a version that matches nothing, to exercise the
	// stripCooldownFiles path with a non-empty tooNew map
	forcedDates := map[string]time.Time{
		"1.0.0": now.Add(-1 * 24 * time.Hour),
	}
	newBody, stripped, _ := handler.stripCooldownFiles(body, forcedDates, 5)
	assert.Equal(t, 1, stripped) // version is "stripped" from the date map perspective

	var result struct {
		Files []json.RawMessage `json:"files"`
	}
	require.NoError(t, json.Unmarshal(newBody, &result))
	// The .egg file must still be present — unparseable filename means fail-open
	assert.Len(t, result.Files, 1)
}

func TestPyPICooldown_HandleMetadataRequest_OverridesHeaders(t *testing.T) {
	handler := newPypiCooldownHandler(nil)
	ctx := makeTestRequestContext("https://pypi.org/simple/requests/")
	ctx.Headers.Set("Accept", "text/html")
	ctx.Headers.Set("Accept-Encoding", "gzip")

	resp, err := handler.HandleMetadataRequest(ctx, "requests", 5)
	require.NoError(t, err)
	assert.Equal(t, proxy.ActionModifyResponse, resp.Action)
	assert.Equal(t, "application/vnd.pypi.simple.v1+json", ctx.Headers.Get("Accept"))
	assert.Equal(t, "identity", ctx.Headers.Get("Accept-Encoding"))
}

func TestPyPICooldown_HandleMetadataRequest_NonJSONResponse_FailOpen(t *testing.T) {
	handler := newPypiCooldownHandler(nil)
	ctx := makeTestRequestContext("https://pypi.org/simple/requests/")

	resp, err := handler.HandleMetadataRequest(ctx, "requests", 5)
	require.NoError(t, err)
	require.NotNil(t, resp.ResponseModifier)

	htmlBody := []byte(`<!DOCTYPE html><html><body><a href="/packages/requests-2.31.0.tar.gz">requests-2.31.0.tar.gz</a></body></html>`)
	headers := http.Header{}
	headers.Set("Content-Type", "text/html")

	_, retHeaders, retBody, err := resp.ResponseModifier(200, headers, htmlBody)
	require.NoError(t, err)
	assert.Equal(t, htmlBody, retBody)
	assert.NotEqual(t, "no-store", retHeaders.Get("Cache-Control"))
}

func TestPyPICooldown_HandleMetadataRequest_StripsRecentVersions(t *testing.T) {
	now := time.Now()
	day := 24 * time.Hour
	versions := map[string]time.Time{
		"1.0.0": now.Add(-30 * day),
		"2.0.0": now.Add(-1 * day),
	}
	body := buildTestPEP691Response(versions)

	handler := newPypiCooldownHandler(NewAnalysisStatsCollector())
	ctx := makeTestRequestContext("https://pypi.org/simple/testpkg/")

	resp, err := handler.HandleMetadataRequest(ctx, "testpkg", 5)
	require.NoError(t, err)
	require.NotNil(t, resp.ResponseModifier)

	headers := http.Header{}
	headers.Set("Content-Type", "application/vnd.pypi.simple.v1+json")

	_, retHeaders, retBody, err := resp.ResponseModifier(200, headers, body)
	require.NoError(t, err)
	assert.Equal(t, "no-store", retHeaders.Get("Cache-Control"))

	var result struct {
		Files []struct {
			Filename string `json:"filename"`
		} `json:"files"`
	}
	require.NoError(t, json.Unmarshal(retBody, &result))

	filenames := make([]string, 0, len(result.Files))
	for _, f := range result.Files {
		filenames = append(filenames, f.Filename)
	}
	assert.Contains(t, filenames, "testpkg-1.0.0.tar.gz")
	assert.NotContains(t, filenames, "testpkg-2.0.0.tar.gz")
}

func TestPyPICooldown_HandleMetadataRequest_AllVersionsInCooldown_RecordsStats(t *testing.T) {
	now := time.Now()
	versions := map[string]time.Time{
		"1.0.0": now.Add(-1 * 24 * time.Hour),
	}
	body := buildTestPEP691Response(versions)

	collector := NewAnalysisStatsCollector()
	handler := newPypiCooldownHandler(collector)
	ctx := makeTestRequestContext("https://pypi.org/simple/newpkg/")

	resp, err := handler.HandleMetadataRequest(ctx, "newpkg", 5)
	require.NoError(t, err)
	require.NotNil(t, resp.ResponseModifier)

	headers := http.Header{}
	headers.Set("Content-Type", "application/vnd.pypi.simple.v1+json")

	_, _, _, err = resp.ResponseModifier(200, headers, body)
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

func TestPyPICooldown_HandleMetadataRequest_NoVersionsInCooldown_BodyUnchanged(t *testing.T) {
	now := time.Now()
	day := 24 * time.Hour
	versions := map[string]time.Time{
		"1.0.0": now.Add(-30 * day),
		"2.0.0": now.Add(-20 * day),
	}
	body := buildTestPEP691Response(versions)

	handler := newPypiCooldownHandler(nil)
	ctx := makeTestRequestContext("https://pypi.org/simple/testpkg/")

	resp, err := handler.HandleMetadataRequest(ctx, "testpkg", 5)
	require.NoError(t, err)
	require.NotNil(t, resp.ResponseModifier)

	headers := http.Header{}
	headers.Set("Content-Type", "application/vnd.pypi.simple.v1+json")

	_, _, retBody, err := resp.ResponseModifier(200, headers, body)
	require.NoError(t, err)
	assert.Equal(t, body, retBody)
}

func TestPyPICooldown_HandleMetadataRequest_MalformedJSON_FailOpen(t *testing.T) {
	handler := newPypiCooldownHandler(nil)
	ctx := makeTestRequestContext("https://pypi.org/simple/badpkg/")

	resp, err := handler.HandleMetadataRequest(ctx, "badpkg", 5)
	require.NoError(t, err)
	require.NotNil(t, resp.ResponseModifier)

	body := []byte(`not-json`)
	headers := http.Header{}
	headers.Set("Content-Type", "application/vnd.pypi.simple.v1+json")

	_, _, retBody, err := resp.ResponseModifier(200, headers, body)
	require.NoError(t, err)
	assert.Equal(t, body, retBody)
}

func TestPyPICooldown_InterceptorDelegation_CooldownEnabled(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: true, Days: 5})

	interceptor := NewPypiRegistryInterceptor(nil, NewInMemoryAnalysisCache(), NewAnalysisStatsCollector(), make(chan *ConfirmationRequest, 1))

	ctx := makeTestRequestContext("https://pypi.org/simple/requests/")
	ctx.Hostname = "pypi.org"
	ctx.Headers.Set("Accept", "text/html")

	resp, err := interceptor.HandleRequest(ctx)
	require.NoError(t, err)
	assert.Equal(t, proxy.ActionModifyResponse, resp.Action)
	assert.Equal(t, "application/vnd.pypi.simple.v1+json", ctx.Headers.Get("Accept"))
}

func TestPyPICooldown_InterceptorDelegation_CooldownDisabled(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: false, Days: 5})

	interceptor := NewPypiRegistryInterceptor(nil, NewInMemoryAnalysisCache(), NewAnalysisStatsCollector(), make(chan *ConfirmationRequest, 1))

	ctx := makeTestRequestContext("https://pypi.org/simple/requests/")
	ctx.Hostname = "pypi.org"
	ctx.Headers.Set("Accept", "text/html")

	resp, err := interceptor.HandleRequest(ctx)
	require.NoError(t, err)
	assert.Equal(t, proxy.ActionAllow, resp.Action)
	assert.Equal(t, "text/html", ctx.Headers.Get("Accept"))
}

func TestPyPICooldown_JSONAPIRequest_NotIntercepted(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: true, Days: 5})

	interceptor := NewPypiRegistryInterceptor(nil, NewInMemoryAnalysisCache(), NewAnalysisStatsCollector(), make(chan *ConfirmationRequest, 1))

	ctx := makeTestRequestContext("https://pypi.org/pypi/requests/json")
	ctx.Hostname = "pypi.org"
	ctx.Headers.Set("Accept", "application/json")

	resp, err := interceptor.HandleRequest(ctx)
	require.NoError(t, err)
	assert.Equal(t, proxy.ActionAllow, resp.Action)
	assert.Equal(t, "application/json", ctx.Headers.Get("Accept"))
}

func TestPyPICooldown_FileDownloadBypassesCooldown(t *testing.T) {
	setCooldownConfig(t, config.DependencyCooldownConfig{Enabled: true, Days: 5})

	origInsecure := config.Get().InsecureInstallation
	config.Get().InsecureInstallation = true
	t.Cleanup(func() { config.Get().InsecureInstallation = origInsecure })

	interceptor := NewPypiRegistryInterceptor(nil, NewInMemoryAnalysisCache(), NewAnalysisStatsCollector(), make(chan *ConfirmationRequest, 1))

	ctx := makeTestRequestContext("https://files.pythonhosted.org/packages/ab/cd/ef/requests-2.31.0-py3-none-any.whl")
	ctx.Hostname = "files.pythonhosted.org"

	resp, err := interceptor.HandleRequest(ctx)
	require.NoError(t, err)
	assert.NotEqual(t, proxy.ActionModifyResponse, resp.Action)
	assert.NotEqual(t, "application/vnd.pypi.simple.v1+json", ctx.Headers.Get("Accept"))
}
