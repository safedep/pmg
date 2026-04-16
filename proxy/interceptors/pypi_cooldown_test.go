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

var (
	_ = config.DependencyCooldownConfig{}
	_ = proxy.ActionAllow
	_ = http.Header{}
)
