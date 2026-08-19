package interceptors

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPypiCustomParser_ParseURL(t *testing.T) {
	tests := []struct {
		name             string
		baseEndsInSimple bool
		urlPath          string
		wantErr          bool
		wantName         string
		wantVersion      string
		wantIsDownload   bool
	}{
		{
			name:             "single project segment below a /simple-ending base is Simple metadata",
			baseEndsInSimple: true,
			urlPath:          "/demo/",
			wantName:         "demo",
			wantVersion:      "",
			wantIsDownload:   false,
		},
		{
			name:             "project segment plus filename below a /simple-ending base is a download",
			baseEndsInSimple: true,
			urlPath:          "/demo/demo-1.2.3-py3-none-any.whl",
			wantName:         "demo",
			wantVersion:      "1.2.3",
			wantIsDownload:   true,
		},
		{
			name:           "bare filename below a download-only base is a download",
			urlPath:        "/demo-1.2.3-py3-none-any.whl",
			wantName:       "demo",
			wantVersion:    "1.2.3",
			wantIsDownload: true,
		},
		{
			name:           "a self-describing filename at arbitrary depth is a download regardless of base shape",
			urlPath:        "/ab/cd/demo-1.2.3-py3-none-any.whl",
			wantName:       "demo",
			wantVersion:    "1.2.3",
			wantIsDownload: true,
		},
		{
			name:             "a self-describing filename at arbitrary depth resolves under a /simple-ending base too",
			baseEndsInSimple: true,
			urlPath:          "/ab/cd/demo-1.2.3-py3-none-any.whl",
			wantName:         "demo",
			wantVersion:      "1.2.3",
			wantIsDownload:   true,
		},
		{
			name:             "a project literally named simple is not shadowed by the reserved segment",
			baseEndsInSimple: true,
			urlPath:          "/simple/simple-1.0.0-py3-none-any.whl",
			wantName:         "simple",
			wantVersion:      "1.0.0",
			wantIsDownload:   true,
		},
		{
			name:           "existing simple API shape is retained when the base sits above it",
			urlPath:        "/simple/demo/",
			wantName:       "demo",
			wantVersion:    "",
			wantIsDownload: false,
		},
		{
			name:           "existing JSON API shape is retained when the base sits above it",
			urlPath:        "/pypi/demo/json",
			wantName:       "demo",
			wantVersion:    "",
			wantIsDownload: false,
		},
		{
			name:           "existing JSON API version shape is retained when the base sits above it",
			urlPath:        "/pypi/demo/1.2.3/json",
			wantName:       "demo",
			wantVersion:    "1.2.3",
			wantIsDownload: false,
		},
		{
			name:    "empty path is an error",
			urlPath: "",
			wantErr: true,
		},
		{
			name:    "just a slash is an error",
			urlPath: "/",
			wantErr: true,
		},
		{
			name:             "too many segments is an error",
			baseEndsInSimple: true,
			urlPath:          "/demo/1.2.3/extra/segments",
			wantErr:          true,
		},
		{
			name:    "a single non-filename segment under a non-/simple base is an error, not a guess",
			urlPath: "/health",
			wantErr: true,
		},
		{
			name:    "a two-segment non-filename path under a non-/simple base is an error, not a guess",
			urlPath: "/auth/login",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := pypiCustomParser{baseEndsInSimple: tt.baseEndsInSimple}
			got, err := parser.ParseURL(tt.urlPath)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantName, got.GetName())
			assert.Equal(t, tt.wantVersion, got.GetVersion())
			assert.Equal(t, tt.wantIsDownload, got.IsFileDownload())
		})
	}
}

func TestPypiCustomParser_SimpleMetadataIsFlaggedAsSimpleAPI(t *testing.T) {
	parser := pypiCustomParser{baseEndsInSimple: true}

	got, err := parser.ParseURL("/demo/")
	require.NoError(t, err)
	info, ok := got.(*pypiPackageInfo)
	require.True(t, ok)
	assert.True(t, info.IsSimpleAPI())
}

func TestPypiCustomParser_JSONAPIIsNotFlaggedAsSimpleAPI(t *testing.T) {
	parser := pypiCustomParser{}

	got, err := parser.ParseURL("/pypi/demo/json")
	require.NoError(t, err)
	info, ok := got.(*pypiPackageInfo)
	require.True(t, ok)
	assert.False(t, info.IsSimpleAPI())
}

func TestPypiCustomParser_ProjectNameShapedLikeFilenameUnderSimpleBaseIsMetadata(t *testing.T) {
	parser := pypiCustomParser{baseEndsInSimple: true}

	// "totally-fine-2.0.0.tar.gz" happens to parse as a filename, but per PEP
	// 503 a bare one-segment path under a Simple API mount is always the
	// project's index page, never a download.
	got, err := parser.ParseURL("/totally-fine-2.0.0.tar.gz/")
	require.NoError(t, err)
	assert.False(t, got.IsFileDownload(), "a one-segment path under a /simple base must never be treated as a download")

	info, ok := got.(*pypiPackageInfo)
	require.True(t, ok)
	assert.True(t, info.IsSimpleAPI())
	assert.Equal(t, denormalizePyPIPackageName("totally-fine-2.0.0.tar.gz"), got.GetName())
}

func TestPypiCustomParser_BareFilenameStillDownloadUnderNonSimpleBase(t *testing.T) {
	// The shortcut's gate is specific to depth 1 under a /simple base; a
	// non-/simple endpoint must keep resolving a bare filename as a download.
	parser := pypiCustomParser{baseEndsInSimple: false}

	got, err := parser.ParseURL("/demo-1.2.3-py3-none-any.whl")
	require.NoError(t, err)
	assert.True(t, got.IsFileDownload(), "the depth-1 filename-first shortcut must remain for a non-/simple base")
	assert.Equal(t, "demo", got.GetName())
	assert.Equal(t, "1.2.3", got.GetVersion())
}

func TestPypiCustomParser_DoesNotDecodeSegmentsASecondTime(t *testing.T) {
	// MatchURL decodes the path once before parsing. A segment still
	// containing %-escapes after that single decode (wire-encoded as %252B)
	// must not be misread as a +build tag in the version: it simply does
	// not parse as a distribution filename.
	parser := pypiCustomParser{baseEndsInSimple: false}

	filename, ok := pypiFilenameFromLastSegment("demo-1.0.0%2Bbuild.tar.gz")
	if ok {
		assert.NotEqual(t, "1.0.0+build", filename.GetVersion(), "an escaped segment must never be double-decoded")
	}

	_, err := parser.ParseURL("/demo-1.0.0%2Bbuild.tar.gz")
	assert.Error(t, err, "a leftover escape must not yield a misattributed identity")
}

func TestPypiBaseEndsInSimple(t *testing.T) {
	tests := []struct {
		name     string
		basePath string
		want     bool
	}{
		{"exact /simple", "/simple", true},
		{"exact /simple with trailing slash", "/simple/", true},
		{"mounted below another prefix", "/python/simple", true},
		{"non-simple base", "/files", false},
		{"non-simple base mounted below a prefix", "/python/files", false},
		{"a base merely containing simple as a substring is not a match", "/notsimple", false},
		{"empty base", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, pypiBaseEndsInSimple(tt.basePath))
		})
	}
}
