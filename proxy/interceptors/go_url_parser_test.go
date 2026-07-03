package interceptors

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGoProxyParserParseURL(t *testing.T) {
	cases := []struct {
		name            string
		path            string
		wantName        string
		wantVersion     string
		wantType        string
		wantIsDownload  bool
		wantErrContains string
	}{
		{
			name:           "zip download",
			path:           "/github.com/x/y/@v/v1.2.3.zip",
			wantName:       "github.com/x/y",
			wantVersion:    "v1.2.3",
			wantType:       goRequestZip,
			wantIsDownload: true,
		},
		{
			name:        "info metadata",
			path:        "/github.com/x/y/@v/v1.2.3.info",
			wantName:    "github.com/x/y",
			wantVersion: "v1.2.3",
			wantType:    goRequestInfo,
		},
		{
			name:        "mod metadata",
			path:        "/github.com/x/y/@v/v1.2.3.mod",
			wantName:    "github.com/x/y",
			wantVersion: "v1.2.3",
			wantType:    goRequestMod,
		},
		{
			name:     "version list",
			path:     "/github.com/x/y/@v/list",
			wantName: "github.com/x/y",
			wantType: goRequestList,
		},
		{
			name:     "latest metadata",
			path:     "/github.com/x/y/@latest",
			wantName: "github.com/x/y",
			wantType: goRequestLatest,
		},
		{
			name:           "case-escaped module path and version are decoded",
			path:           "/github.com/!burnt!sushi/toml/@v/!v1.0.0-!rc1.zip",
			wantName:       "github.com/BurntSushi/toml",
			wantVersion:    "V1.0.0-Rc1",
			wantType:       goRequestZip,
			wantIsDownload: true,
		},
		{
			name:           "pseudo-version",
			path:           "/example.com/m/@v/v0.0.0-20191109021931-daa7c04131f5.zip",
			wantName:       "example.com/m",
			wantVersion:    "v0.0.0-20191109021931-daa7c04131f5",
			wantType:       goRequestZip,
			wantIsDownload: true,
		},
		{
			name:           "incompatible version",
			path:           "/github.com/x/y/@v/v4.1.2+incompatible.zip",
			wantName:       "github.com/x/y",
			wantVersion:    "v4.1.2+incompatible",
			wantType:       goRequestZip,
			wantIsDownload: true,
		},
		{
			name:     "proxied checksum database traffic",
			path:     "/sumdb/sum.golang.org/lookup/example.com/m@v1.0.0",
			wantType: goRequestSumDB,
		},
		{
			name:     "sumdb capability check",
			path:     "/sumdb/sum.golang.org/supported",
			wantType: goRequestSumDB,
		},
		{
			name:            "missing marker",
			path:            "/github.com/x/y",
			wantErrContains: "missing /@v/",
		},
		{
			name:            "unknown suffix",
			path:            "/github.com/x/y/@v/v1.2.3.tar",
			wantErrContains: "unrecognized go proxy version suffix",
		},
		{
			name:            "empty path",
			path:            "/",
			wantErrContains: "empty go proxy URL path",
		},
		{
			name:            "version without suffix",
			path:            "/github.com/x/y/@v/v123",
			wantErrContains: "no version suffix",
		},
	}

	parser := goProxyParser{}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info, err := parser.ParseURL(tc.path)

			if tc.wantErrContains != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErrContains)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.wantName, info.GetName())
			assert.Equal(t, tc.wantVersion, info.GetVersion())
			assert.Equal(t, tc.wantIsDownload, info.IsFileDownload())

			goInfo, ok := info.(*goModuleInfo)
			require.True(t, ok)
			assert.Equal(t, tc.wantType, goInfo.requestType)
		})
	}
}
