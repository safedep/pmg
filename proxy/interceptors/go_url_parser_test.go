package interceptors

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGoProxyParser_ParseURL(t *testing.T) {
	tests := []struct {
		name            string
		urlPath         string
		wantName        string
		wantVersion     string
		wantIsDownload  bool
		wantRequestType string
		wantErr         bool
	}{
		// @latest requests
		{
			name:            "latest version query",
			urlPath:         "/github.com/stretchr/testify/@latest",
			wantName:        "github.com/stretchr/testify",
			wantRequestType: "latest",
		},
		{
			name:            "latest with two-segment module",
			urlPath:         "/gopkg.in/yaml.v3/@latest",
			wantName:        "gopkg.in/yaml.v3",
			wantRequestType: "latest",
		},

		// @v/list requests
		{
			name:            "list versions",
			urlPath:         "/github.com/stretchr/testify/@v/list",
			wantName:        "github.com/stretchr/testify",
			wantRequestType: "list",
		},

		// .info requests
		{
			name:            "version info",
			urlPath:         "/github.com/stretchr/testify/@v/v1.8.4.info",
			wantName:        "github.com/stretchr/testify",
			wantVersion:     "v1.8.4",
			wantRequestType: "info",
		},

		// .mod requests
		{
			name:            "version mod file",
			urlPath:         "/github.com/stretchr/testify/@v/v1.8.4.mod",
			wantName:        "github.com/stretchr/testify",
			wantVersion:     "v1.8.4",
			wantRequestType: "mod",
		},

		// .zip requests (only downloadable artifact)
		{
			name:            "version zip download",
			urlPath:         "/github.com/stretchr/testify/@v/v1.8.4.zip",
			wantName:        "github.com/stretchr/testify",
			wantVersion:     "v1.8.4",
			wantIsDownload:  true,
			wantRequestType: "zip",
		},
		{
			name:            "stdlib module zip",
			urlPath:         "/golang.org/x/text/@v/v0.14.0.zip",
			wantName:        "golang.org/x/text",
			wantVersion:     "v0.14.0",
			wantIsDownload:  true,
			wantRequestType: "zip",
		},
		{
			name:            "gopkg.in module zip",
			urlPath:         "/gopkg.in/yaml.v3/@v/v3.0.1.zip",
			wantName:        "gopkg.in/yaml.v3",
			wantVersion:     "v3.0.1",
			wantIsDownload:  true,
			wantRequestType: "zip",
		},

		// Major version suffix in module path
		{
			name:            "major version suffix v2",
			urlPath:         "/github.com/user/repo/v2/@v/v2.1.0.zip",
			wantName:        "github.com/user/repo/v2",
			wantVersion:     "v2.1.0",
			wantIsDownload:  true,
			wantRequestType: "zip",
		},
		{
			name:            "major version suffix v3 info",
			urlPath:         "/github.com/user/repo/v3/@v/v3.0.0.info",
			wantName:        "github.com/user/repo/v3",
			wantVersion:     "v3.0.0",
			wantRequestType: "info",
		},

		// Pre-release / pseudo-versions
		{
			name:            "pseudo-version zip",
			urlPath:         "/github.com/foo/bar/@v/v0.0.0-20231215164652-abc123def456.zip",
			wantName:        "github.com/foo/bar",
			wantVersion:     "v0.0.0-20231215164652-abc123def456",
			wantIsDownload:  true,
			wantRequestType: "zip",
		},
		{
			name:            "pre-release version info",
			urlPath:         "/github.com/foo/bar/@v/v1.0.0-rc.1.info",
			wantName:        "github.com/foo/bar",
			wantVersion:     "v1.0.0-rc.1",
			wantRequestType: "info",
		},

		// Escaped module paths (uppercase letters)
		{
			name:            "escaped uppercase module path",
			urlPath:         "/github.com/!azure/azure-sdk-for-go/@v/v1.0.0.info",
			wantName:        "github.com/Azure/azure-sdk-for-go",
			wantVersion:     "v1.0.0",
			wantRequestType: "info",
		},
		{
			name:            "escaped uppercase in nested path",
			urlPath:         "/github.com/!buy!stuff/!my!lib/@latest",
			wantName:        "github.com/BuyStuff/MyLib",
			wantRequestType: "latest",
		},
		{
			name:            "escaped uppercase zip download",
			urlPath:         "/github.com/!a!b!c/pkg/@v/v0.1.0.zip",
			wantName:        "github.com/ABC/pkg",
			wantVersion:     "v0.1.0",
			wantIsDownload:  true,
			wantRequestType: "zip",
		},

		// Leading slash handling
		{
			name:            "no leading slash",
			urlPath:         "github.com/stretchr/testify/@v/v1.8.4.zip",
			wantName:        "github.com/stretchr/testify",
			wantVersion:     "v1.8.4",
			wantIsDownload:  true,
			wantRequestType: "zip",
		},

		// Error cases
		{
			name:    "empty URL path",
			urlPath: "",
			wantErr: true,
		},
		{
			name:    "just slash",
			urlPath: "/",
			wantErr: true,
		},
		{
			name:    "no @v or @latest marker",
			urlPath: "/github.com/stretchr/testify",
			wantErr: true,
		},
		{
			name:    "empty version part after @v",
			urlPath: "/github.com/stretchr/testify/@v/",
			wantErr: true,
		},
		{
			name:    "unknown suffix",
			urlPath: "/github.com/stretchr/testify/@v/v1.8.4.txt",
			wantErr: true,
		},
		{
			name:    "empty version with .zip suffix",
			urlPath: "/github.com/stretchr/testify/@v/.zip",
			wantErr: true,
		},
		{
			name:    "trailing bang in escaped path",
			urlPath: "/github.com/bad!/@v/v1.0.0.zip",
			wantErr: true,
		},
		{
			name:    "invalid escape character",
			urlPath: "/github.com/!1bad/@v/v1.0.0.zip",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := goProxyParser{}
			got, err := parser.ParseURL(tt.urlPath)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantName, got.GetName())
			assert.Equal(t, tt.wantVersion, got.GetVersion())
			assert.Equal(t, tt.wantIsDownload, got.IsFileDownload())

			goInfo, ok := got.(*goModuleInfo)
			require.True(t, ok, "expected *goModuleInfo type")
			assert.Equal(t, tt.wantRequestType, goInfo.RequestType())
		})
	}
}

func TestUnescapeModulePath(t *testing.T) {
	tests := []struct {
		escaped string
		want    string
		wantErr bool
	}{
		{"github.com/stretchr/testify", "github.com/stretchr/testify", false},
		{"github.com/!azure/azure-sdk", "github.com/Azure/azure-sdk", false},
		{"!a!b!c", "ABC", false},
		{"no-escapes-here", "no-escapes-here", false},
		{"", "", false},
		{"trailing!", "", true},
		{"!1invalid", "", true},
		{"!Ainvalid", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.escaped, func(t *testing.T) {
			got, err := unescapeModulePath(tt.escaped)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
