package interceptors

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseNpmRegistryURL(t *testing.T) {
	tests := []struct {
		name          string
		urlPath       string
		wantName      string
		wantVersion   string
		wantIsTarball bool
		wantIsScoped  bool
		wantErr       bool
	}{
		// Unscoped packages - metadata requests
		{
			name:          "unscoped package without version",
			urlPath:       "/lodash",
			wantName:      "lodash",
			wantVersion:   "",
			wantIsTarball: false,
			wantIsScoped:  false,
			wantErr:       false,
		},
		{
			name:          "unscoped package with version",
			urlPath:       "/lodash/4.17.21",
			wantName:      "lodash",
			wantVersion:   "4.17.21",
			wantIsTarball: false,
			wantIsScoped:  false,
			wantErr:       false,
		},
		{
			name:          "unscoped package with leading slash",
			urlPath:       "/express",
			wantName:      "express",
			wantVersion:   "",
			wantIsTarball: false,
			wantIsScoped:  false,
			wantErr:       false,
		},
		{
			name:          "unscoped package with trailing slash",
			urlPath:       "/react/",
			wantName:      "react",
			wantVersion:   "",
			wantIsTarball: false,
			wantIsScoped:  false,
			wantErr:       false,
		},

		// Unscoped packages - tarball downloads
		{
			name:          "unscoped package tarball",
			urlPath:       "/lodash/-/lodash-4.17.21.tgz",
			wantName:      "lodash",
			wantVersion:   "4.17.21",
			wantIsTarball: true,
			wantIsScoped:  false,
			wantErr:       false,
		},
		{
			name:          "unscoped package tarball with prerelease",
			urlPath:       "/react/-/react-18.0.0-rc.1.tgz",
			wantName:      "react",
			wantVersion:   "18.0.0-rc.1",
			wantIsTarball: true,
			wantIsScoped:  false,
			wantErr:       false,
		},
		{
			name:          "unscoped package tarball with build metadata",
			urlPath:       "/vue/-/vue-3.2.0+build123.tgz",
			wantName:      "vue",
			wantVersion:   "3.2.0+build123",
			wantIsTarball: true,
			wantIsScoped:  false,
			wantErr:       false,
		},

		// Scoped packages - metadata requests
		{
			name:          "scoped package without version",
			urlPath:       "/@types/node",
			wantName:      "@types/node",
			wantVersion:   "",
			wantIsTarball: false,
			wantIsScoped:  true,
			wantErr:       false,
		},
		{
			name:          "scoped package with version",
			urlPath:       "/@types/node/18.0.0",
			wantName:      "@types/node",
			wantVersion:   "18.0.0",
			wantIsTarball: false,
			wantIsScoped:  true,
			wantErr:       false,
		},
		{
			name:          "scoped package with complex scope",
			urlPath:       "/@babel/core",
			wantName:      "@babel/core",
			wantVersion:   "",
			wantIsTarball: false,
			wantIsScoped:  true,
			wantErr:       false,
		},

		// Scoped packages - tarball downloads
		{
			name:          "scoped package tarball",
			urlPath:       "/@types/node/-/types-node-18.0.0.tgz",
			wantName:      "@types/node",
			wantVersion:   "18.0.0",
			wantIsTarball: true,
			wantIsScoped:  true,
			wantErr:       false,
		},
		{
			name:          "scoped package tarball with prerelease",
			urlPath:       "/@babel/core/-/babel-core-7.20.0-beta.1.tgz",
			wantName:      "@babel/core",
			wantVersion:   "7.20.0-beta.1",
			wantIsTarball: true,
			wantIsScoped:  true,
			wantErr:       false,
		},
		{
			name:          "scoped package with hyphenated name",
			urlPath:       "/@angular/common-http/-/angular-common-http-15.0.0.tgz",
			wantName:      "@angular/common-http",
			wantVersion:   "15.0.0",
			wantIsTarball: true,
			wantIsScoped:  true,
			wantErr:       false,
		},
		{
			name:          "scoped package tarball without scope prefix (Format 2)",
			urlPath:       "/@prisma/studio-core-licensed/-/studio-core-licensed-0.0.0-dev.202601011229.tgz",
			wantName:      "@prisma/studio-core-licensed",
			wantVersion:   "0.0.0-dev.202601011229",
			wantIsTarball: true,
			wantIsScoped:  true,
			wantErr:       false,
		},
		{
			name:          "scoped package tarball with scope prefix (Format 1)",
			urlPath:       "/@types/node/-/types-node-20.0.0.tgz",
			wantName:      "@types/node",
			wantVersion:   "20.0.0",
			wantIsTarball: true,
			wantIsScoped:  true,
			wantErr:       false,
		},

		// Error cases
		{
			name:          "empty URL path",
			urlPath:       "",
			wantName:      "",
			wantVersion:   "",
			wantIsTarball: false,
			wantIsScoped:  false,
			wantErr:       true,
		},
		{
			name:          "just slash",
			urlPath:       "/",
			wantName:      "",
			wantVersion:   "",
			wantIsTarball: false,
			wantIsScoped:  false,
			wantErr:       true,
		},
		{
			name:          "scoped package missing package name",
			urlPath:       "/@types",
			wantName:      "",
			wantVersion:   "",
			wantIsTarball: false,
			wantIsScoped:  false,
			wantErr:       true,
		},
		{
			name:          "unscoped package with too many segments",
			urlPath:       "/lodash/4.17.21/extra/segment",
			wantName:      "",
			wantVersion:   "",
			wantIsTarball: false,
			wantIsScoped:  false,
			wantErr:       true,
		},
		{
			name:          "scoped package with too many segments",
			urlPath:       "/@types/node/18.0.0/extra/segment",
			wantName:      "",
			wantVersion:   "",
			wantIsTarball: false,
			wantIsScoped:  false,
			wantErr:       true,
		},
		{
			name:          "malformed tarball - wrong prefix",
			urlPath:       "/lodash/-/react-4.17.21.tgz",
			wantName:      "",
			wantVersion:   "",
			wantIsTarball: false,
			wantIsScoped:  false,
			wantErr:       true,
		},
		{
			name:          "malformed tarball - no .tgz extension",
			urlPath:       "/lodash/-/lodash-4.17.21.tar.gz",
			wantName:      "",
			wantVersion:   "",
			wantIsTarball: false,
			wantIsScoped:  false,
			wantErr:       true,
		},
		{
			name:          "scoped tarball with wrong scope in filename",
			urlPath:       "/@types/node/-/babel-node-18.0.0.tgz",
			wantName:      "",
			wantVersion:   "",
			wantIsTarball: false,
			wantIsScoped:  false,
			wantErr:       true,
		},

		// Edge cases
		{
			name:          "package name with numbers",
			urlPath:       "/vue3",
			wantName:      "vue3",
			wantVersion:   "",
			wantIsTarball: false,
			wantIsScoped:  false,
			wantErr:       false,
		},
		{
			name:          "package name with hyphens",
			urlPath:       "/express-validator",
			wantName:      "express-validator",
			wantVersion:   "",
			wantIsTarball: false,
			wantIsScoped:  false,
			wantErr:       false,
		},
		{
			name:          "version with v prefix (uncommon but valid)",
			urlPath:       "/lodash/v4.17.21",
			wantName:      "lodash",
			wantVersion:   "v4.17.21",
			wantIsTarball: false,
			wantIsScoped:  false,
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := npmParser{}
			got, err := parser.ParseURL(tt.urlPath)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.wantName, got.GetName())
			assert.Equal(t, tt.wantVersion, got.GetVersion())
			assert.Equal(t, tt.wantIsTarball, got.IsFileDownload())

			// Check scoped status via type assertion - must succeed for npm packages
			npmInfo, ok := got.(*npmPackageInfo)
			assert.True(t, ok, "expected *npmPackageInfo type")
			if ok {
				assert.Equal(t, tt.wantIsScoped, npmInfo.IsScoped())
			}
		})
	}
}

func TestGithubParser_ParseURL(t *testing.T) {
	tests := []struct {
		name          string
		urlPath       string
		wantIsTarball bool
		wantErr       bool
	}{
		{
			name:          "github metadata request",
			urlPath:       "/@owner/package",
			wantIsTarball: false,
			wantErr:       false,
		},
		{
			name:          "github download request",
			urlPath:       "/download/@owner/package/1.0.0/abc123.tgz",
			wantIsTarball: false,
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := npmGithubParser{}
			got, err := parser.ParseURL(tt.urlPath)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.wantIsTarball, got.IsFileDownload())
		})
	}
}

func TestGithubBlobParser_ParseURL(t *testing.T) {
	tests := []struct {
		name          string
		urlPath       string
		wantIsTarball bool
		wantErr       bool
	}{
		{
			name:          "github blob storage request",
			urlPath:       "/npmregistryv2prod/blobs/132160241/gh-npm-pkg/1.0.0/abc123",
			wantIsTarball: false,
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := npmGithubBlobParser{}
			got, err := parser.ParseURL(tt.urlPath)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.wantIsTarball, got.IsFileDownload())
		})
	}
}
