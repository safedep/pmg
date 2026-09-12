package interceptors

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPypiCoreMetadata(t *testing.T) {
	for _, tt := range []struct {
		filename string
		version  string
		wantErr  bool
	}{
		{filename: "demo-1.0-py3-none-any.whl.metadata", version: "1.0"},
		{filename: "demo-1.0-1local-py3-none-any.whl.metadata", version: "1.0"},
		{filename: "demo-1!2.0.tar.gz.metadata", version: "1!2.0"},
		{filename: "invalid.metadata", wantErr: true},
		{filename: "demo-1.0-py3-none-any.whl.metadata.metadata", wantErr: true},
	} {
		for _, route := range []struct {
			name   string
			parser registryURLParser
			prefix string
		}{
			{name: "files", parser: pypiFilesParser{}, prefix: "/packages/ab/cd/"},
			{name: "simple", parser: pypiOrgParser{}, prefix: "/simple/demo/"},
			{name: "custom", parser: pypiCustomParser{}, prefix: "/files/"},
		} {
			t.Run(route.name+"/"+tt.filename, func(t *testing.T) {
				info, err := route.parser.ParseURL(route.prefix + tt.filename)
				if tt.wantErr {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)
				assert.Equal(t, "demo", info.GetName())
				assert.Equal(t, tt.version, info.GetVersion())
				assert.False(t, info.IsFileDownload())
				assert.False(t, pypiIsSimpleAPIMetadataRequest(info))
			})
		}
	}
}

func TestPypiFilesParser_ParseURL(t *testing.T) {
	tests := []struct {
		name           string
		urlPath        string
		wantName       string
		wantVersion    string
		wantIsDownload bool
		wantErr        bool
	}{
		// Source distributions (sdist)
		{
			name:           "sdist tar.gz simple package",
			urlPath:        "/packages/ab/cd/abcd1234/requests-2.28.0.tar.gz",
			wantName:       "requests",
			wantVersion:    "2.28.0",
			wantIsDownload: true,
			wantErr:        false,
		},
		{
			name:           "sdist tar.gz with hyphenated name",
			urlPath:        "/packages/12/34/5678abcd/Flask-RESTful-0.3.10.tar.gz",
			wantName:       "flask-restful",
			wantVersion:    "0.3.10",
			wantIsDownload: true,
			wantErr:        false,
		},
		{
			name:           "sdist zip format",
			urlPath:        "/packages/aa/bb/ccdd/some-package-1.0.0.zip",
			wantName:       "some-package",
			wantVersion:    "1.0.0",
			wantIsDownload: true,
			wantErr:        false,
		},
		{
			name:           "sdist with prerelease version",
			urlPath:        "/packages/ff/ee/ddcc/mypackage-2.0.0rc1.tar.gz",
			wantName:       "mypackage",
			wantVersion:    "2.0.0rc1",
			wantIsDownload: true,
			wantErr:        false,
		},
		{
			name:           "sdist with dev version",
			urlPath:        "/packages/11/22/3344/testpkg-0.1.0.dev1.tar.gz",
			wantName:       "testpkg",
			wantVersion:    "0.1.0.dev1",
			wantIsDownload: true,
			wantErr:        false,
		},
		{
			name:           "sdist with post version",
			urlPath:        "/packages/aa/bb/cc/package-1.0.0.post1.tar.gz",
			wantName:       "package",
			wantVersion:    "1.0.0.post1",
			wantIsDownload: true,
			wantErr:        false,
		},
		{
			name:           "sdist with local version identifier",
			urlPath:        "/packages/dd/ee/ff/mylib-1.2.3+local.tar.gz",
			wantName:       "mylib",
			wantVersion:    "1.2.3+local",
			wantIsDownload: true,
			wantErr:        false,
		},

		// Wheel files
		{
			name:           "wheel simple package",
			urlPath:        "/packages/ab/cd/ef12/requests-2.28.0-py3-none-any.whl",
			wantName:       "requests",
			wantVersion:    "2.28.0",
			wantIsDownload: true,
			wantErr:        false,
		},
		{
			name:           "wheel with platform-specific tags",
			urlPath:        "/packages/12/34/56/numpy-1.24.0-cp311-cp311-linux_x86_64.whl",
			wantName:       "numpy",
			wantVersion:    "1.24.0",
			wantIsDownload: true,
			wantErr:        false,
		},
		{
			name:           "wheel with manylinux platform",
			urlPath:        "/packages/aa/bb/cc/cryptography-41.0.0-cp39-cp39-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
			wantName:       "cryptography",
			wantVersion:    "41.0.0",
			wantIsDownload: true,
			wantErr:        false,
		},
		{
			name:           "wheel with underscore in name (normalized)",
			urlPath:        "/packages/11/22/33/some_package-1.0.0-py3-none-any.whl",
			wantName:       "some-package",
			wantVersion:    "1.0.0",
			wantIsDownload: true,
			wantErr:        false,
		},
		{
			name:           "wheel with build tag",
			urlPath:        "/packages/ff/ee/dd/mypackage-1.0.0-1-py3-none-any.whl",
			wantName:       "mypackage",
			wantVersion:    "1.0.0",
			wantIsDownload: true,
			wantErr:        false,
		},
		{
			name:           "wheel windows platform",
			urlPath:        "/packages/aa/bb/cc/pywin32-306-cp311-cp311-win_amd64.whl",
			wantName:       "pywin32",
			wantVersion:    "306",
			wantIsDownload: true,
			wantErr:        false,
		},
		{
			name:           "wheel macos platform",
			urlPath:        "/packages/dd/ee/ff/tensorflow-2.15.0-cp311-cp311-macosx_10_15_x86_64.whl",
			wantName:       "tensorflow",
			wantVersion:    "2.15.0",
			wantIsDownload: true,
			wantErr:        false,
		},

		// Real-world examples
		{
			name:           "real django sdist",
			urlPath:        "/packages/b8/50/71e60c5e9148c20de37c37f3e4cd1da1f63f7d0f7ea4c7e9c8a2f5c8d9e1/Django-4.2.7.tar.gz",
			wantName:       "django",
			wantVersion:    "4.2.7",
			wantIsDownload: true,
			wantErr:        false,
		},
		{
			name:           "real pandas wheel",
			urlPath:        "/packages/a1/b2/c3d4e5f6/pandas-2.1.3-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
			wantName:       "pandas",
			wantVersion:    "2.1.3",
			wantIsDownload: true,
			wantErr:        false,
		},

		// Error cases
		{
			name:           "empty URL path",
			urlPath:        "",
			wantName:       "",
			wantVersion:    "",
			wantIsDownload: false,
			wantErr:        true,
		},
		{
			name:           "just slash",
			urlPath:        "/",
			wantName:       "",
			wantVersion:    "",
			wantIsDownload: false,
			wantErr:        true,
		},
		{
			name:           "invalid path without packages prefix",
			urlPath:        "/files/ab/cd/requests-2.28.0.tar.gz",
			wantName:       "",
			wantVersion:    "",
			wantIsDownload: false,
			wantErr:        true,
		},
		{
			name:           "unsupported file type",
			urlPath:        "/packages/ab/cd/ef/readme.txt",
			wantName:       "",
			wantVersion:    "",
			wantIsDownload: false,
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := pypiFilesParser{}
			got, err := parser.ParseURL(tt.urlPath)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.wantName, got.GetName())
			assert.Equal(t, tt.wantVersion, got.GetVersion())
			assert.Equal(t, tt.wantIsDownload, got.IsFileDownload())

		})
	}
}

func TestPypiOrgParser_ParseURL(t *testing.T) {
	tests := []struct {
		name           string
		urlPath        string
		wantName       string
		wantVersion    string
		wantIsDownload bool
		wantErr        bool
	}{
		{
			name:    "invalid Simple API artifact",
			urlPath: "/simple/demo/invalid.whl",
			wantErr: true,
		},
		// Simple API
		{
			name:           "simple api package index",
			urlPath:        "/simple/requests/",
			wantName:       "requests",
			wantVersion:    "",
			wantIsDownload: false,
			wantErr:        false,
		},
		{
			name:           "simple api package without trailing slash",
			urlPath:        "/simple/django",
			wantName:       "django",
			wantVersion:    "",
			wantIsDownload: false,
			wantErr:        false,
		},
		{
			name:           "simple api normalized name",
			urlPath:        "/simple/flask-restful/",
			wantName:       "flask-restful",
			wantVersion:    "",
			wantIsDownload: false,
			wantErr:        false,
		},

		// JSON API
		{
			name:           "json api package metadata",
			urlPath:        "/pypi/requests/json",
			wantName:       "requests",
			wantVersion:    "",
			wantIsDownload: false,
			wantErr:        false,
		},
		{
			name:           "json api version metadata",
			urlPath:        "/pypi/requests/2.28.0/json",
			wantName:       "requests",
			wantVersion:    "2.28.0",
			wantIsDownload: false,
			wantErr:        false,
		},
		{
			name:           "json api with normalized name",
			urlPath:        "/pypi/flask-restful/0.3.10/json",
			wantName:       "flask-restful",
			wantVersion:    "0.3.10",
			wantIsDownload: false,
			wantErr:        false,
		},

		// Error cases
		{
			name:           "empty URL path",
			urlPath:        "",
			wantName:       "",
			wantVersion:    "",
			wantIsDownload: false,
			wantErr:        true,
		},
		{
			name:           "just slash",
			urlPath:        "/",
			wantName:       "",
			wantVersion:    "",
			wantIsDownload: false,
			wantErr:        true,
		},
		{
			name:           "unknown path prefix",
			urlPath:        "/unknown/requests/",
			wantName:       "",
			wantVersion:    "",
			wantIsDownload: false,
			wantErr:        true,
		},
		{
			name:           "simple api root listing",
			urlPath:        "/simple/",
			wantName:       "",
			wantVersion:    "",
			wantIsDownload: false,
		},
		{
			name:           "json api missing package name",
			urlPath:        "/pypi/json",
			wantName:       "",
			wantVersion:    "",
			wantIsDownload: false,
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := pypiOrgParser{}
			got, err := parser.ParseURL(tt.urlPath)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.wantName, got.GetName())
			assert.Equal(t, tt.wantVersion, got.GetVersion())
			assert.Equal(t, tt.wantIsDownload, got.IsFileDownload())
		})
	}
}

func TestParseWheelFilename(t *testing.T) {
	tests := []struct {
		name        string
		filename    string
		wantName    string
		wantVersion string
		wantErr     bool
	}{
		{
			name:        "hyphenated name",
			filename:    "Flask-RESTful-0.3.10-py2.py3-none-any.whl",
			wantName:    "flask-restful",
			wantVersion: "0.3.10",
		},
		{
			name:     "invalid build tag",
			filename: "demo-1.0.0-local1-py3-none-any.whl",
			wantErr:  true,
		},
		{
			name:     "extra components",
			filename: "pkg-1.0.0-1local-1-py3-none-any.whl",
			wantErr:  true,
		},
		{
			name:     "invalid version",
			filename: "demo-invalid-py3-none-any.whl",
			wantErr:  true,
		},
		{
			name:        "epoch version",
			filename:    "demo-1!2.0-1local-py3-none-any.whl",
			wantName:    "demo",
			wantVersion: "1!2.0",
		},
		{
			name:        "wheel with build suffix",
			filename:    "wheel_canary-1.0.0-1local-py3-none-any.whl",
			wantName:    "wheel-canary",
			wantVersion: "1.0.0",
		},
		{
			name:        "wheel with multiple build digits and suffix",
			filename:    "wheel_canary-1.0.0-12local-py3-none-any.whl",
			wantName:    "wheel-canary",
			wantVersion: "1.0.0",
		},
		{
			name:        "simple wheel",
			filename:    "requests-2.28.0-py3-none-any.whl",
			wantName:    "requests",
			wantVersion: "2.28.0",
			wantErr:     false,
		},
		{
			name:        "wheel with cpython tag",
			filename:    "numpy-1.24.0-cp311-cp311-linux_x86_64.whl",
			wantName:    "numpy",
			wantVersion: "1.24.0",
			wantErr:     false,
		},
		{
			name:        "wheel with build tag",
			filename:    "package-1.0.0-1-py3-none-any.whl",
			wantName:    "package",
			wantVersion: "1.0.0",
			wantErr:     false,
		},
		{
			name:        "wheel with underscore name",
			filename:    "my_package-1.0.0-py3-none-any.whl",
			wantName:    "my-package",
			wantVersion: "1.0.0",
			wantErr:     false,
		},
		{
			name:        "invalid wheel - too few parts",
			filename:    "invalid-1.0.0.whl",
			wantName:    "",
			wantVersion: "",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseWheelFilename(tt.filename)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantName, got.GetName())
			assert.Equal(t, tt.wantVersion, got.GetVersion())
			assert.True(t, got.IsFileDownload())
		})
	}
}

func TestIsBuildTag(t *testing.T) {
	for _, tt := range []struct {
		tag  string
		want bool
	}{
		{tag: "", want: false},
		{tag: "1", want: true},
		{tag: "0local", want: true},
		{tag: "12local", want: true},
		{tag: "local1", want: false},
		{tag: "١local", want: false},
	} {
		t.Run(tt.tag, func(t *testing.T) {
			assert.Equal(t, tt.want, isBuildTag(tt.tag))
		})
	}
}

func TestParseSdistFilename(t *testing.T) {
	tests := []struct {
		name        string
		filename    string
		wantName    string
		wantVersion string
		wantErr     bool
	}{
		{
			name:        "epoch version",
			filename:    "epoch_canary-1!2.0.tar.gz",
			wantName:    "epoch-canary",
			wantVersion: "1!2.0",
		},
		{
			name:        "epoch with release suffixes",
			filename:    "epoch_canary-12!2.0rc1.post2.dev3+local.zip",
			wantName:    "epoch-canary",
			wantVersion: "12!2.0rc1.post2.dev3+local",
		},
		{
			name:     "missing epoch digits",
			filename: "epoch_canary-!2.0.tar.gz",
			wantErr:  true,
		},
		{
			name:     "multiple epochs",
			filename: "epoch_canary-1!2!2.0.tar.gz",
			wantErr:  true,
		},
		{
			name:        "simple tar.gz",
			filename:    "requests-2.28.0.tar.gz",
			wantName:    "requests",
			wantVersion: "2.28.0",
			wantErr:     false,
		},
		{
			name:        "zip format",
			filename:    "django-4.2.0.zip",
			wantName:    "django",
			wantVersion: "4.2.0",
			wantErr:     false,
		},
		{
			name:        "hyphenated name",
			filename:    "Flask-RESTful-0.3.10.tar.gz",
			wantName:    "flask-restful",
			wantVersion: "0.3.10",
			wantErr:     false,
		},
		{
			name:        "prerelease version",
			filename:    "package-1.0.0rc1.tar.gz",
			wantName:    "package",
			wantVersion: "1.0.0rc1",
			wantErr:     false,
		},
		{
			name:        "dev version",
			filename:    "package-0.1.0.dev1.tar.gz",
			wantName:    "package",
			wantVersion: "0.1.0.dev1",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSdistFilename(tt.filename)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantName, got.GetName())
			assert.Equal(t, tt.wantVersion, got.GetVersion())
			assert.True(t, got.IsFileDownload())
		})
	}
}

func TestDenormalizePyPIPackageName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"requests", "requests"},
		{"Flask_RESTful", "flask-restful"},
		{"My_Package", "my-package"},
		{"UPPERCASE", "uppercase"},
		{"under_score", "under-score"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := denormalizePyPIPackageName(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetPypiRegistryConfigForHostname(t *testing.T) {
	tests := []struct {
		name         string
		hostname     string
		expectConfig bool
		expectHost   string
	}{
		{
			name:         "exact match files.pythonhosted.org",
			hostname:     "files.pythonhosted.org",
			expectConfig: true,
			expectHost:   "files.pythonhosted.org",
		},
		{
			name:         "exact match pypi.org",
			hostname:     "pypi.org",
			expectConfig: true,
			expectHost:   "pypi.org",
		},
		{
			name:         "subdomain match",
			hostname:     "cdn.files.pythonhosted.org",
			expectConfig: true,
			expectHost:   "files.pythonhosted.org",
		},
		{
			name:         "test pypi",
			hostname:     "test.pypi.org",
			expectConfig: true,
			expectHost:   "test.pypi.org",
		},
		{
			name:         "unknown hostname",
			hostname:     "example.com",
			expectConfig: false,
			expectHost:   "",
		},
		{
			name:         "partial match should not work",
			hostname:     "fakepypi.org",
			expectConfig: false,
			expectHost:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match := (registrySet{entries: pypiRegistryEndpoints}).MatchConnect(tt.hostname, "443")

			if !tt.expectConfig {
				assert.Nil(t, match)
				return
			}

			require.NotNil(t, match)
			assert.Equal(t, tt.expectHost, match.Endpoint.Host)
		})
	}
}

func TestPypiRegistryDomains_ContainsHostname(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		want     bool
	}{
		{
			name:     "exact match",
			hostname: "files.pythonhosted.org",
			want:     true,
		},
		{
			name:     "subdomain match",
			hostname: "cdn.files.pythonhosted.org",
			want:     true,
		},
		{
			name:     "no match",
			hostname: "example.com",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (registrySet{entries: pypiRegistryEndpoints}).MatchConnect(tt.hostname, "443") != nil
			assert.Equal(t, tt.want, got)
		})
	}
}
