package interceptors

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCargoIndexParserParseURL(t *testing.T) {
	cases := []struct {
		path        string
		name        string
		requestType string
		wantErr     bool
	}{
		{path: "/config.json", requestType: cargoRequestConfig},
		{path: "/1/a", name: "a", requestType: cargoRequestIndex},
		{path: "/2/ab", name: "ab", requestType: cargoRequestIndex},
		{path: "/3/s/syn", name: "syn", requestType: cargoRequestIndex},
		{path: "/se/rd/serde", name: "serde", requestType: cargoRequestIndex},
		{path: "/to/ki/tokio", name: "tokio", requestType: cargoRequestIndex},
		{path: "/in/fl/inflector", name: "inflector", requestType: cargoRequestIndex},
		{path: "/", wantErr: true},
		{path: "/serde", wantErr: true},
		{path: "/xx/yy/serde", wantErr: true},
		{path: "/2/abc", wantErr: true},
		{path: "/se/rd/serde/extra", wantErr: true},
	}

	parser := cargoIndexParser{}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			info, err := parser.ParseURL(tc.path)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.name, info.GetName())
			assert.False(t, info.IsFileDownload())

			crateInfo, ok := info.(*cargoCrateInfo)
			require.True(t, ok)
			assert.Equal(t, tc.requestType, crateInfo.requestType)
		})
	}
}

func TestCargoDownloadParserParseURL(t *testing.T) {
	cases := []struct {
		path    string
		name    string
		version string
		wantErr bool
	}{
		{path: "/crates/serde/1.0.219/download", name: "serde", version: "1.0.219"},
		{path: "/crates/serde/serde-1.0.219.crate", name: "serde", version: "1.0.219"},
		{path: "/crates/Inflector/0.11.4/download", name: "inflector", version: "0.11.4"},
		{path: "/crates/Inflector/Inflector-0.11.4.crate", name: "inflector", version: "0.11.4"},
		{path: "/crates/my-crate/my-crate-0.1.0-alpha.1.crate", name: "my-crate", version: "0.1.0-alpha.1"},
		{path: "/crates/serde", wantErr: true},
		{path: "/crates/serde/1.0.219", wantErr: true},
		{path: "/crates/serde/other-1.0.219.crate", wantErr: true},
		{path: "/crates//1.0.219/download", wantErr: true},
		{path: "/other/serde/1.0.219/download", wantErr: true},
	}

	parser := cargoDownloadParser{}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			info, err := parser.ParseURL(tc.path)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.name, info.GetName())
			assert.Equal(t, tc.version, info.GetVersion())
			assert.True(t, info.IsFileDownload())
		})
	}
}

func TestCargoSparseIndexPath(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{"a", "1/a"},
		{"ab", "2/ab"},
		{"syn", "3/s/syn"},
		{"serde", "se/rd/serde"},
		{"Inflector", "in/fl/inflector"},
	}

	for _, tc := range cases {
		assert.Equal(t, tc.want, cargoSparseIndexPath(tc.name), "name %q", tc.name)
	}
}

func TestCargoCustomParserParseURL(t *testing.T) {
	cases := []struct {
		name        string
		path        string
		crate       string
		version     string
		requestType string
	}{
		{name: "config at the base", path: "/config.json", requestType: cargoRequestConfig},
		{name: "index, 1 character", path: "/1/a", crate: "a", requestType: cargoRequestIndex},
		{name: "index, 3 characters", path: "/3/s/syn", crate: "syn", requestType: cargoRequestIndex},
		{name: "index, long name", path: "/se/rd/serde", crate: "serde", requestType: cargoRequestIndex},
		{name: "index of a crate named download", path: "/do/wn/download", crate: "download", requestType: cargoRequestIndex},
		{name: "download appended to a dl URL", path: "/serde/1.0.219/download", crate: "serde", version: "1.0.219", requestType: cargoRequestDownload},
		{name: "download under api/v1/crates (Gitea, Kellnr)", path: "/api/v1/crates/serde/1.0.219/download", crate: "serde", version: "1.0.219", requestType: cargoRequestDownload},
		{name: "download keeps a prerelease", path: "/v1/crates/foo-bar/1.0.0-rc.1/download", crate: "foo-bar", version: "1.0.0-rc.1", requestType: cargoRequestDownload},
		{name: "download name is lowercased", path: "/Inflector/0.11.4/download", crate: "inflector", version: "0.11.4", requestType: cargoRequestDownload},
		{name: "crate file under its name", path: "/crates/serde/serde-1.0.219.crate", crate: "serde", version: "1.0.219", requestType: cargoRequestDownload},
		{name: "crate file under a lowerprefix", path: "/se/rd/serde-1.0.219.crate", crate: "serde", version: "1.0.219", requestType: cargoRequestDownload},
		{name: "crate file with hyphens and a prerelease", path: "/files/foo-bar-1.0.0-rc.1.crate", crate: "foo-bar", version: "1.0.0-rc.1", requestType: cargoRequestDownload},
		{name: "crate file whose name ends in a number", path: "/x-1-2.0.0.crate", crate: "x-1", version: "2.0.0", requestType: cargoRequestDownload},
		{name: "index of a name with a leading underscore", path: "/_f/oo/_foo", crate: "_foo", requestType: cargoRequestIndex},
		{name: "download of a name with a leading underscore", path: "/_foo/1.0.0/download", crate: "_foo", version: "1.0.0", requestType: cargoRequestDownload},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info, err := cargoCustomParser{}.ParseURL(tc.path)
			require.NoError(t, err)

			crateInfo, ok := info.(*cargoCrateInfo)
			require.True(t, ok)
			assert.Equal(t, tc.crate, crateInfo.name)
			assert.Equal(t, tc.version, crateInfo.version)
			assert.Equal(t, tc.requestType, crateInfo.requestType)
		})
	}
}

func TestCargoCustomParserRejectsUnknownPaths(t *testing.T) {
	for _, path := range []string{
		"/",
		"/api/v1/config.json",
		"/serde",
		"/xx/yy/serde",
		"/serde/1.0/download",
		"/serde/latest/download",
		"/download",
		"/1.0.219/download",
		"/files/0f9a3c.crate",
		"/files/serde.crate",
		"/files/serde-1.0.crate",
		"/files/serde.json-1.0.0.crate",
		"/api/v1/crates/new",
	} {
		t.Run(path, func(t *testing.T) {
			_, err := cargoCustomParser{}.ParseURL(path)
			assert.Error(t, err)
		})
	}
}

func TestCargoIndexParserRejectsCrateFiles(t *testing.T) {
	_, err := cargoIndexParser{}.ParseURL("/se/rd/serde-1.0.219.crate")
	assert.Error(t, err)
}
