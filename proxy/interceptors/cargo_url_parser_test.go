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
