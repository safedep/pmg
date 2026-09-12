package interceptors

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPypiLegacyRoutes(t *testing.T) {
	for _, tt := range []struct {
		filename, name, version string
		index                   bool
		invalid                 bool
	}{
		{filename: "index.html", name: "demo", index: true},
		{filename: "numpy-1.9.2-cp27-none-win32.egg", name: "numpy", version: "1.9.2"},
		{filename: "demo-0.6c11-py2.7-linux-x86_64.egg", name: "demo", version: "0.6rc11"},
		{filename: "demo-1.0.egg", name: "demo", version: "1.0"},
		{filename: "PyYAML-3.10.win32-py2.5.exe", name: "pyyaml", version: "3.10"},
		{filename: "demo-1.0.win-amd64.exe", name: "demo", version: "1.0"},
		{filename: "invalid.whl", invalid: true},
		{filename: "demo-1.0.0-build2.tar.gz", invalid: true},
		{filename: "demo-1.0.0-linux.tar.gz", invalid: true},
		{filename: "demo-1.0-final.tar.gz", invalid: true},
		{filename: "Flask-RESTful-0.3.10.tar.gz", name: "flask-restful", version: "0.3.10"},
		{filename: "demo-1.0-post1.tar.gz", name: "demo", version: "1.0.post1"},
		{filename: "demo-invalid.egg", invalid: true},
		{filename: "demo-invalid.win32.exe", invalid: true},
	} {
		for _, route := range []struct {
			name, prefix string
			parser       registryURLParser
		}{
			{name: "custom", prefix: "/demo/", parser: pypiCustomParser{baseEndsInSimple: true}},
			{name: "builtin", prefix: "/simple/demo/", parser: pypiOrgParser{}},
		} {
			t.Run(route.name+"/"+tt.filename, func(t *testing.T) {
				info, err := route.parser.ParseURL(route.prefix + tt.filename)
				if tt.invalid {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)
				assert.Equal(t, tt.name, info.GetName())
				assert.Equal(t, tt.version, info.GetVersion())
				assert.Equal(t, !tt.index, info.IsFileDownload())
				assert.Equal(t, tt.index, pypiIsSimpleAPIMetadataRequest(info))
			})
		}
	}
}

func TestPypiRootIndex(t *testing.T) {
	for _, route := range []struct {
		name, path string
		parser     registryURLParser
	}{
		{"builtin root", "/simple/", pypiOrgParser{}},
		{"builtin HTML", "/simple/index.html", pypiOrgParser{}},
		{"custom root", "/", pypiCustomParser{baseEndsInSimple: true}},
		{"custom HTML", "/index.html", pypiCustomParser{baseEndsInSimple: true}},
	} {
		t.Run(route.name, func(t *testing.T) {
			info, err := route.parser.ParseURL(route.path)
			require.NoError(t, err)
			assert.Empty(t, info.GetName())
			assert.Empty(t, info.GetVersion())
			assert.False(t, info.IsFileDownload())
			assert.False(t, pypiIsSimpleAPIMetadataRequest(info))
		})
	}
}
