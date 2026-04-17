package extractor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGoExtractorExtract(t *testing.T) {
	tmpDir := t.TempDir()
	goModPath := filepath.Join(tmpDir, "go.mod")

	err := os.WriteFile(goModPath, []byte(`module example.com/app

go 1.24

require (
	github.com/google/uuid v1.6.0
	golang.org/x/text v0.3.0 // indirect
	example.com/localdep v1.0.0
	example.com/forked v1.2.3
)

replace example.com/localdep v1.0.0 => ../localdep
replace example.com/forked v1.2.3 => github.com/acme/forked v1.2.4
`), 0o600)
	require.NoError(t, err)

	extractor := &GoExtractor{}
	packages, err := extractor.Extract(goModPath, tmpDir)
	require.NoError(t, err)
	require.Len(t, packages, 3)

	assert.Equal(t, "github.com/google/uuid", packages[0].GetPackage().GetName())
	assert.Equal(t, "v1.6.0", packages[0].GetVersion())
	assert.Equal(t, "golang.org/x/text", packages[1].GetPackage().GetName())
	assert.Equal(t, "v0.3.0", packages[1].GetVersion())
	assert.Equal(t, "github.com/acme/forked", packages[2].GetPackage().GetName())
	assert.Equal(t, "v1.2.4", packages[2].GetVersion())
}

func TestGoExtractorSkipsUnsupportedManifestFile(t *testing.T) {
	extractor := &GoExtractor{}

	packages, err := extractor.Extract(filepath.Join(t.TempDir(), "go.sum"), ".")
	require.NoError(t, err)
	assert.Empty(t, packages)
}
