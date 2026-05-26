package extractor

import (
	"os"
	"path/filepath"
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/stretchr/testify/assert"
)

func TestGoExtractor(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "go-extractor-test")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	goModContent := `module github.com/test/project

go 1.21

require (
	github.com/stretchr/testify v1.7.0
	github.com/safedep/dry v0.1.0
)
`
	goModPath := filepath.Join(tempDir, "go.mod")
	err = os.WriteFile(goModPath, []byte(goModContent), 0644)
	assert.NoError(t, err)

	extractor := &GoExtractor{}
	packages, err := extractor.Extract(goModPath, tempDir)
	assert.NoError(t, err)

	// stdlib, testify, dry
	assert.GreaterOrEqual(t, len(packages), 2)
	
	packageNames := make(map[string]string)
	for _, pkg := range packages {
		packageNames[pkg.Package.Name] = pkg.Version
		assert.Equal(t, packagev1.Ecosystem_ECOSYSTEM_GO, pkg.Package.Ecosystem)
	}

	assert.Contains(t, packageNames, "github.com/stretchr/testify")
	assert.Contains(t, packageNames, "github.com/safedep/dry")
	
	// osv-scalibr might strip 'v' prefix
	assert.True(t, packageNames["github.com/stretchr/testify"] == "v1.7.0" || packageNames["github.com/stretchr/testify"] == "1.7.0")
	assert.True(t, packageNames["github.com/safedep/dry"] == "v0.1.0" || packageNames["github.com/safedep/dry"] == "0.1.0")
}
