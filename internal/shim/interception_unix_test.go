//go:build unix

package shim

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/safedep/pmg/internal/platform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// On Unix there is one PATH, so InspectInterception resolves each manager
// over the process PATH in order, marks the ones under a shim directory, and
// omits one that does not resolve. No resolution carries an origin.
func TestInspectInterception(t *testing.T) {
	shimDir, nodeDir := t.TempDir(), t.TempDir()
	for _, dir := range []string{shimDir, nodeDir} {
		for _, name := range []string{"npm"} {
			require.NoError(t, os.WriteFile(filepath.Join(dir, name), nil, 0o755))
		}
	}
	require.NoError(t, os.WriteFile(filepath.Join(nodeDir, "pip"), nil, 0o755))
	t.Setenv("PATH", shimDir+string(os.PathListSeparator)+nodeDir)

	inspection, err := InspectInterception([]string{"npm", "pip", "yarn"}, []string{shimDir})
	require.NoError(t, err)

	assert.Equal(t, []ManagerResolution{
		{Name: "npm", Path: filepath.Join(shimDir, "npm"), UnderShim: true, Origin: platform.PathOriginUnknown},
		{Name: "pip", Path: filepath.Join(nodeDir, "pip"), Origin: platform.PathOriginUnknown},
	}, inspection.Resolutions, "configured order kept, unresolved manager omitted")
}

// A shim that names a stable alias of this binary, such as a version
// manager's latest directory, names this binary.
func TestInspectShimFilesThroughAlias(t *testing.T) {
	pmgBin, err := currentExecutable()
	require.NoError(t, err)

	alias := filepath.Join(t.TempDir(), "pmg")
	require.NoError(t, os.Symlink(pmgBin, alias))

	dir := t.TempDir()
	require.NoError(t, NewShimManager(ShimConfig{
		BinDir:          dir,
		PMGBin:          alias,
		PackageManagers: []string{"npm"},
		SkipUserPath:    true,
	}).Install())

	inspection, err := InspectShimFiles(dir, []string{"npm"})
	require.NoError(t, err)
	assert.Empty(t, inspection.Missing)
	assert.Empty(t, inspection.BinaryMissing)
	assert.Empty(t, inspection.BinaryDiffers)
}
