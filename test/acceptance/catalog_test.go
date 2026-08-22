package acceptance

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeriveFeatureID(t *testing.T) {
	cases := map[string]string{
		"npm/guard/malware-block.txtar":     "npm/guard/malware-block",
		"npm/dry-run/clean-allow.txtar":     "npm/dry-run/clean-allow",
		"setup/install/shims-created.txtar": "setup/install/shims-created",
	}
	for in, want := range cases {
		assert.Equal(t, want, DeriveFeatureID(filepath.FromSlash(in)))
	}
}

func TestLoadCatalog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
- id: npm/guard/malware-block
  title: "npm install of a known-malicious package is blocked"
  surface: npm
  tier: P0
  guarantee: "A malware verdict is never installed; pmg exits non-zero."
- id: setup/install/shims-created
  title: "setup install creates shims"
  surface: setup
  tier: P1
  guarantee: "pmg setup install creates package-manager shims."
`), 0o600))

	cat, err := LoadCatalog(path)
	require.NoError(t, err)
	assert.Equal(t, []string{"npm/guard/malware-block", "setup/install/shims-created"}, cat.IDs())
	assert.True(t, cat.Has("npm/guard/malware-block"))
	g, ok := cat.Get("setup/install/shims-created")
	require.True(t, ok)
	assert.Equal(t, TierP1, g.Tier)
	assert.Equal(t, "setup", g.Surface)
}

func TestLoadCatalogRejectsBadTierAndDupes(t *testing.T) {
	dir := t.TempDir()
	badTier := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(badTier, []byte(`
- id: a/b/c
  surface: npm
  tier: P9
  guarantee: x
`), 0o600))
	_, err := LoadCatalog(badTier)
	assert.Error(t, err)

	dupe := filepath.Join(dir, "dupe.yaml")
	require.NoError(t, os.WriteFile(dupe, []byte(`
- id: a/b/c
  surface: npm
  tier: P0
  guarantee: x
- id: a/b/c
  surface: npm
  tier: P0
  guarantee: y
`), 0o600))
	_, err = LoadCatalog(dupe)
	assert.Error(t, err)
}
