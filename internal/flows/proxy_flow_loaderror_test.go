package flows

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/safedep/pmg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withUnloadableProxyRegistries points PMG at a config file containing an
// invalid proxy.registries entry and reloads, setting LoadError. Cleanup
// restores the previous state.
func withUnloadableProxyRegistries(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	broken := `
proxy:
  registries:
    - name: bad
      ecosystem: maven
      endpoints:
        - url: https://packages.example.test/npm
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yml"), []byte(broken), 0o644))
	require.NoError(t, os.Setenv("PMG_CONFIG_DIR", dir))
	config.Reload()
	t.Cleanup(func() {
		_ = os.Unsetenv("PMG_CONFIG_DIR")
		config.Reload()
	})
	require.Error(t, config.LoadError())
}

func TestProxyFlowRunRejectsUnloadableProxyRegistries(t *testing.T) {
	withUnloadableProxyRegistries(t)

	var flow proxyFlow
	err := flow.Run(context.Background(), nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid proxy registries")
}
