package setup

import (
	"bytes"
	"context"
	"testing"

	"github.com/safedep/pmg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunCache_NoFile(t *testing.T) {
	t.Setenv("PMG_CACHE_DIR", t.TempDir())
	config.Reload()
	cfg := config.Get()

	var out bytes.Buffer
	require.NoError(t, runCacheStatus(context.Background(), cfg, &out))
	assert.Contains(t, out.String(), "Entries: 0")

	out.Reset()
	require.NoError(t, runCacheClear(context.Background(), cfg, &out))
	assert.Contains(t, out.String(), "already empty")
}
