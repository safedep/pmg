package proxyserver

import (
	"context"
	"testing"

	"github.com/safedep/pmg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildAnalyzerCacheDisabled(t *testing.T) {
	cfg := config.Get()
	cfg.Config.AnalysisCache.Malysis.Enabled = false

	a, closer, err := buildAnalyzer(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, a)
	require.NotNil(t, closer)
	assert.NoError(t, closer())
}
