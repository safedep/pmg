package proxyserver

import (
	"path/filepath"
	"testing"

	"github.com/safedep/pmg/config"
	"github.com/stretchr/testify/assert"
)

func TestResolveStatePath(t *testing.T) {
	cfg := config.Get()

	t.Run("flag override wins", func(t *testing.T) {
		assert.Equal(t, "/custom/proxy.json", ResolveStatePath("/custom/proxy.json", cfg))
	})

	t.Run("defaults to cacheDir", func(t *testing.T) {
		want := filepath.Join(cfg.CacheDir(), "proxy-state.json")
		assert.Equal(t, want, ResolveStatePath("", cfg))
	})
}
