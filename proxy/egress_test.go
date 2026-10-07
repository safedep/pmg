package proxy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type denyAllEgress struct{}

func (denyAllEgress) Allows(string, uint16) bool { return false }

func TestNewProxyServerRejectsEgressWithTransparent(t *testing.T) {
	cfg := DefaultProxyConfig()
	cfg.EnableMITM = false
	cfg.Transparent = true
	cfg.Egress = denyAllEgress{}

	_, err := NewProxyServer(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "transparent")
}

func TestNewProxyServerAcceptsEgressWithoutMITM(t *testing.T) {
	cfg := DefaultProxyConfig()
	cfg.EnableMITM = false
	cfg.Egress = denyAllEgress{}

	_, err := NewProxyServer(cfg)
	require.NoError(t, err)
}
