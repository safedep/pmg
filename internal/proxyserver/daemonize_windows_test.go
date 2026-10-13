//go:build windows

package proxyserver

import (
	"testing"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDaemonizeNamesTheUnsupportedFlag(t *testing.T) {
	_, err := Daemonize(ProxyDaemonConfig{}, "", "", nil)
	require.Error(t, err)

	ue, ok := usefulerror.AsUsefulError(err)
	require.True(t, ok)
	assert.Equal(t, errcodes.UnsupportedPlatform, ue.Code())
	assert.Equal(t, "pmg proxy start --daemon is not supported on Windows", ue.HumanError())
}
