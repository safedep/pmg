//go:build linux

package platform

import (
	"context"
	"os/exec"
	"testing"

	"github.com/safedep/dry/utils"
	"github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLinuxDriversRejectNetworkViaProxyOnly(t *testing.T) {
	bwrap, err := newBubblewrapSandbox()
	require.NoError(t, err)

	drivers := []struct {
		name string
		sb   sandbox.Sandbox
	}{
		{"bubblewrap", bwrap},
		{"landlock", &landlockSandbox{abi: newLandlockABI(4)}},
	}

	policy := &sandbox.SandboxPolicy{
		Name:                "lockdown",
		PackageManagers:     []string{"npm"},
		Filesystem:          sandbox.FilesystemPolicy{AllowRead: []string{"/tmp"}},
		NetworkViaProxyOnly: utils.PtrTo(true),
	}

	for _, d := range drivers {
		t.Run(d.name, func(t *testing.T) {
			cmd := exec.Command("/bin/true")
			result, err := d.sb.Execute(context.Background(), cmd, policy,
				&sandbox.ExecutionContext{ProxyAddr: "127.0.0.1:54321"})

			require.Error(t, err)
			assert.Nil(t, result)
			assert.Contains(t, err.Error(), "not yet supported on this platform")
		})
	}
}
