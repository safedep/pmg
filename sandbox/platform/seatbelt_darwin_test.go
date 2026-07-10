//go:build darwin
// +build darwin

package platform

import (
	"context"
	"os"
	"os/exec"
	"testing"

	"github.com/safedep/dry/utils"
	"github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSeatbeltDarwin(t *testing.T) {
	policy := &sandbox.SandboxPolicy{
		Name:            "test",
		Description:     "test",
		PackageManagers: []string{"npm"},
		Filesystem: sandbox.FilesystemPolicy{
			AllowRead:  []string{"/tmp"},
			AllowWrite: []string{"/tmp"},
			DenyRead:   []string{"/private/var"},
			DenyWrite:  []string{"/private/var"},
		},
		Network: sandbox.NetworkPolicy{
			AllowOutbound: []string{"*:*"},
		},
		Process: sandbox.ProcessPolicy{
			AllowExec: []string{"/bin/sh"},
			DenyExec:  []string{"/bin/bash"},
		},
	}

	sb, err := newSeatbeltSandbox()
	assert.NoError(t, err)

	cmd := exec.Command("npm", "install", "lodash")
	npmResolvedPath := cmd.Path

	result, err := sb.Execute(context.Background(), cmd, policy, nil)
	assert.NoError(t, err)
	assert.True(t, result.ShouldRun(), "command should be runnable because seatbelt only patches the command")

	assert.Equal(t, cmd.Path, "/usr/bin/sandbox-exec")
	assert.Equal(t, cmd.Args, []string{"sandbox-exec", "-f", sb.tempProfilePath, npmResolvedPath, "install", "lodash"})

	err = result.Close()
	assert.NoError(t, err)

	assert.NoFileExists(t, sb.tempProfilePath)
}

func TestSeatbeltExecuteLockdownValidation(t *testing.T) {
	lockdownPolicy := &sandbox.SandboxPolicy{
		Name:            "lockdown",
		PackageManagers: []string{"npm"},
		Filesystem: sandbox.FilesystemPolicy{
			AllowRead:  []string{"/tmp"},
			AllowWrite: []string{"/tmp"},
		},
		NetworkViaProxyOnly: utils.PtrTo(true),
	}

	tests := []struct {
		name    string
		rt      *sandbox.ExecutionContext
		wantErr string
	}{
		{"nil execution context", nil, "requires the PMG proxy"},
		{"empty proxy address", &sandbox.ExecutionContext{}, "requires the PMG proxy"},
		{"non-loopback proxy address", &sandbox.ExecutionContext{ProxyAddr: "192.168.1.5:9999"}, "loopback"},
		{"unparseable proxy address", &sandbox.ExecutionContext{ProxyAddr: "not-an-address"}, "loopback"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sb, err := newSeatbeltSandbox()
			require.NoError(t, err)

			cmd := exec.Command("/usr/bin/true")
			result, err := sb.Execute(context.Background(), cmd, lockdownPolicy, tt.rt)

			require.Error(t, err)
			assert.Nil(t, result)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestSeatbeltExecuteLockdownWrapsCommand(t *testing.T) {
	policy := &sandbox.SandboxPolicy{
		Name:            "lockdown",
		PackageManagers: []string{"npm"},
		Filesystem: sandbox.FilesystemPolicy{
			AllowRead:  []string{"/tmp"},
			AllowWrite: []string{"/tmp"},
		},
		NetworkViaProxyOnly: utils.PtrTo(true),
	}

	sb, err := newSeatbeltSandbox()
	require.NoError(t, err)

	cmd := exec.Command("/usr/bin/true")
	result, err := sb.Execute(context.Background(), cmd, policy,
		&sandbox.ExecutionContext{ProxyAddr: "127.0.0.1:54321"})
	require.NoError(t, err)
	assert.True(t, result.ShouldRun())
	assert.Equal(t, "/usr/bin/sandbox-exec", cmd.Path)

	profile, err := os.ReadFile(sb.tempProfilePath)
	require.NoError(t, err)
	assert.Contains(t, string(profile), `(allow network-outbound (remote ip "localhost:54321"))`)

	require.NoError(t, result.Close())
}
