//go:build darwin
// +build darwin

package platform

import (
	"context"
	"os/exec"
	"testing"

	"github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
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

	result, err := sb.Execute(context.Background(), cmd, policy)
	assert.NoError(t, err)
	assert.True(t, result.ShouldRun(), "command should be runnable because seatbelt only patches the command")

	assert.Equal(t, cmd.Path, "/usr/bin/sandbox-exec")
	assert.Equal(t, cmd.Args, []string{"sandbox-exec", "-f", sb.tempProfilePath, npmResolvedPath, "install", "lodash"})

	err = result.Close()
	assert.NoError(t, err)

	assert.NoFileExists(t, sb.tempProfilePath)
}
