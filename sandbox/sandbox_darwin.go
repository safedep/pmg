//go:build darwin
// +build darwin

package sandbox

import (
	"context"
	"os/exec"

	"github.com/safedep/pmg/sandbox/seatbelt"
)

// darwinSandboxAdapter adapts the seatbelt implementation to the Sandbox interface.
type darwinSandboxAdapter struct {
	seatbelt *seatbelt.SeatbeltSandbox
}

// newPlatformSandbox creates a platform-specific sandbox instance for macOS.
// Uses Seatbelt (sandbox-exec) for process isolation.
func newPlatformSandbox() (Sandbox, error) {
	sb, err := seatbelt.NewSeatbeltSandbox()
	if err != nil {
		return nil, err
	}

	return &darwinSandboxAdapter{seatbelt: sb}, nil
}

func (d *darwinSandboxAdapter) Execute(ctx context.Context, cmd *exec.Cmd, policy *SandboxPolicy) error {
	// Convert sandbox.SandboxPolicy to seatbelt.SandboxPolicy
	seatbeltPolicy := &seatbelt.SandboxPolicy{
		Name:            policy.Name,
		Description:     policy.Description,
		PackageManagers: policy.PackageManagers,
		ViolationMode:   policy.ViolationMode,
		Filesystem: seatbelt.FilesystemPolicy{
			AllowRead:  policy.Filesystem.AllowRead,
			AllowWrite: policy.Filesystem.AllowWrite,
			DenyRead:   policy.Filesystem.DenyRead,
			DenyWrite:  policy.Filesystem.DenyWrite,
		},
		Network: seatbelt.NetworkPolicy{
			AllowOutbound: policy.Network.AllowOutbound,
			DenyOutbound:  policy.Network.DenyOutbound,
		},
		Process: seatbelt.ProcessPolicy{
			AllowExec: policy.Process.AllowExec,
			DenyExec:  policy.Process.DenyExec,
		},
	}

	return d.seatbelt.Execute(ctx, cmd, seatbeltPolicy)
}

func (d *darwinSandboxAdapter) Name() string {
	return d.seatbelt.Name()
}

func (d *darwinSandboxAdapter) IsAvailable() bool {
	return d.seatbelt.IsAvailable()
}
