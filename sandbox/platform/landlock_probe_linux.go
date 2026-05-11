//go:build linux

package platform

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

var landlockShimProbe = runLandlockShimProbe

// runLandlockShimProbe verifies that the installed pmg binary can perform the
// same critical operation as the real Landlock shim: create a user namespace
// and install a seccomp-notify filter without setting NO_NEW_PRIVS.
func runLandlockShimProbe() error {
	selfExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve self exe: %w", err)
	}

	cmd := exec.Command(selfExe, "__landlock_probe")
	uid := os.Getuid()
	gid := os.Getgid()
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: uid, Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: gid, Size: 1},
		},
		GidMappingsEnableSetgroups: false,
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(output))
		if msg == "" {
			return fmt.Errorf("run shim probe: %w", err)
		}
		return fmt.Errorf("run shim probe: %w: %s", err, msg)
	}
	return nil
}

// RunLandlockProbe is the hidden self-reexec entry point used by
// runLandlockShimProbe. It intentionally reuses shimInstallSeccomp so the probe
// stays coupled to the exact no-NNP seccomp path the real shim needs.
func RunLandlockProbe() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	notifyFd, err := shimInstallSeccomp(false)
	if err != nil {
		return fmt.Errorf("probe: install seccomp: %w", err)
	}
	if err := unix.Close(notifyFd); err != nil {
		return fmt.Errorf("probe: close notify fd: %w", err)
	}
	return nil
}
