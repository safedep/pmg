package platform

import (
	"path/filepath"

	"github.com/safedep/dry/log"
	"golang.org/x/sys/windows"
)

// stillActive matches Windows STILL_ACTIVE (STATUS_PENDING).
const stillActive uint32 = 259

func parentProcessName() (string, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(windows.Getppid()))
	if err != nil {
		return "", err
	}
	defer func() { _ = windows.CloseHandle(handle) }()

	var buf [windows.MAX_LONG_PATH]uint16
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(handle, 0, &buf[0], &size); err != nil {
		return "", err
	}
	return filepath.Base(windows.UTF16ToString(buf[:size])), nil
}

func isProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer func() {
		if cerr := windows.CloseHandle(handle); cerr != nil {
			log.Warnf("platform: close process handle for pid %d: %v", pid, cerr)
		}
	}()

	var exitCode uint32
	if err := windows.GetExitCodeProcess(handle, &exitCode); err != nil {
		return false
	}
	return exitCode == stillActive
}
