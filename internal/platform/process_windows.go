package platform

import (
	"path/filepath"

	"golang.org/x/sys/windows"
)

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
