//go:build windows

package alias

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// parentShellName names the shell that started this process. Only a known
// shell counts: an MDM agent, an IDE task or `go test` is a parent too.
func parentShellName() string {
	exe, err := parentProcessName()
	if err != nil {
		return ""
	}
	switch name := strings.ToLower(strings.TrimSuffix(exe, ".exe")); name {
	case "pwsh", "powershell", "cmd", "bash":
		return name
	}
	return ""
}

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
