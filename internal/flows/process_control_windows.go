//go:build windows
// +build windows

package flows

import (
	"fmt"
	"os/exec"

	"golang.org/x/sys/windows"
)

var (
	modntdll             = windows.NewLazySystemDLL("ntdll.dll")
	procNtSuspendProcess = modntdll.NewProc("NtSuspendProcess")
	procNtResumeProcess  = modntdll.NewProc("NtResumeProcess")
)

// platformPauseProcess suspends the process using Windows NT API.
//
// Known limitations:
// - Race condition: threads created during suspension are not suspended
// - Remote thread injection still possible (very rare)
//
// For PMG's use case (brief suspension during user prompts), these limitations
// are acceptable.
//
// References:
// - gopsutil: https://github.com/shirou/gopsutil/blob/master/process/process_windows.go
// - Analysis: https://github.com/diversenok/Suspending-Techniques
func platformPauseProcess(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}

	handle, err := windows.OpenProcess(
		windows.PROCESS_SUSPEND_RESUME,
		false,
		uint32(cmd.Process.Pid),
	)
	if err != nil {
		return fmt.Errorf("failed to open process for suspension: %w", err)
	}

	defer windows.CloseHandle(handle)

	r1, _, _ := procNtSuspendProcess.Call(uintptr(handle))
	if r1 != 0 {
		return fmt.Errorf("NtSuspendProcess failed with NTSTATUS=0x%.8X", r1)
	}

	return nil
}

// platformResumeProcess resumes a suspended process using Windows NT API.
func platformResumeProcess(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}

	handle, err := windows.OpenProcess(
		windows.PROCESS_SUSPEND_RESUME,
		false,
		uint32(cmd.Process.Pid),
	)
	if err != nil {
		return fmt.Errorf("failed to open process for resumption: %w", err)
	}

	defer windows.CloseHandle(handle)

	r1, _, _ := procNtResumeProcess.Call(uintptr(handle))
	if r1 != 0 {
		return fmt.Errorf("NtResumeProcess failed with NTSTATUS=0x%.8X", r1)
	}

	return nil
}
