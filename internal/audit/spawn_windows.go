//go:build windows

package audit

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// applyDetachAttrs configures cmd so that the child process is fully
// detached from the parent's console and process group. DETACHED_PROCESS
// removes the inherited console; CREATE_NEW_PROCESS_GROUP isolates the
// child from Ctrl+C events sent to the parent's group.
func applyDetachAttrs(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
	}
}
