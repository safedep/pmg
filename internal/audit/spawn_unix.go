//go:build !windows

package audit

import (
	"os/exec"
	"syscall"
)

// applyDetachAttrs configures cmd so that the child process is fully
// detached from the parent's controlling terminal and process group. Setsid
// makes the child its own session leader, so the parent can exit immediately
// without the child receiving SIGHUP/SIGINT from the parent's shell.
func applyDetachAttrs(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
