//go:build windows

package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/safedep/pmg/internal/shim"
)

// launchCommand builds the command PMG starts for the resolved manager.
//
// CreateProcess starts the program named by lpApplicationName, which Go
// fills from Cmd.Path, and a batch file is not a program. A .cmd resolved
// from a shim invocation therefore runs through cmd.exe with one command
// line that carries the raw tail the shim captured. PMG adds no second
// serialisation, so the manager sees the result of one parse rather than
// two. Every other case, a .exe or a direct `pmg npm ...`, keeps the plain
// exec.Cmd.
func launchCommand(ctx context.Context, binary string, args []string) *exec.Cmd {
	rawArgs, viaShim := shim.ShimInvocation()
	line, ok := cmdExeCommandLine(binary, viaShim, rawArgs)
	if !ok {
		return exec.CommandContext(ctx, binary, args...)
	}

	cmd := exec.CommandContext(ctx, comspec())
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: line}
	return cmd
}

// rawCommandLine returns the command line launchCommand set, so the PTY
// path hands ptyx the same line instead of rebuilding one from Args.
func rawCommandLine(cmd *exec.Cmd) string {
	if cmd.SysProcAttr == nil {
		return ""
	}
	return cmd.SysProcAttr.CmdLine
}

// cmdExeCommandLine forms the cmd.exe command line for a batch file. /s
// controls how cmd.exe strips the outer quote pair, which is why the whole
// command carries one. /v:off holds delayed expansion off whatever the
// parent enabled. The tail is appended byte for byte and never quoted.
func cmdExeCommandLine(binary string, viaShim bool, rawArgs string) (string, bool) {
	if !viaShim {
		return "", false
	}
	if ext := strings.ToLower(filepath.Ext(binary)); ext != ".cmd" && ext != ".bat" {
		return "", false
	}

	tail := ""
	if rawArgs != "" {
		tail = " " + rawArgs
	}
	return fmt.Sprintf(`cmd.exe /d /s /v:off /c ""%s"%s"`, binary, tail), true
}

func comspec() string {
	if c := os.Getenv("COMSPEC"); c != "" {
		return c
	}
	return "cmd.exe"
}
