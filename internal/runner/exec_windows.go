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

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/internal/shim"
	"golang.org/x/sys/windows"
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

	cmd := exec.CommandContext(ctx, interpreterPath())
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
//
// The interpreter is named by absolute path. The PTY path hands this line to
// ptyx, which passes nil for lpApplicationName, so CreateProcess would
// resolve a bare `cmd.exe` by its own search order, and that order puts the
// current directory ahead of System32. A repository carrying a cmd.exe would
// then run on `npm install`.
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
	return fmt.Sprintf(`"%s" /d /s /v:off /c ""%s"%s"`, interpreterPath(), binary, tail), true
}

// interpreterPath returns the absolute path of the command interpreter.
// COMSPEC is honoured only when it is already absolute, because a relative
// value would put the search back in the caller's hands. The system
// directory is the fallback, rather than a PATH lookup, because neither PATH
// nor the current directory can influence it.
func interpreterPath() string {
	if c := os.Getenv("COMSPEC"); filepath.IsAbs(c) {
		return c
	}

	systemDir, err := windows.GetSystemDirectory()
	if err != nil {
		log.Warnf("failed to resolve the system directory: %v", err)
		return `C:\Windows\System32\cmd.exe`
	}
	return filepath.Join(systemDir, "cmd.exe")
}
