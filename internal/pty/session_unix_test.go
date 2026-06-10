//go:build !windows

package pty

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/safedep/ptyx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const ttyHelperEnv = "PMG_TEST_TTY_HELPER"

// Reproduces https://github.com/safedep/pmg/issues/322: a pmg process started
// as a background job (`pmg npm run test &`) still has the TTY on
// stdin/stdout, but it is not in the terminal's foreground process group.
// Treating it as interactive makes the PTY session call tcsetattr, which
// stops the process with SIGTTOU. IsInteractiveTerminal must report false in
// that situation.
func TestIsInteractiveTerminalBackgroundJob(t *testing.T) {
	exe, err := os.Executable()
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// The helper runs on a fresh PTY as the foreground process group, then
	// moves itself to the background, checking IsInteractiveTerminal in both
	// states.
	sess, err := ptyx.Spawn(ctx, ptyx.SpawnOpts{
		Prog: exe,
		Args: []string{"-test.run", "^TestIsInteractiveTerminalTTYHelper$", "-test.v"},
		Env:  append(envWithoutCI(), ttyHelperEnv+"=1"),
		Cols: 80,
		Rows: 24,
	})
	require.NoError(t, err)
	defer func() {
		require.NoError(t, sess.Close())
	}()

	var output bytes.Buffer
	copyDone := make(chan struct{})
	go func() {
		defer close(copyDone)
		_, _ = io.Copy(&output, sess.PtyReader())
	}()

	waitErr := sess.Wait()

	// The buffer must not be read until the copy goroutine is done, both to
	// avoid a data race and to ensure all helper output has been captured.
	select {
	case <-copyDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for pty output copy to finish")
	}

	out := output.String()
	require.NoError(t, waitErr, "helper failed, output:\n%s", out)
	assert.Contains(t, out, "foreground_interactive=true", "expected interactive in foreground, output:\n%s", out)
	assert.Contains(t, out, "background_interactive=false", "expected non-interactive in background, output:\n%s", out)
}

// TestIsInteractiveTerminalTTYHelper is not a real test. It is re-executed by
// TestIsInteractiveTerminalBackgroundJob on a PTY where it starts as the
// foreground process group.
func TestIsInteractiveTerminalTTYHelper(t *testing.T) {
	if os.Getenv(ttyHelperEnv) != "1" {
		t.Skip("helper for TestIsInteractiveTerminalBackgroundJob")
	}

	fmt.Printf("foreground_interactive=%v\n", IsInteractiveTerminal())

	// Hand the terminal's foreground process group to a child, like a shell
	// does for the foreground job. This process then becomes a background job
	// on the TTY, matching `pmg npm run test &`.
	cmd := exec.Command("sleep", "30")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid:    true,
		Foreground: true,
		Ctty:       int(os.Stdin.Fd()),
	}
	require.NoError(t, cmd.Start())
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	fmt.Printf("background_interactive=%v\n", IsInteractiveTerminal())
}

func envWithoutCI() []string {
	env := make([]string, 0, len(os.Environ()))
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "CI=") {
			continue
		}
		env = append(env, entry)
	}

	return env
}
