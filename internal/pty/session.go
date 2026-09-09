package pty

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/internal/proc"
	"github.com/safedep/ptyx"
	"golang.org/x/term"
)

// InteractiveSession manages a PTY-based command execution with
// support for input/output routing and terminal mode switching.
type InteractiveSession interface {
	// PtyWriter returns the writer to send input to the child process
	PtyWriter() io.Writer

	// PtyReader returns the reader to receive output from the child process
	PtyReader() io.Reader

	// CopyOutputContext copies child output to dst until the child exits (EOF)
	// or ctx is cancelled. On unix it drives the read with a poll(2) loop so it
	// works even when the Go netpoller cannot manage the PTY master, and so it
	// can be cancelled without leaking a goroutine blocked in read().
	CopyOutputContext(ctx context.Context, dst io.Writer) error

	// SetRawMode puts terminal in raw mode (for PTY passthrough)
	SetRawMode() error

	// SetCookedMode restores normal terminal mode (for prompts)
	SetCookedMode() error

	// Wait blocks until the child process exits
	// Returns ExitError if process exited with non-zero code
	Wait() error

	// Close cleans up resources (PTY, terminal state)
	Close() error
}

// IsInteractiveTerminal returns true if stdin is a real terminal (TTY) and
// the process can safely drive it. Returns false in CI environments (when the
// "CI" env var is set to "true"), when input or output is piped, in
// non-interactive shells, or when running as a background job (where putting
// the terminal into raw mode would stop the process with SIGTTOU).
func IsInteractiveTerminal() bool {
	if ci := os.Getenv("CI"); ci != "" && strings.ToLower(ci) == "true" {
		return false
	}

	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return false
	}

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return false
	}

	return isForegroundProcess(os.Stdin.Fd())
}

var _ InteractiveSession = &session{}

type session struct {
	console  ptyx.Console
	spawn    ptyx.Session
	oldState ptyx.RawState // Saved terminal state for restoration
	done     chan struct{}
	stopOnce sync.Once
}

// SessionConfig holds options for creating a session
type SessionConfig struct {
	Command string
	Args    []string
	Env     []string

	// CmdLine is the raw Windows command line, passed to ptyx and then to
	// CreateProcess with no escaping. Set it when the CommandLineToArgvW
	// rules that Args follows are the wrong rules, for example to start a
	// batch file through cmd.exe. Windows only, and exclusive with Args.
	CmdLine string
}

func NewSessionConfig(cmd string, args, env []string) SessionConfig {
	return SessionConfig{
		Command: cmd,
		Args:    args,
		Env:     env,
	}
}

// NewSession creates a new interactive PTY session.
// The terminal is put into raw mode automatically.
func NewSession(ctx context.Context, cfg SessionConfig) (InteractiveSession, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	// 1. Create console
	c, err := ptyx.NewConsole()
	if err != nil {
		return nil, fmt.Errorf("failed to create console: %w", err)
	}
	c.EnableVT()

	// 2. Set raw mode, save old state
	oldState, err := c.MakeRaw()
	if err != nil {
		if closeErr := c.Close(); closeErr != nil {
			log.Warnf("failed to close console after MakeRaw error: %v", closeErr)
		}
		return nil, fmt.Errorf("failed to set raw mode: %w", err)
	}

	// 3. Get terminal size
	cols, rows := c.Size()

	// 4. Spawn the process
	s, err := ptyx.Spawn(ctx, cfg.spawnOpts(cols, rows))
	if err != nil {
		// We are already in error state, restore and close is best effort.
		_ = c.Restore(oldState)
		_ = c.Close()

		return nil, fmt.Errorf("failed to spawn: %w", err)
	}

	sess := &session{
		console:  c,
		spawn:    s,
		oldState: oldState,
		done:     make(chan struct{}),
	}
	go sess.forwardResize()

	return sess, nil
}

func (cfg SessionConfig) validate() error {
	if cfg.Command == "" {
		return fmt.Errorf("pty session requires command")
	}
	if cfg.CmdLine != "" && len(cfg.Args) > 0 {
		return fmt.Errorf("pty session accepts CmdLine or Args, not both")
	}
	return nil
}

func (cfg SessionConfig) spawnOpts(cols, rows int) ptyx.SpawnOpts {
	return ptyx.SpawnOpts{
		Prog:    cfg.Command,
		Args:    cfg.Args,
		CmdLine: cfg.CmdLine,
		Cols:    cols,
		Rows:    rows,
		Env:     cfg.Env,
	}
}

// forwardResize passes terminal size changes to the child. A TUI agent
// keeps its launch size otherwise. The console closes the channel on Close,
// and done covers a console that does not.
func (s *session) forwardResize() {
	ch := s.console.OnResize()
	if ch == nil {
		return
	}
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return
			}
			cols, rows := s.console.Size()
			if err := s.spawn.Resize(cols, rows); err != nil {
				log.Warnf("failed to resize pty: %v", err)
			}
		case <-s.done:
			return
		}
	}
}

func (s *session) PtyWriter() io.Writer { return s.spawn.PtyWriter() }
func (s *session) PtyReader() io.Reader { return s.spawn.PtyReader() }

func (s *session) CopyOutputContext(ctx context.Context, dst io.Writer) error {
	return copyPTYOutput(ctx, dst, s.spawn.PtyReader())
}

func (s *session) SetRawMode() error {
	_, err := s.console.MakeRaw()
	return err
}

func (s *session) SetCookedMode() error {
	return s.console.Restore(s.oldState)
}

func (s *session) Wait() error {
	err := s.spawn.Wait()
	if err != nil {
		if exitErr, ok := err.(*ptyx.ExitError); ok {
			return newExitError(exitErr.ExitCode, exitErr.Sys(), err)
		}
		return newExitError(-1, nil, err)
	}
	return nil
}

func (s *session) Close() error {
	s.stopOnce.Do(func() { close(s.done) })

	// Always restore terminal state
	if s.oldState != nil {
		_ = s.console.Restore(s.oldState)
	}

	if s.spawn != nil {
		_ = s.spawn.Close()
	}

	if s.console != nil {
		_ = s.console.Close()
	}

	return nil
}

// ExitError is returned when the child process exits with non-zero code
type ExitError struct {
	Code     int
	Signaled bool  // true if the child was terminated by a signal (Ctrl+C, SIGTERM, …)
	Err      error // Underlying error from ptyx
}

// newExitError resolves the child's termination into an ExitError. When the
// process was signal-terminated, Code is the conventional 128+signum and
// Signaled is set; otherwise the raw exit code is preserved.
func newExitError(code int, sys any, err error) *ExitError {
	if signum, signaled := proc.SignalInfo(sys); signaled {
		return &ExitError{Code: 128 + signum, Signaled: true, Err: err}
	}
	return &ExitError{Code: code, Err: err}
}

func (e *ExitError) Error() string {
	if e.Code != 0 {
		return fmt.Sprintf("process exited with code %d", e.Code)
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return "unknown process error"
}

// Unwrap allows errors.Is and errors.As to work
func (e *ExitError) Unwrap() error {
	return e.Err
}
