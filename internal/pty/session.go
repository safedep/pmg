package pty

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/KennethanCeyer/ptyx"
	"golang.org/x/term"
)

// InteractiveSession manages a PTY-based command execution with
// support for input/output routing and terminal mode switching.
type InteractiveSession interface {
	// PtyWriter returns the writer to send input to the child process
	PtyWriter() io.Writer

	// PtyReader returns the reader to receive output from the child process
	PtyReader() io.Reader

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

// IsInteractiveTerminal returns true if stdin is a real terminal (TTY).
// Returns false in CI environments, when input is piped, or in non-interactive shells.
func IsInteractiveTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

var _ InteractiveSession = &session{}

type session struct {
	console  ptyx.Console
	spawn    ptyx.Session
	oldState ptyx.RawState // Saved terminal state for restoration
}

// SessionConfig holds options for creating a session
type SessionConfig struct {
	Command string
	Args    []string
	Env     []string
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
	if cfg.Command == "" {
		return nil, fmt.Errorf("pty session requires command")
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
		c.Close()
		return nil, fmt.Errorf("failed to set raw mode: %w", err)
	}

	// 3. Get terminal size
	cols, rows := c.Size()

	// 4. Spawn the process
	s, err := ptyx.Spawn(ctx, ptyx.SpawnOpts{
		Prog: cfg.Command,
		Args: cfg.Args,
		Cols: cols,
		Rows: rows,
		Env:  cfg.Env,
	})
	if err != nil {
		c.Restore(oldState)
		c.Close()
		return nil, fmt.Errorf("failed to spawn: %w", err)
	}

	return &session{
		console:  c,
		spawn:    s,
		oldState: oldState,
	}, nil
}

func (s *session) PtyWriter() io.Writer { return s.spawn.PtyWriter() }
func (s *session) PtyReader() io.Reader { return s.spawn.PtyReader() }

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
			return &ExitError{Code: exitErr.ExitCode, Err: err}
		}
		return &ExitError{Code: -1, Err: err}
	}
	return nil
}

func (s *session) Close() error {
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
	Code int
	Err  error // Underlying error from ptyx
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
