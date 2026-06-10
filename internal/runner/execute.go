package runner

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/pty"
	"github.com/safedep/pmg/internal/shim"
	"github.com/safedep/pmg/packagemanager"
	"github.com/safedep/pmg/sandbox"
	"github.com/safedep/pmg/sandbox/executor"
)

type ExecutionMode int

const (
	ExecutionModeDirect ExecutionMode = iota
	ExecutionModePTY
	ExecutionModeAuto
)

// outputDrainGrace bounds how long we wait for the PTY output reader to finish
// after the child exits before forcing it to stop.
const outputDrainGrace = 2 * time.Second

type ExecuteOptions struct {
	PackageManagerName string
	DryRun             bool
	EnvOverrides       []string
	DirectEnvOverrides []string
	PTYEnvOverrides    []string
	Mode               ExecutionMode

	// BeforeDirectRun runs after command/env construction and before sandbox
	// application for non-PTY execution. Use this for setup that must exist even
	// when a sandbox implementation executes the child inside ApplySandbox.
	BeforeDirectRun func() error

	// PreparePTYSession runs after the PTY session and routers are created, but
	// before waiting for the child process. Use this to wire interactive routing,
	// prompts, or output buffering around an already-started PTY child.
	PreparePTYSession func(*PTYRuntime) error

	IsInteractive func() bool
}

type PTYRuntime struct {
	Session      pty.InteractiveSession
	OutputRouter *pty.OutputRouter
	InputRouter  *pty.InputRouter
	PromptReader *io.PipeReader
	PromptWriter *io.PipeWriter
}

// Execute runs a package manager command without proxy or guard analysis.
// It applies sandbox policy if configured, then executes the command directly.
func Execute(ctx context.Context, pc *packagemanager.ParsedCommand, pmName string, dryRun bool) error {
	return ExecuteWithOptions(ctx, pc, ExecuteOptions{
		PackageManagerName: pmName,
		DryRun:             dryRun,
		Mode:               ExecutionModeDirect,
	})
}

// ExecuteWithOptions runs a package manager command through PMG's shared
// execution path: real binary resolution, environment setup, sandbox
// application, command launch, sandbox cleanup, and exit error wrapping.
func ExecuteWithOptions(ctx context.Context, pc *packagemanager.ParsedCommand, opts ExecuteOptions) error {
	if len(pc.Command.Exe) == 0 {
		return fmt.Errorf("no command to execute")
	}

	if opts.DryRun {
		log.Debugf("Dry run, skipping command execution")
		return nil
	}

	realBinary, err := shim.ResolveRealBinary(pc.Command.Exe)
	if err != nil {
		return fmt.Errorf("failed to resolve real %s binary: %w", pc.Command.Exe, err)
	}

	mode := executionMode(opts)

	cmd := exec.CommandContext(ctx, realBinary, pc.Command.Args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = commandEnv(modeEnvOverrides(opts, mode))

	if mode != ExecutionModePTY && opts.BeforeDirectRun != nil {
		if err := opts.BeforeDirectRun(); err != nil {
			return err
		}
	}

	result, err := executor.ApplySandbox(ctx, cmd, opts.PackageManagerName)
	if err != nil {
		return fmt.Errorf("failed to apply sandbox: %w", err)
	}

	defer func() {
		if err := result.Close(); err != nil {
			log.Errorf("failed to close sandbox: %v", err)
		}
	}()

	switch mode {
	case ExecutionModePTY:
		return runPTY(ctx, cmd, cmd.Env, result, opts.PackageManagerName, opts.PreparePTYSession)
	default:
		return runDirect(cmd, result, opts.PackageManagerName)
	}
}

func runDirect(cmd *exec.Cmd, result *sandbox.ExecutionResult, pmName string) error {
	if !result.ShouldRun() {
		return nil
	}

	log.Debugf("Running command with args: %s: %v", cmd.Path, cmd.Args[1:])

	if err := cmd.Run(); err != nil {
		executor.ObserveViolations(result, err)
		return classify(err, pmName, result.ScrubbedEnvCount())
	}

	log.Debugf("Command completed successfully")
	return nil
}

func runPTY(
	ctx context.Context,
	cmd *exec.Cmd,
	env []string,
	result *sandbox.ExecutionResult,
	pmName string,
	beforeWait func(*PTYRuntime) error,
) error {
	if !result.ShouldRun() {
		return usefulerror.NewUsefulError().
			Wrap(fmt.Errorf("sandbox not supported for PTY sessions")).
			WithCode(errcodes.InvalidArgument).
			WithHumanError("Sandbox executed command cannot be used with PTY session. Please use non-interactive TTY mode instead.")
	}

	cmdExe := cmd.Path
	cmdArgs := cmd.Args[1:]

	log.Debugf("Running command with args: %s: %v", cmdExe, cmdArgs)

	sessionConfig := pty.NewSessionConfig(cmdExe, cmdArgs, env)
	sess, err := pty.NewSession(ctx, sessionConfig)
	if err != nil {
		return fmt.Errorf("failed to create pty session: %w", err)
	}
	defer func() {
		if err := sess.Close(); err != nil {
			log.Warnf("failed to close pty session: %v", err)
		}
	}()

	outputRouter, err := pty.NewOutputRouter(os.Stdout)
	if err != nil {
		return fmt.Errorf("failed to create output router: %w", err)
	}

	// The output reader normally ends on its own when the PTY master reports
	// EOF after the child exits. copyCtx lets us stop it otherwise: on parent
	// cancellation (Ctrl+C) and on the drain-grace path below, which guards
	// against a lingering descendant keeping the slave open (no EOF).
	copyCtx, stopCopy := context.WithCancel(ctx)
	defer stopCopy()

	copyDone := make(chan struct{})
	go func() {
		defer close(copyDone)
		if err := sess.CopyOutputContext(copyCtx, outputRouter); err != nil {
			log.Errorf("failed to copy output: %v", err)
		}
	}()

	inputRouter, err := pty.NewInputRouter(sess.PtyWriter())
	if err != nil {
		return fmt.Errorf("failed to create input router: %w", err)
	}

	promptReader, promptWriter := io.Pipe()
	defer func() {
		if err := promptWriter.Close(); err != nil {
			log.Warnf("failed to close prompt writer: %v", err)
		}
	}()
	defer func() {
		if err := promptReader.Close(); err != nil {
			log.Warnf("failed to close prompt reader: %v", err)
		}
	}()

	inputCtx, cancelInput := context.WithCancel(ctx)
	inputDone := make(chan struct{})
	go func() {
		defer close(inputDone)
		inputRouter.ReadLoopContext(inputCtx, os.Stdin)
	}()
	defer func() {
		cancelInput()
		<-inputDone
	}()

	if beforeWait != nil {
		runtime := &PTYRuntime{
			Session:      sess,
			OutputRouter: outputRouter,
			InputRouter:  inputRouter,
			PromptReader: promptReader,
			PromptWriter: promptWriter,
		}

		if err := beforeWait(runtime); err != nil {
			return err
		}
	}

	sessionError := sess.Wait()

	// Child has exited. Let the reader drain to EOF, but bound the wait so a
	// lingering descendant holding the slave open cannot block teardown.
	select {
	case <-copyDone:
	case <-time.After(outputDrainGrace):
		log.Debugf("output drain grace exceeded, stopping pty reader")
		stopCopy()
		<-copyDone
	}

	if sessionError != nil {
		executor.ObserveViolations(result, sessionError)
		return classify(sessionError, pmName, result.ScrubbedEnvCount())
	}

	return nil
}

func executionMode(opts ExecuteOptions) ExecutionMode {
	if opts.Mode != ExecutionModeAuto {
		return opts.Mode
	}

	isInteractive := pty.IsInteractiveTerminal
	if opts.IsInteractive != nil {
		isInteractive = opts.IsInteractive
	}

	if isInteractive() {
		return ExecutionModePTY
	}

	return ExecutionModeDirect
}

func commandEnv(overrides []string) []string {
	return mergeEnv(shim.FilterPMGFromEnv(os.Environ()), overrides)
}

func modeEnvOverrides(opts ExecuteOptions, mode ExecutionMode) []string {
	overrides := append([]string{}, opts.EnvOverrides...)
	switch mode {
	case ExecutionModePTY:
		overrides = append(overrides, opts.PTYEnvOverrides...)
	default:
		overrides = append(overrides, opts.DirectEnvOverrides...)
	}

	return overrides
}

func mergeEnv(base, overrides []string) []string {
	env := append([]string{}, base...)
	indexByKey := make(map[string]int, len(env))

	for i, entry := range env {
		key, _, ok := strings.Cut(entry, "=")
		if ok {
			indexByKey[key] = i
		}
	}

	for _, entry := range overrides {
		key, _, ok := strings.Cut(entry, "=")
		if !ok {
			env = append(env, entry)
			continue
		}

		if idx, exists := indexByKey[key]; exists {
			env[idx] = entry
			continue
		}

		indexByKey[key] = len(env)
		env = append(env, entry)
	}

	return env
}
