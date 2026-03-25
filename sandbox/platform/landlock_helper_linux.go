//go:build linux

package platform

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/landlock-lsm/go-landlock/landlock"
	llsyscall "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"golang.org/x/sys/unix"
)

// RunLandlockHelper is the entry point for the __landlock_sandbox_exec helper process.
// Called by the thin Cobra command in cmd/landlock/.
func RunLandlockHelper(args []string) error {
	// 1. Read policy from FD=3
	policy, err := readLandlockPolicyFromFD()
	if err != nil {
		return fmt.Errorf("read policy from FD=3: %w", err)
	}

	// 2. Open FD=4 for audit writing
	auditFd := os.NewFile(4, "audit-pipe")

	// 3. Set no new privileges
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl PR_SET_NO_NEW_PRIVS: %w", err)
	}

	// 4. Die if parent exits
	if err := unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL), 0, 0, 0); err != nil {
		return fmt.Errorf("prctl PR_SET_PDEATHSIG: %w", err)
	}

	// 5. Build go-landlock rules from policy
	var rules []landlock.Rule
	for _, r := range policy.FilesystemRules {
		rules = append(rules, landlock.PathAccess(
			landlock.AccessFSSet(r.Access), r.Path,
		).IgnoreIfMissing())
	}

	// Select config version based on highest ABI features used
	cfg := landlockSelectConfig(policy)

	// 6. Install seccomp-notify BPF filter and start Phase 1 loop
	supervisor, err := newLandlockSupervisor()
	if err != nil {
		return fmt.Errorf("create seccomp supervisor: %w", err)
	}

	// 7. Apply Landlock filesystem restrictions
	if err := cfg.BestEffort().RestrictPaths(rules...); err != nil {
		_ = supervisor.Stop()
		return fmt.Errorf("landlock restrict paths: %w", err)
	}

	// 8. Build exec.Cmd from policy
	cmd := exec.Command(policy.Command, policy.Args...)
	if len(policy.Env) > 0 {
		cmd.Env = policy.Env
	} else {
		cmd.Env = os.Environ()
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// 9. Set namespace clone flags
	cloneFlags := landlockBuildCloneflags(policy)
	if cloneFlags != 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags: cloneFlags,
		}
	}

	// 10. Start child process
	if err := cmd.Start(); err != nil {
		var pathErr *os.PathError
		if errors.As(err, &pathErr) &&
			(errors.Is(pathErr.Err, unix.EPERM) || errors.Is(pathErr.Err, unix.EINVAL)) {
			// Retry without namespace isolation
			landlockWriteAuditEvent(auditFd, auditEvent{ //nolint:errcheck
				Type:    auditNamespaceUnavailable,
				Message: fmt.Sprintf("namespace clone failed (%v), retrying without namespaces", err),
				Ts:      time.Now().UnixNano(),
			})
			fmt.Fprintf(os.Stderr, "pmg: warning: namespace isolation unavailable (%v), continuing without it\n", err)
			cmd.SysProcAttr = nil
			if err := cmd.Start(); err != nil {
				_ = supervisor.Stop()
				return fmt.Errorf("start child process (retry): %w", err)
			}
		} else {
			_ = supervisor.Stop()
			return fmt.Errorf("start child process: %w", err)
		}
	}

	childPID := cmd.Process.Pid

	// 11. Pre-open /proc/<child-pid>/mem (FAIL-CLOSE)
	memFd, err := openLandlockChildMemFd(childPID)
	if err != nil {
		// FAIL-CLOSE: kill child and return error
		_ = cmd.Process.Signal(unix.SIGKILL)
		_ = cmd.Wait()
		_ = supervisor.Stop()
		landlockWriteAuditEvent(auditFd, auditEvent{ //nolint:errcheck
			Type:    auditMemFdOpenFailed,
			PID:     childPID,
			Error:   err.Error(),
			Message: "failed to open /proc/<pid>/mem, killing child (fail-close)",
			Ts:      time.Now().UnixNano(),
		})
		return fmt.Errorf("open /proc/%d/mem (fail-close): %w", childPID, err)
	}

	// 12. Transition supervisor to enforcement mode
	if err := supervisor.Enforce(childPID, memFd, policy.DenyPaths, policy.DenyExecPaths, auditFd); err != nil {
		_ = cmd.Process.Signal(unix.SIGKILL)
		_ = cmd.Wait()
		memFd.Close()
		_ = supervisor.Stop()
		return fmt.Errorf("enforce seccomp rules: %w", err)
	}

	// 13. Signal forwarding
	sigCh := make(chan os.Signal, 3)
	signal.Notify(sigCh, unix.SIGINT, unix.SIGTERM, unix.SIGQUIT)
	go func() {
		for sig := range sigCh {
			_ = cmd.Process.Signal(sig)
		}
	}()

	// 14. Wait for child
	waitErr := cmd.Wait()

	// 15. Stop supervisor
	_ = supervisor.Stop()

	// 16. Cleanup
	signal.Stop(sigCh)
	close(sigCh)
	memFd.Close()
	auditFd.Close()

	// 17. Exit with child's exit code
	exitCode := 0
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}
	os.Exit(exitCode)

	return nil // unreachable
}

// readLandlockPolicyFromFD reads the landlockExecPolicy JSON from FD=3.
func readLandlockPolicyFromFD() (*landlockExecPolicy, error) {
	f := os.NewFile(3, "policy-pipe")
	if f == nil {
		return nil, fmt.Errorf("FD=3 is not available")
	}
	defer f.Close()

	return readLandlockPolicyFromReader(f)
}

// readLandlockPolicyFromReader reads and deserializes a landlockExecPolicy from an io.Reader.
func readLandlockPolicyFromReader(r io.Reader) (*landlockExecPolicy, error) {
	var policy landlockExecPolicy
	if err := json.NewDecoder(r).Decode(&policy); err != nil {
		return nil, fmt.Errorf("decode policy JSON: %w", err)
	}

	if policy.Command == "" {
		return nil, fmt.Errorf("policy has empty command")
	}

	return &policy, nil
}

// landlockBuildCloneflags builds the clone flags for the child process based on policy.
func landlockBuildCloneflags(policy *landlockExecPolicy) uintptr {
	var flags uintptr

	if !policy.SkipPIDNamespace {
		flags |= unix.CLONE_NEWPID | unix.CLONE_NEWNS
	}

	if !policy.SkipIPCNamespace {
		flags |= unix.CLONE_NEWIPC
	}

	return flags
}

// openLandlockChildMemFd opens /proc/<pid>/mem for reading the child's memory.
func openLandlockChildMemFd(pid int) (*os.File, error) {
	path := fmt.Sprintf("/proc/%d/mem", pid)
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	return f, nil
}

// landlockSelectConfig determines the appropriate go-landlock Config version
// based on the access flags used in the policy's filesystem rules.
func landlockSelectConfig(policy *landlockExecPolicy) landlock.Config {
	var hasRefer, hasTruncate, hasIoctlDev bool

	for _, r := range policy.FilesystemRules {
		if r.Access&uint64(llsyscall.AccessFSRefer) != 0 {
			hasRefer = true
		}
		if r.Access&uint64(llsyscall.AccessFSTruncate) != 0 {
			hasTruncate = true
		}
		if r.Access&uint64(llsyscall.AccessFSIoctlDev) != 0 {
			hasIoctlDev = true
		}
	}

	switch {
	case hasIoctlDev:
		return landlock.V5
	case hasTruncate:
		return landlock.V3
	case hasRefer:
		return landlock.V2
	default:
		return landlock.V1
	}
}
