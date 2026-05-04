//go:build linux

package platform

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"github.com/landlock-lsm/go-landlock/landlock"
	llsyscall "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"github.com/safedep/dry/log"
	"golang.org/x/sys/unix"
)

// RunLandlockHelper is the entry point for the __landlock_sandbox_exec helper
// process. policyFile is the path to the policy JSON temp file. auditSocket is
// the path to the audit unix socket. cmdArgs are the target command args
// (everything after "--").
//
// Architecture — why the helper spawns a shim in a user namespace:
//
// We want to install seccomp-notify AND keep /proc/<pid>/mem readable for
// descendants, so the supervisor can resolve openat path arguments throughout
// the process tree. Unprivileged seccomp install requires PR_SET_NO_NEW_PRIVS
// — but NNP + execve resets the target's dumpable flag to 0, which blocks
// /proc/<pid>/mem opens for anyone without CAP_SYS_PTRACE. This defeats
// deny-rule enforcement on grandchildren (bash -> npm -> node).
//
// Fix: fork the target through a thin shim with CLONE_NEWUSER + uid map
// 0->host. The shim boots as uid 0 inside the new user namespace (so
// CAP_SYS_ADMIN in that ns) and installs seccomp WITHOUT NNP, which means
// descendants keep dumpable=1 and the helper can read their memory. The
// shim then execve's the real target with the filter inherited. To the real
// target, this is indistinguishable from running directly — same uid, same
// filesystem, same environment. The user namespace is only a capability
// vehicle.
func RunLandlockHelper(policyFile, auditSocket string, cmdArgs []string) error {
	// The shim will re-open this file from disk; we keep it alive until the
	// shim has loaded it.
	policy, err := readLandlockPolicyFromFile(policyFile)
	if err != nil {
		return fmt.Errorf("read policy from file: %w", err)
	}
	defer func() {
		if os.Getenv("PMG_KEEP_POLICY") == "" {
			_ = os.Remove(policyFile)
		}
	}()

	log.InitZapLogger("pmg", "landlock-helper")

	var auditWriter io.Writer = io.Discard
	conn, err := net.Dial("unix", auditSocket)
	if err == nil {
		defer conn.Close()
		auditWriter = conn
	} else {
		log.Debugf("Failed to connect to audit socket %s: %v", auditSocket, err)
	}

	if len(cmdArgs) > 0 {
		policy.Command = cmdArgs[0]
		if len(cmdArgs) > 1 {
			policy.Args = cmdArgs[1:]
		} else {
			policy.Args = nil
		}
	}

	// Die if parent exits.
	if err := unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL), 0, 0, 0); err != nil {
		return fmt.Errorf("prctl PR_SET_PDEATHSIG: %w", err)
	}

	// Socketpair: the shim sends its seccomp notify fd back to the helper
	// over its end (passed via ExtraFiles).
	sockPair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return fmt.Errorf("socketpair: %w", err)
	}
	helperSockFile := os.NewFile(uintptr(sockPair[0]), "shim-notify-helper")
	shimSockFile := os.NewFile(uintptr(sockPair[1]), "shim-notify-shim")
	defer helperSockFile.Close()

	// ExtraFiles[0] becomes fd=3 inside the shim. Go's exec.Cmd writes
	// uid_map/gid_map automatically when UidMappings/GidMappings are set.
	selfExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve self exe: %w", err)
	}
	shimArgs := []string{
		selfExe, "__landlock_shim",
		"--policy-file", policyFile,
		"--notify-socket-fd", "3",
		"--", policy.Command,
	}
	shimArgs = append(shimArgs, policy.Args...)

	cmd := exec.Command(selfExe, shimArgs[1:]...)
	cmd.Path = selfExe
	cmd.Args = shimArgs
	if len(policy.Env) > 0 {
		cmd.Env = policy.Env
	} else {
		cmd.Env = os.Environ()
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = []*os.File{shimSockFile}

	// CLONE_NEWUSER is the whole point — see function-level comment. We map
	// host uid/gid to 0 in the ns so the shim has CAP_SYS_ADMIN to install
	// seccomp without NNP. Identity mapping would leave us as unprivileged
	// uid inside the ns and we'd have to re-acquire caps via ambient, which
	// is not trivial in a Go runtime.
	uid := os.Getuid()
	gid := os.Getgid()
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: uid, Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: gid, Size: 1},
		},
		GidMappingsEnableSetgroups: false,
	}

	extraCloneFlags := landlockBuildCloneflags(policy)
	if extraCloneFlags != 0 {
		cmd.SysProcAttr.Cloneflags |= extraCloneFlags
	}

	// Retry without extra-ns flags if clone fails (kernel/seccomp policy
	// may forbid PID/IPC namespaces in restricted environments).
	if err := cmd.Start(); err != nil {
		var pathErr *os.PathError
		if errors.As(err, &pathErr) &&
			(errors.Is(pathErr.Err, unix.EPERM) || errors.Is(pathErr.Err, unix.EINVAL)) &&
			extraCloneFlags != 0 {
			_ = landlockWriteAuditEvent(auditWriter, auditEvent{
				Type:    auditNamespaceUnavailable,
				Message: fmt.Sprintf("namespace clone failed (%v), retrying without PID/IPC ns", err),
				Ts:      time.Now().UnixNano(),
			})
			fmt.Fprintf(os.Stderr, "pmg: warning: PID/IPC namespace unavailable (%v), continuing without\n", err)
			cmd.SysProcAttr.Cloneflags &^= extraCloneFlags
			if err := cmd.Start(); err != nil {
				_ = shimSockFile.Close()
				return fmt.Errorf("start shim (retry): %w", err)
			}
		} else {
			_ = shimSockFile.Close()
			return fmt.Errorf("start shim: %w", err)
		}
	}
	_ = shimSockFile.Close() // child has its own copy
	childPID := cmd.Process.Pid

	notifyFd, err := receiveNotifyFd(int(helperSockFile.Fd()))
	if err != nil {
		_ = cmd.Process.Signal(unix.SIGKILL)
		_ = cmd.Wait()
		return fmt.Errorf("receive notify fd from shim: %w", err)
	}

	supervisor, err := newLandlockSupervisorFromFd(notifyFd)
	if err != nil {
		_ = cmd.Process.Signal(unix.SIGKILL)
		_ = cmd.Wait()
		_ = unix.Close(notifyFd)
		return fmt.Errorf("create supervisor: %w", err)
	}

	// dumpable=1 is preserved across the shim tree (no NNP), so this open
	// succeeds for grandchildren too via memFdFor.
	memFd, err := openLandlockChildMemFd(childPID)
	if err != nil {
		_ = cmd.Process.Signal(unix.SIGKILL)
		_ = cmd.Wait()
		_ = supervisor.Stop()
		_ = landlockWriteAuditEvent(auditWriter, auditEvent{
			Type:    auditMemFdOpenFailed,
			PID:     childPID,
			Error:   err.Error(),
			Message: "failed to open /proc/<pid>/mem, killing child (fail-close)",
			Ts:      time.Now().UnixNano(),
		})
		return fmt.Errorf("open /proc/%d/mem (fail-close): %w", childPID, err)
	}

	if err := supervisor.Enforce(childPID, memFd, policy.DenyPaths, policy.DenyExecPaths, auditWriter); err != nil {
		_ = cmd.Process.Signal(unix.SIGKILL)
		_ = cmd.Wait()
		memFd.Close()
		_ = supervisor.Stop()
		return fmt.Errorf("enforce seccomp rules: %w", err)
	}

	sigCh := make(chan os.Signal, 3)
	signal.Notify(sigCh, unix.SIGINT, unix.SIGTERM, unix.SIGQUIT)
	go func() {
		for sig := range sigCh {
			_ = cmd.Process.Signal(sig)
		}
	}()

	waitErr := cmd.Wait()

	_ = supervisor.Stop()
	signal.Stop(sigCh)
	close(sigCh)
	memFd.Close()

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

// receiveNotifyFd reads a single SCM_RIGHTS-packed fd from the socketpair.
// The shim writes it right after installing the seccomp filter. Returns the
// fd as seen by the helper (kernel re-numbered at recvmsg time).
func receiveNotifyFd(sockFd int) (int, error) {
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	iov := unix.Iovec{Base: &buf[0], Len: 1}
	msg := unix.Msghdr{Iov: &iov, Iovlen: 1, Control: &oob[0]}
	msg.SetControllen(len(oob))
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	for {
		_, _, errno := unix.Syscall(
			unix.SYS_RECVMSG,
			uintptr(sockFd),
			uintptr(unsafe.Pointer(&msg)),
			0,
		)
		runtime.KeepAlive(&buf)
		runtime.KeepAlive(&oob)
		runtime.KeepAlive(&iov)
		runtime.KeepAlive(&msg)
		if errno == unix.EINTR {
			continue
		}
		if errno != 0 {
			return -1, fmt.Errorf("recvmsg: %w", errno)
		}
		break
	}
	cmsgs, err := unix.ParseSocketControlMessage(oob[:msg.Controllen])
	if err != nil {
		return -1, fmt.Errorf("parse cmsg: %w", err)
	}
	if len(cmsgs) == 0 {
		return -1, fmt.Errorf("no SCM_RIGHTS cmsg received (shim likely failed before send)")
	}
	fds, err := unix.ParseUnixRights(&cmsgs[0])
	if err != nil {
		return -1, fmt.Errorf("parse unix rights: %w", err)
	}
	if len(fds) == 0 {
		return -1, fmt.Errorf("no fds in cmsg")
	}
	return fds[0], nil
}

// readLandlockPolicyFromFile reads and deserializes a landlockExecPolicy from
// a file path.
func readLandlockPolicyFromFile(path string) (*landlockExecPolicy, error) {
	if path == "" {
		return nil, fmt.Errorf("policy file path is empty")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open policy file: %w", err)
	}
	defer f.Close()
	return readLandlockPolicyFromReader(f)
}

// readLandlockPolicyFromReader reads and deserializes a landlockExecPolicy
// from an io.Reader.
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

// landlockBuildCloneflags builds extra clone flags for the shim process based
// on the policy. The CLONE_NEWUSER flag itself is always added by the caller;
// this function returns ONLY the optional PID/IPC/MNT namespace flags.
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

// landlockSelectConfig picks the Landlock go library's Config (and thus
// ABI target) based on the highest access flag used in the policy. Kept
// in the helper file to avoid import cycles; consumed by the shim.
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
