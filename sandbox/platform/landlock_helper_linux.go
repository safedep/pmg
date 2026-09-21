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
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/landlock-lsm/go-landlock/landlock"
	llsyscall "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"github.com/safedep/dry/log"
	"golang.org/x/sys/unix"
)

// preferredUnmappedID is the first choice for a root caller's uid and gid
// in the user namespace. It must differ from the kernel overflow id: each
// unmapped host id displays as the overflow id, and a target id equal to it
// makes user-space ownership checks answer "mine" for the whole filesystem.
const preferredUnmappedID = 65533

// sandboxUnmappedIDs returns the uid and gid a root caller gets in the user
// namespace. It avoids the kernel overflow ids.
func sandboxUnmappedIDs() (int, int) {
	return unmappedID("/proc/sys/kernel/overflowuid"), unmappedID("/proc/sys/kernel/overflowgid")
}

func unmappedID(overflowPath string) int {
	data, err := os.ReadFile(overflowPath)
	if err != nil {
		return preferredUnmappedID
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || v != preferredUnmappedID {
		return preferredUnmappedID
	}
	return preferredUnmappedID - 1
}

// RunLandlockHelper is the entry point of the __landlock_sandbox_exec
// process. It forks the shim and runs the seccomp supervisor for the target
// tree. See docs/sandbox-landlock.md.
func RunLandlockHelper(policyFile, auditSocket string, cmdArgs []string) error {
	// The shim reads this file again. Keep it until the run ends.
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

	auditWriter := io.Writer(io.Discard)
	conn, err := net.Dial("unix", auditSocket)
	if err == nil {
		defer func() {
			if cerr := conn.Close(); cerr != nil {
				log.Warnf("close audit socket: %v", cerr)
			}
		}()
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

	if err := unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL), 0, 0, 0); err != nil {
		return fmt.Errorf("prctl PR_SET_PDEATHSIG: %w", err)
	}

	sockPair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return fmt.Errorf("socketpair: %w", err)
	}
	helperSockFile := os.NewFile(uintptr(sockPair[0]), "shim-notify-helper")
	shimSockFile := os.NewFile(uintptr(sockPair[1]), "shim-notify-shim")
	defer func() {
		if err := helperSockFile.Close(); err != nil {
			log.Warnf("close helper socket: %v", err)
		}
	}()

	// ExtraFiles[0] is fd 3 in the shim.
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

	// One clone creates the user namespace and the PID, IPC and mount
	// namespaces, so the capability check for those passes. The identity
	// map keeps the target as the caller with no capabilities. A 0->uid map
	// would give the whole target tree uid 0 with CAP_SYS_ADMIN.
	uid := os.Getuid()
	gid := os.Getgid()
	containerUID, containerGID := uid, gid
	if uid == 0 {
		// A root caller must not see uid 0 in the namespace. Tools take
		// root-only paths on getuid() == 0. A tar extractor restores
		// tarball ownership with chown, and a chown to an unmapped uid
		// fails with EINVAL. The mapped kuid is still 0, so the target
		// owns the same files as the root caller.
		containerUID, containerGID = sandboxUnmappedIDs()
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: containerUID, HostID: uid, Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: containerGID, HostID: gid, Size: 1},
		},
		GidMappingsEnableSetgroups: false,
	}

	extraCloneFlags := landlockBuildCloneflags(policy)
	if extraCloneFlags != 0 {
		cmd.SysProcAttr.Cloneflags |= extraCloneFlags
	}

	// A restricted host can refuse the PID or IPC namespace. Retry without.
	if err := cmd.Start(); err != nil {
		var pathErr *os.PathError
		if errors.As(err, &pathErr) &&
			(errors.Is(pathErr.Err, unix.EPERM) || errors.Is(pathErr.Err, unix.EINVAL)) &&
			extraCloneFlags != 0 {
			if err := landlockWriteAuditEvent(auditWriter, auditEvent{
				Type:    auditNamespaceUnavailable,
				Message: fmt.Sprintf("namespace clone failed (%v), retrying without PID/IPC ns", err),
				Ts:      time.Now().UnixNano(),
			}); err != nil {
				log.Warnf("sandbox: failed to record a denial: %v", err)
			}
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

	memFd, err := openLandlockChildMemFd(childPID)
	if err != nil {
		_ = cmd.Process.Signal(unix.SIGKILL)
		_ = cmd.Wait()
		_ = supervisor.Stop()
		if err := landlockWriteAuditEvent(auditWriter, auditEvent{
			Type:    auditMemFdOpenFailed,
			PID:     childPID,
			Error:   err.Error(),
			Message: "failed to open /proc/<pid>/mem, killing child (fail-close)",
			Ts:      time.Now().UnixNano(),
		}); err != nil {
			log.Warnf("sandbox: failed to record a denial: %v", err)
		}
		return fmt.Errorf("open /proc/%d/mem (fail-close): %w", childPID, err)
	}

	if err := supervisor.Enforce(childPID, policy.DenyPaths, policy.DenyExecPaths, policy.Network, auditWriter); err != nil {
		_ = cmd.Process.Signal(unix.SIGKILL)
		_ = cmd.Wait()
		if cerr := memFd.Close(); cerr != nil {
			log.Warnf("close /proc/%d/mem: %v", childPID, cerr)
		}
		_ = supervisor.Stop()
		return fmt.Errorf("enforce seccomp rules: %w", err)
	}

	// This fd was only the fail-close check. An open mem fd pins the mm of
	// the task, so it would read a dead address space after an execve.
	if err := memFd.Close(); err != nil {
		log.Warnf("close /proc/%d/mem: %v", childPID, err)
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

func readLandlockPolicyFromFile(path string) (*landlockExecPolicy, error) {
	if path == "" {
		return nil, fmt.Errorf("policy file path is empty")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open policy file: %w", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Warnf("close policy file %s: %v", path, err)
		}
	}()
	return readLandlockPolicyFromReader(f)
}

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

func openLandlockChildMemFd(pid int) (*os.File, error) {
	path := fmt.Sprintf("/proc/%d/mem", pid)
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	return f, nil
}

// landlockSelectConfig picks the lowest Landlock ABI that covers every
// access flag in the policy.
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
