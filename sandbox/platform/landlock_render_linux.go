//go:build linux
// +build linux

package platform

import (
	"fmt"
	"strings"

	llsyscall "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"github.com/safedep/pmg/sandbox"
)

// landlockRenderFallbackABI is used when the host kernel does not support
// Landlock (so callers on non-landlock hosts still get a meaningful render
// for inspection). Set to the highest ABI version this translator knows
// about so all feature flags are enabled in the rendered ruleset.
const landlockRenderFallbackABI = 6

// RenderLandlock translates a SandboxPolicy into a human-readable summary of
// the Landlock ruleset the driver would apply. The summary lists the detected
// ABI level, the filesystem allow rules (path + symbolic access flags), the
// deny paths consumed by the seccomp supervisor, and the deny-exec list.
//
// This is a thin wrapper over the internal landlock translator and is
// intended for inspection use cases such as
// `pmg setup sandbox profile show --driver=landlock`. When the host kernel
// does not support Landlock, the renderer falls back to a default ABI so the
// output is still meaningful for design-time inspection; this fallback is
// noted in the rendered header.
func RenderLandlock(policy *sandbox.SandboxPolicy) ([]byte, error) {
	if policy == nil {
		return nil, fmt.Errorf("policy is nil")
	}

	abi, err := landlockDetectABI()
	abiSource := "detected"
	if err != nil {
		abi = newLandlockABI(landlockRenderFallbackABI)
		abiSource = "fallback"
	}

	ep, err := landlockTranslatePolicy(policy, abi)
	if err != nil {
		return nil, err
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "# Landlock ruleset\n")
	fmt.Fprintf(&sb, "# policy: %s\n", policy.Name)
	fmt.Fprintf(&sb, "abi: %d (%s)\n", abi.Version, abiSource)
	fmt.Fprintf(&sb, "features: refer=%t truncate=%t network=%t ioctl_dev=%t scoping=%t\n",
		abi.HasRefer, abi.HasTruncate, abi.HasNetwork, abi.HasIoctlDev, abi.HasScoping)
	fmt.Fprintf(&sb, "allow_pty: %t\n", ep.AllowPTY)
	fmt.Fprintf(&sb, "skip_pid_namespace: %t\n", ep.SkipPIDNamespace)
	fmt.Fprintf(&sb, "skip_ipc_namespace: %t\n", ep.SkipIPCNamespace)

	fmt.Fprintf(&sb, "\nfilesystem_rules (%d):\n", len(ep.FilesystemRules))
	for _, r := range ep.FilesystemRules {
		fmt.Fprintf(&sb, "  - path: %s\n    access: %s\n", r.Path, landlockAccessFlagsString(r.Access))
	}

	fmt.Fprintf(&sb, "\ndeny_paths (%d):\n", len(ep.DenyPaths))
	for _, d := range ep.DenyPaths {
		fmt.Fprintf(&sb, "  - path: %s\n    mode: %s\n", d.Path, landlockDenyModeString(d.Mode))
	}

	fmt.Fprintf(&sb, "\ndeny_exec_paths (%d):\n", len(ep.DenyExecPaths))
	for _, p := range ep.DenyExecPaths {
		fmt.Fprintf(&sb, "  - %s\n", p)
	}

	return []byte(sb.String()), nil
}

// landlockAccessFlagsString renders a Landlock AccessFs bitmask as a
// stable, space-separated list of symbolic flag names. The order is fixed so
// the output is suitable for golden tests and diffing.
func landlockAccessFlagsString(access uint64) string {
	type bit struct {
		mask uint64
		name string
	}
	bits := []bit{
		{uint64(llsyscall.AccessFSExecute), "execute"},
		{uint64(llsyscall.AccessFSReadFile), "read_file"},
		{uint64(llsyscall.AccessFSReadDir), "read_dir"},
		{uint64(llsyscall.AccessFSWriteFile), "write_file"},
		{uint64(llsyscall.AccessFSTruncate), "truncate"},
		{uint64(llsyscall.AccessFSIoctlDev), "ioctl_dev"},
		{uint64(llsyscall.AccessFSMakeReg), "make_reg"},
		{uint64(llsyscall.AccessFSMakeDir), "make_dir"},
		{uint64(llsyscall.AccessFSMakeSock), "make_sock"},
		{uint64(llsyscall.AccessFSMakeFifo), "make_fifo"},
		{uint64(llsyscall.AccessFSMakeBlock), "make_block"},
		{uint64(llsyscall.AccessFSMakeChar), "make_char"},
		{uint64(llsyscall.AccessFSMakeSym), "make_sym"},
		{uint64(llsyscall.AccessFSRemoveFile), "remove_file"},
		{uint64(llsyscall.AccessFSRemoveDir), "remove_dir"},
		{uint64(llsyscall.AccessFSRefer), "refer"},
	}

	parts := []string{}
	for _, b := range bits {
		if access&b.mask != 0 {
			parts = append(parts, b.name)
		}
	}
	if len(parts) == 0 {
		return "(none)"
	}
	return strings.Join(parts, "|")
}

func landlockDenyModeString(m denyMode) string {
	switch m {
	case denyRead:
		return "read"
	case denyWrite:
		return "write"
	case denyBoth:
		return "both"
	default:
		return fmt.Sprintf("unknown(%d)", int(m))
	}
}
