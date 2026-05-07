//go:build linux

package platform

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/safedep/dry/log"
	"github.com/safedep/dry/utils"
	"github.com/safedep/pmg/sandbox"
	"github.com/safedep/pmg/sandbox/util"

	llsyscall "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// landlockExecPolicy is the internal representation of a translated sandbox policy
// ready for Landlock enforcement. It contains filesystem rules (allow-list),
// deny paths (for seccomp-notify enforcement), and execution configuration.
type landlockExecPolicy struct {
	FilesystemRules  []landlockPathRule `json:"filesystem_rules"`
	DenyPaths        []denyPathEntry    `json:"deny_paths"`
	DenyExecPaths    []string           `json:"deny_exec_paths"`
	AllowPTY         bool               `json:"allow_pty"`
	SkipPIDNamespace bool               `json:"skip_pid_namespace"`
	SkipIPCNamespace bool               `json:"skip_ipc_namespace"`
	Command          string             `json:"command"`
	Args             []string           `json:"args"`
	Env              []string           `json:"env,omitempty"`
}

// landlockPathRule represents a single Landlock filesystem rule mapping a path
// to its allowed access bitmask.
type landlockPathRule struct {
	Path   string `json:"path"`
	Access uint64 `json:"access"` // Raw kernel Landlock AccessFs bitmask
}

// Landlock access flag groups composed from go-landlock syscall constants.
//
// Note on Execute: Landlock is stricter than bubblewrap's bind-mount model.
// With bubblewrap, a read-only bind automatically permits execve of anything
// inside. With Landlock, EXECUTE must be granted explicitly — otherwise
// execve returns EACCES even for script interpreters that the policy clearly
// intends to allow (e.g. /usr/bin/node reached via an allow_read of $HOME).
//
// We include AccessFSExecute in landlockReadAccess so `allow_read: /` matches
// user intent: "I can read and run stuff from under here." Deny-exec is still
// enforced via the seccomp supervisor, which wins over the Landlock allow.
var (
	landlockReadAccess = uint64(llsyscall.AccessFSReadFile | llsyscall.AccessFSReadDir | llsyscall.AccessFSExecute)

	landlockWriteAccessBase = uint64(
		llsyscall.AccessFSWriteFile |
			llsyscall.AccessFSMakeReg |
			llsyscall.AccessFSMakeDir |
			llsyscall.AccessFSMakeSock |
			llsyscall.AccessFSMakeFifo |
			llsyscall.AccessFSMakeBlock |
			llsyscall.AccessFSMakeChar |
			llsyscall.AccessFSMakeSym |
			llsyscall.AccessFSRemoveFile |
			llsyscall.AccessFSRemoveDir)

	// Execute access includes ReadFile because the kernel must read the
	// shebang line of script files (e.g. #!/bin/bash) to determine the
	// interpreter. Without ReadFile, execve on scripts fails with EACCES.
	landlockExecuteAccess = uint64(llsyscall.AccessFSExecute | llsyscall.AccessFSReadFile)
)

// landlockFileAccess is the set of Landlock access flags valid for regular files.
// Matches the go-landlock library's accessFile constant. All other access flags
// are directory-only and must be stripped when the rule targets a non-directory.
var landlockFileAccess = uint64(
	llsyscall.AccessFSReadFile |
		llsyscall.AccessFSWriteFile |
		llsyscall.AccessFSExecute |
		llsyscall.AccessFSTruncate |
		llsyscall.AccessFSIoctlDev)

// landlockAdjustAccessForPath stats the given path and strips directory-only
// access flags when the path refers to a regular file. If the path does not
// exist or cannot be stat'd, the original access mask is returned unchanged
// (go-landlock's IgnoreIfMissing handles missing paths).
func landlockAdjustAccessForPath(path string, access uint64) uint64 {
	info, err := os.Stat(path)
	if err != nil {
		return access
	}
	if !info.IsDir() {
		access &= landlockFileAccess
	}
	return access
}

// landlockUsrBinAlternate returns the /usr/bin equivalent of a /bin path and
// vice versa, to handle merged-/usr systems where /bin is a symlink to /usr/bin.
// Returns empty string if the path is not in /bin or /usr/bin.
func landlockUsrBinAlternate(path string) string {
	prefixes := [][2]string{
		{"/bin/", "/usr/bin/"},
		{"/sbin/", "/usr/sbin/"},
		{"/lib/", "/usr/lib/"},
		{"/lib64/", "/usr/lib64/"},
	}
	for _, pair := range prefixes {
		if strings.HasPrefix(path, pair[0]) {
			return pair[1] + strings.TrimPrefix(path, pair[0])
		}
		if strings.HasPrefix(path, pair[1]) {
			return pair[0] + strings.TrimPrefix(path, pair[1])
		}
	}
	return ""
}

// landlockIsProcPath returns true if the path is /proc or any path under /proc.
// Uses a path boundary check so /process, /procurement, etc. don't match.
func landlockIsProcPath(path string) bool {
	return path == "/proc" || strings.HasPrefix(path, "/proc/")
}

// landlockGlobMatches expands a glob pattern, transparently handling **
// globstar (which filepath.Glob does not). Used for deny-path expansion.
func landlockGlobMatches(pattern string) ([]string, error) {
	if strings.Contains(pattern, "**") {
		return expandGlobstarPattern(pattern, landlockGlobstarMaxDepth, landlockGlobstarMaxPaths)
	}
	return filepath.Glob(pattern)
}

// landlockIsWithinWritableArea checks if a path (or glob pattern) falls within
// any of the write-allowed prefixes. This is used to skip deny_write entries
// that Landlock already prevents (paths outside the write allow-list).
func landlockIsWithinWritableArea(path string, writePrefixes []string) bool {
	// Strip glob suffix from both sides; we only compare the literal prefix.
	base := path
	if idx := strings.IndexAny(base, "*?["); idx >= 0 {
		base = base[:idx]
	}

	for _, prefix := range writePrefixes {
		expandedPrefix, err := util.ExpandVariables(prefix)
		if err != nil {
			continue
		}
		cleanPrefix := expandedPrefix
		if idx := strings.IndexAny(cleanPrefix, "*?["); idx >= 0 {
			cleanPrefix = cleanPrefix[:idx]
		}
		if strings.HasPrefix(base, cleanPrefix) || strings.HasPrefix(cleanPrefix, base) {
			return true
		}
	}
	return false
}

// landlockGlobFallbackThreshold is the maximum number of glob matches before
// falling back to the parent directory. Same threshold as Bubblewrap translator.
const landlockGlobFallbackThreshold = 100

// Globstar walk limits, matching the Bubblewrap translator defaults so the
// two drivers expand built-in profiles consistently.
const (
	landlockGlobstarMaxDepth = 5
	landlockGlobstarMaxPaths = 1000
)

// landlockTranslatePolicy converts a SandboxPolicy into a landlockExecPolicy
// that can be applied by the Landlock driver. It expands variables, resolves
// glob patterns, maps allow/deny rules, and adds implicit rules.
func landlockTranslatePolicy(policy *sandbox.SandboxPolicy, abi *landlockABI) (*landlockExecPolicy, error) {
	ep := &landlockExecPolicy{}

	writeAccess := landlockWriteAccessBase
	if abi.HasRefer {
		writeAccess |= uint64(llsyscall.AccessFSRefer)
	}
	if abi.HasTruncate {
		writeAccess |= uint64(llsyscall.AccessFSTruncate)
	}

	for _, pattern := range policy.Filesystem.AllowRead {
		paths, err := landlockExpandPattern(pattern)
		if err != nil {
			log.Warnf("Failed to expand allow_read pattern '%s': %v", pattern, err)
			continue
		}
		for _, p := range paths {
			ep.FilesystemRules = append(ep.FilesystemRules, landlockPathRule{
				Path:   p,
				Access: landlockReadAccess,
			})
		}
	}

	// allow_write grants read+write to mirror Bubblewrap's --bind (which
	// exposes both directions). Package managers routinely reopen files in
	// temp/cache trees with O_RDONLY/O_RDWR, so write-only access would
	// surface as spurious EACCES on otherwise-allowed paths.
	readWriteAccess := landlockReadAccess | writeAccess
	for _, pattern := range policy.Filesystem.AllowWrite {
		paths, err := landlockExpandPattern(pattern)
		if err != nil {
			log.Warnf("Failed to expand allow_write pattern '%s': %v", pattern, err)
			continue
		}
		for _, p := range paths {
			ep.FilesystemRules = append(ep.FilesystemRules, landlockPathRule{
				Path:   p,
				Access: readWriteAccess,
			})
		}
	}

	for _, pattern := range policy.Process.AllowExec {
		paths, err := landlockExpandPattern(pattern)
		if err != nil {
			log.Warnf("Failed to expand allow_exec pattern '%s': %v", pattern, err)
			continue
		}
		for _, p := range paths {
			ep.FilesystemRules = append(ep.FilesystemRules, landlockPathRule{
				Path:   p,
				Access: landlockExecuteAccess,
			})
			// On merged-/usr systems, /bin/X and /usr/bin/X refer to the
			// same file. Add the alternate path so Landlock covers both
			// access routes.
			if alt := landlockUsrBinAlternate(p); alt != "" {
				ep.FilesystemRules = append(ep.FilesystemRules, landlockPathRule{
					Path:   alt,
					Access: landlockExecuteAccess,
				})
			}
		}
	}

	for _, pattern := range policy.Filesystem.DenyRead {
		expanded, err := util.ExpandVariables(pattern)
		if err != nil {
			log.Warnf("Failed to expand deny_read pattern '%s': %v", pattern, err)
			continue
		}
		if landlockIsProcPath(expanded) {
			log.Warnf("Dropping /proc deny entry '%s': Landlock cannot deny /proc sub-paths reliably", expanded)
			continue
		}
		if util.ContainsGlob(expanded) {
			matches, err := landlockGlobMatches(expanded)
			if err != nil {
				log.Warnf("Failed to expand deny_read glob '%s': %v", expanded, err)
				continue
			}
			for _, m := range matches {
				ep.DenyPaths = append(ep.DenyPaths, denyPathEntry{Path: m, Mode: denyRead})
			}
		} else {
			ep.DenyPaths = append(ep.DenyPaths, denyPathEntry{Path: expanded, Mode: denyRead})
		}
	}

	// Landlock already prevents writes outside allow_write, so deny_write is
	// only meaningful within writable areas. Skipping the rest avoids thousands
	// of redundant seccomp deny entries (e.g. /etc/**, /usr/**).
	writablePrefixes := policy.Filesystem.AllowWrite
	for _, pattern := range policy.Filesystem.DenyWrite {
		expanded, err := util.ExpandVariables(pattern)
		if err != nil {
			log.Warnf("Failed to expand deny_write pattern '%s': %v", pattern, err)
			continue
		}
		if landlockIsProcPath(expanded) {
			log.Warnf("Dropping /proc deny entry '%s': Landlock cannot deny /proc sub-paths reliably", expanded)
			continue
		}
		if !landlockIsWithinWritableArea(expanded, writablePrefixes) {
			continue
		}
		if util.ContainsGlob(expanded) {
			matches, err := landlockGlobMatches(expanded)
			if err != nil {
				log.Warnf("Failed to expand deny_write glob '%s': %v", expanded, err)
				continue
			}
			for _, m := range matches {
				ep.DenyPaths = append(ep.DenyPaths, denyPathEntry{Path: m, Mode: denyWrite})
			}
		} else {
			ep.DenyPaths = append(ep.DenyPaths, denyPathEntry{Path: expanded, Mode: denyWrite})
		}
	}

	for _, pattern := range policy.Process.DenyExec {
		expanded, err := util.ExpandVariables(pattern)
		if err != nil {
			log.Warnf("Failed to expand deny_exec pattern '%s': %v", pattern, err)
			continue
		}
		if util.ContainsGlob(expanded) {
			matches, err := landlockGlobMatches(expanded)
			if err != nil {
				log.Warnf("Failed to expand deny_exec glob '%s': %v", expanded, err)
				continue
			}
			ep.DenyExecPaths = append(ep.DenyExecPaths, matches...)
		} else {
			ep.DenyExecPaths = append(ep.DenyExecPaths, expanded)
		}
	}

	expandedAllowRead, err := expandAll(policy.Filesystem.AllowRead)
	if err != nil {
		log.Warnf("sandbox: failed to expand allow_read for mandatory deny suppression, all mandatory denies preserved: %v", err)
		expandedAllowRead = nil
	}
	expandedAllowWrite, err := expandAll(policy.Filesystem.AllowWrite)
	if err != nil {
		log.Warnf("sandbox: failed to expand allow_write for mandatory deny suppression, all mandatory denies preserved: %v", err)
		expandedAllowWrite = nil
	}

	mandatoryResult := util.GetMandatoryDenyPatterns(util.MandatoryDenyOptions{
		AllowGitConfig: utils.SafelyGetValue(policy.AllowGitConfig),
		AllowRead:      expandedAllowRead,
		AllowWrite:     expandedAllowWrite,
	})

	for _, p := range mandatoryResult.SuppressedRead {
		log.Warnf("sandbox: mandatory deny %q suppressed for read by explicit allow rule in policy %q", p, policy.Name)
	}
	for _, p := range mandatoryResult.SuppressedWrite {
		log.Warnf("sandbox: mandatory deny %q suppressed for write by explicit allow rule in policy %q", p, policy.Name)
	}

	// Collapse paths that appear in both directions into a single denyBoth
	// entry; emit per-direction entries for the rest.
	denyWriteSet := make(map[string]bool, len(mandatoryResult.DenyWrite))
	for _, p := range mandatoryResult.DenyWrite {
		denyWriteSet[p] = true
	}
	bothSet := make(map[string]bool)
	for _, p := range mandatoryResult.DenyRead {
		if denyWriteSet[p] {
			bothSet[p] = true
		}
	}
	appendDeny := func(pattern string, mode denyMode) {
		if util.ContainsGlob(pattern) {
			matches, err := landlockGlobMatches(pattern)
			if err != nil {
				log.Warnf("Failed to expand mandatory deny glob '%s': %v", pattern, err)
				return
			}
			for _, m := range matches {
				ep.DenyPaths = append(ep.DenyPaths, denyPathEntry{Path: m, Mode: mode})
			}
			return
		}
		ep.DenyPaths = append(ep.DenyPaths, denyPathEntry{Path: pattern, Mode: mode})
	}

	for _, p := range mandatoryResult.DenyRead {
		if bothSet[p] {
			appendDeny(p, denyBoth)
			continue
		}
		appendDeny(p, denyRead)
	}
	for _, p := range mandatoryResult.DenyWrite {
		if bothSet[p] {
			continue // already emitted as denyBoth
		}
		appendDeny(p, denyWrite)
	}

	// Unlike bubblewrap's read-only bind mounts, Landlock requires explicit
	// execute permission on system binary directories. The deny_exec list
	// (enforced via seccomp) blocks specific dangerous binaries within them.
	sysExecDirs := []string{"/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib64",
		"/bin", "/sbin", "/lib", "/lib64"}
	for _, dir := range sysExecDirs {
		ep.FilesystemRules = append(ep.FilesystemRules, landlockPathRule{
			Path:   dir,
			Access: landlockExecuteAccess,
		})
	}

	// /proc read access — the supervisor reads /proc/<pid>/{cwd,fd,mem}.
	ep.FilesystemRules = append(ep.FilesystemRules, landlockPathRule{
		Path:   "/proc",
		Access: landlockReadAccess,
	})

	devReadWrite := landlockReadAccess | writeAccess
	for _, dev := range []string{"/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"} {
		ep.FilesystemRules = append(ep.FilesystemRules, landlockPathRule{
			Path:   dev,
			Access: devReadWrite,
		})
	}

	ep.FilesystemRules = append(ep.FilesystemRules, landlockPathRule{
		Path:   os.TempDir(),
		Access: writeAccess,
	})

	allowPTY := utils.SafelyGetValue(policy.AllowPTY)
	ep.AllowPTY = allowPTY
	if allowPTY {
		ptyAccess := landlockReadAccess | writeAccess
		if abi.HasIoctlDev {
			ptyAccess |= uint64(llsyscall.AccessFSIoctlDev)
		}
		ep.FilesystemRules = append(ep.FilesystemRules, landlockPathRule{
			Path:   "/dev/pts",
			Access: ptyAccess,
		})
		ep.FilesystemRules = append(ep.FilesystemRules, landlockPathRule{
			Path:   "/dev/ptmx",
			Access: ptyAccess,
		})
	}

	if landlockPolicyExplicitlyAllowsProc(policy) {
		ep.SkipPIDNamespace = true
		log.Warnf("Policy explicitly allows /proc paths beyond /proc/self - skipping PID namespace isolation")
	}

	return ep, nil
}

// landlockExpandPattern expands variables and glob patterns in a path string,
// returning a list of concrete paths. Handles ** globstar (which
// filepath.Glob does not) so built-in profiles like ${CWD}/node_modules/**
// expand correctly even when the parent directory does not yet exist; in
// that case the parent path is returned so Landlock can still grant
// recursive coverage on the directory once it is created. When glob
// matches exceed the fallback threshold, uses the parent directory
// instead.
func landlockExpandPattern(pattern string) ([]string, error) {
	expanded, err := util.ExpandVariables(pattern)
	if err != nil {
		return nil, err
	}

	if !util.ContainsGlob(expanded) {
		return []string{expanded}, nil
	}

	var matches []string
	if strings.Contains(expanded, "**") {
		matches, err = expandGlobstarPattern(expanded, landlockGlobstarMaxDepth, landlockGlobstarMaxPaths)
		if err != nil {
			return nil, err
		}
	} else {
		matches, err = filepath.Glob(expanded)
		if err != nil {
			return nil, err
		}
	}

	if len(matches) > landlockGlobFallbackThreshold {
		parentDir := extractGlobParentDir(expanded)
		log.Warnf("Glob pattern '%s' matched %d paths (threshold: %d), using parent directory '%s'",
			expanded, len(matches), landlockGlobFallbackThreshold, parentDir)
		return []string{parentDir}, nil
	}

	if len(matches) == 0 {
		// Path may not exist yet. For globstar patterns, expandGlobstarPattern
		// already returned the base path when it was missing. For non-globstar
		// patterns, fall back to the literal expanded pattern so go-landlock's
		// IgnoreIfMissing handles it.
		return []string{expanded}, nil
	}

	return matches, nil
}

// landlockPolicyExplicitlyAllowsProc returns true if the policy's AllowRead or
// AllowWrite contains paths starting with /proc that are NOT /proc/self or
// /proc/self/*.
func landlockPolicyExplicitlyAllowsProc(policy *sandbox.SandboxPolicy) bool {
	allPaths := append([]string{}, policy.Filesystem.AllowRead...)
	allPaths = append(allPaths, policy.Filesystem.AllowWrite...)

	for _, p := range allPaths {
		expanded, err := util.ExpandVariables(p)
		if err != nil {
			continue
		}
		if !landlockIsProcPath(expanded) {
			continue
		}
		// Allow /proc/self and /proc/self/* without triggering
		if expanded == "/proc/self" || strings.HasPrefix(expanded, "/proc/self/") {
			continue
		}
		return true
	}

	return false
}
