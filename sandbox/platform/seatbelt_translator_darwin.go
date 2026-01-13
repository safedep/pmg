//go:build darwin
// +build darwin

package platform

import (
	"crypto/rand"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/safedep/pmg/sandbox"
	"github.com/safedep/pmg/sandbox/util"
)

type seatbeltPolicyTranslator struct {
	logTag                       string
	enableMoveBlockingMitigation bool
	enableDangerousFileBlocking  bool
}

// generateLogTag generates a unique log tag for tracking sandbox violations
func generateLogTag() string {
	// Go rand.Text() returns 26 bytes of random string
	randomStr := rand.Text()
	return fmt.Sprintf("PMG_SBX_%s", randomStr[:12])
}

func newSeatbeltPolicyTranslator() *seatbeltPolicyTranslator {
	return &seatbeltPolicyTranslator{
		logTag:                      generateLogTag(),
		enableDangerousFileBlocking: true,

		// We will keep this disabled for now. There are some issues with npm
		// that needs investigation.
		enableMoveBlockingMitigation: false,
	}
}

// extractBaseDir extracts the base directory from a path that may contain glob patterns.
// For glob patterns, it returns the deepest directory path before any glob characters appear.
// Examples:
//   - "/path/to/**" -> "/path/to"
//   - "/path/to/*.txt" -> "/path/to"
//   - "/path/*/subdir" -> "/path"
//   - "/tmp/test[123].txt" -> "/tmp"
//   - "/path/to/file" -> "/path/to/file" (no glob, return as-is)
//   - "/*.txt" -> "/" (root directory)
func extractBaseDir(pattern string) string {
	if !util.ContainsGlob(pattern) {
		return pattern
	}

	// Split the path into components
	components := strings.Split(pattern, string(filepath.Separator))

	// Find the first component that contains a glob character
	baseComponents := []string{}
	for _, component := range components {
		if util.ContainsGlob(component) {
			// Stop before the component with glob
			break
		}
		baseComponents = append(baseComponents, component)
	}

	// Join the base components back together
	basePath := strings.Join(baseComponents, string(filepath.Separator))

	// Handle edge cases
	if basePath == "" {
		// Pattern started with glob (e.g., "*.txt" or if it's an absolute path like "/*.txt", basePath would be "")
		if strings.HasPrefix(pattern, string(filepath.Separator)) {
			// Absolute path starting with glob at root (e.g., "/*.txt")
			return string(filepath.Separator)
		}

		// Relative path starting with glob (e.g., "*.txt")
		return "."
	}

	return basePath
}

// getAncestorDirectories returns all ancestor directories for a path, up to (but not including) root.
// Example: /private/tmp/test/file.txt -> ["/private/tmp/test", "/private/tmp", "/private"]
func getAncestorDirectories(pathStr string) []string {
	ancestors := []string{}
	currentPath := filepath.Dir(pathStr)

	// Walk up the directory tree until we reach root
	for currentPath != string(filepath.Separator) && currentPath != "." {
		ancestors = append(ancestors, currentPath)
		parentPath := filepath.Dir(currentPath)
		// Break if we've reached the top (filepath.Dir returns the same path for root)
		if parentPath == currentPath {
			break
		}
		currentPath = parentPath
	}

	return ancestors
}

// globDoubleStarAutoAllowParentDirIfNeeded checks if a pattern ends with /** and emits a literal rule for the parent directory.
// This ensures operations like mkdir('dir') or stat('dir') succeed before accessing dir/** contents.
func globDoubleStarAutoAllowParentDirIfNeeded(sb *strings.Builder, pattern string, expanded string, operation string) {
	if !strings.HasSuffix(expanded, "/**") {
		return
	}

	parentDir := strings.TrimSuffix(expanded, "/**")
	// Handle edge case where /** results in empty string (use "/" instead)
	if parentDir == "" {
		parentDir = "/"
	}

	sb.WriteString(fmt.Sprintf(";; Auto-allow parent directory for %s\n", pattern))
	sb.WriteString(fmt.Sprintf("(allow %s (literal \"%s\"))\n", operation, parentDir))
}

// generateMoveBlockingRules generates deny rules for file movement (file-write-unlink) to protect paths.
// This prevents bypassing read or write restrictions by moving files/directories.
//
// For each protected path pattern:
// - Blocks moving/renaming the path itself (via subpath or regex)
// - Blocks moving ancestor directories to prevent bypass
//
// Attack scenario this prevents:
//
//	Policy denies write to /sensitive/file
//	Attacker tries: mv /sensitive /tmp/renamed && echo "data" > /tmp/renamed/file && mv /tmp/renamed /sensitive
//	This blocks the initial "mv /sensitive" operation
func generateMoveBlockingRules(pathPatterns []string, logTag string) []string {
	rules := []string{}

	for _, pathPattern := range pathPatterns {
		if util.ContainsGlob(pathPattern) {
			// For glob patterns, use regex matching for precise pattern enforcement
			regexPattern := util.GlobToRegex(pathPattern)
			rules = append(rules, fmt.Sprintf("(deny file-write-unlink (regex \"%s\") (with message \"%s\"))", regexPattern, logTag))

			// Also block moving the base directory to prevent bypass
			baseDir := extractBaseDir(pathPattern)
			rules = append(rules, fmt.Sprintf("(deny file-write-unlink (subpath \"%s\") (with message \"%s\"))", baseDir, logTag))

			// Block moving ancestor directories
			for _, ancestorDir := range getAncestorDirectories(baseDir) {
				rules = append(rules, fmt.Sprintf("(deny file-write-unlink (literal \"%s\") (with message \"%s\"))", ancestorDir, logTag))
			}
		} else {
			// For literal paths, use subpath matching
			rules = append(rules, fmt.Sprintf("(deny file-write-unlink (subpath \"%s\") (with message \"%s\"))", pathPattern, logTag))

			// Block moving ancestor directories
			for _, ancestorDir := range getAncestorDirectories(pathPattern) {
				rules = append(rules, fmt.Sprintf("(deny file-write-unlink (literal \"%s\") (with message \"%s\"))", ancestorDir, logTag))
			}
		}
	}

	return rules
}

func (t *seatbeltPolicyTranslator) translate(policy *sandbox.SandboxPolicy) (string, error) {
	var sb strings.Builder

	// Header
	sb.WriteString("(version 1)\n")
	sb.WriteString(fmt.Sprintf(";; PMG Sandbox Policy: %s\n", policy.Name))
	sb.WriteString(fmt.Sprintf(";; %s\n", policy.Description))
	sb.WriteString(";; Generated by PMG sandbox system\n\n")

	// Default policy: deny by default for maximum security
	// Add log tag to track what gets denied by the default rule
	sb.WriteString(fmt.Sprintf("(deny default (with message \"%s\"))\n\n", t.logTag))

	// Essential system permissions - based on Chrome/Chromium sandbox policy
	// These are the minimum permissions needed for stable process execution
	sb.WriteString(";; Essential system permissions\n")
	sb.WriteString(";; Based on Chrome/Chromium sandbox for stable process execution\n\n")

	// Process permissions
	sb.WriteString(";; Process permissions\n")
	sb.WriteString("(allow process-exec)\n")
	sb.WriteString("(allow process-fork)\n")
	sb.WriteString("(allow process-info* (target same-sandbox))\n")
	sb.WriteString("(allow signal (target same-sandbox))\n")
	sb.WriteString("(allow mach-priv-task-port (target same-sandbox))\n\n")

	// User preferences
	sb.WriteString(";; User preferences\n")
	sb.WriteString("(allow user-preference-read)\n\n")

	// Mach IPC - specific services only (no wildcard for security)
	sb.WriteString(";; Mach IPC - specific services only\n")
	sb.WriteString("(allow mach-lookup\n")
	sb.WriteString("  (global-name \"com.apple.audio.systemsoundserver\")\n")
	sb.WriteString("  (global-name \"com.apple.distributed_notifications@Uv3\")\n")
	sb.WriteString("  (global-name \"com.apple.FontObjectsServer\")\n")
	sb.WriteString("  (global-name \"com.apple.fonts\")\n")
	sb.WriteString("  (global-name \"com.apple.logd\")\n")
	sb.WriteString("  (global-name \"com.apple.lsd.mapdb\")\n")
	sb.WriteString("  (global-name \"com.apple.PowerManagement.control\")\n")
	sb.WriteString("  (global-name \"com.apple.system.logger\")\n")
	sb.WriteString("  (global-name \"com.apple.system.notification_center\")\n")
	sb.WriteString("  (global-name \"com.apple.trustd.agent\")\n")
	sb.WriteString("  (global-name \"com.apple.system.opendirectoryd.libinfo\")\n")
	sb.WriteString("  (global-name \"com.apple.system.opendirectoryd.membership\")\n")
	sb.WriteString("  (global-name \"com.apple.bsd.dirhelper\")\n")
	sb.WriteString("  (global-name \"com.apple.securityd.xpc\")\n")
	sb.WriteString("  (global-name \"com.apple.coreservices.launchservicesd\")\n")
	sb.WriteString(")\n\n")

	// POSIX IPC
	sb.WriteString(";; POSIX IPC\n")
	sb.WriteString("(allow ipc-posix-shm)  ; Shared memory\n")
	sb.WriteString("(allow ipc-posix-sem)  ; Semaphores for Python multiprocessing\n\n")

	// IOKit operations
	sb.WriteString(";; IOKit operations\n")
	sb.WriteString("(allow iokit-open\n")
	sb.WriteString("  (iokit-registry-entry-class \"IOSurfaceRootUserClient\")\n")
	sb.WriteString("  (iokit-registry-entry-class \"RootDomainUserClient\")\n")
	sb.WriteString("  (iokit-user-client-class \"IOSurfaceSendRight\")\n")
	sb.WriteString(")\n")
	sb.WriteString("(allow iokit-get-properties)\n\n")

	// Specific safe system socket
	sb.WriteString(";; Specific safe system socket\n")
	sb.WriteString("(allow system-socket (require-all (socket-domain AF_SYSTEM) (socket-protocol 2)))\n\n")

	// sysctl - specific sysctls only
	sb.WriteString(";; sysctl - specific sysctls only\n")
	sb.WriteString("(allow sysctl-read\n")
	// Hardware info
	sb.WriteString("  (sysctl-name \"hw.activecpu\")\n")
	sb.WriteString("  (sysctl-name \"hw.busfrequency_compat\")\n")
	sb.WriteString("  (sysctl-name \"hw.byteorder\")\n")
	sb.WriteString("  (sysctl-name \"hw.cacheconfig\")\n")
	sb.WriteString("  (sysctl-name \"hw.cachelinesize_compat\")\n")
	sb.WriteString("  (sysctl-name \"hw.cpufamily\")\n")
	sb.WriteString("  (sysctl-name \"hw.cpufrequency\")\n")
	sb.WriteString("  (sysctl-name \"hw.cpufrequency_compat\")\n")
	sb.WriteString("  (sysctl-name \"hw.cputype\")\n")
	sb.WriteString("  (sysctl-name \"hw.l1dcachesize_compat\")\n")
	sb.WriteString("  (sysctl-name \"hw.l1icachesize_compat\")\n")
	sb.WriteString("  (sysctl-name \"hw.l2cachesize_compat\")\n")
	sb.WriteString("  (sysctl-name \"hw.l3cachesize_compat\")\n")
	sb.WriteString("  (sysctl-name \"hw.logicalcpu\")\n")
	sb.WriteString("  (sysctl-name \"hw.logicalcpu_max\")\n")
	sb.WriteString("  (sysctl-name \"hw.machine\")\n")
	sb.WriteString("  (sysctl-name \"hw.memsize\")\n")
	sb.WriteString("  (sysctl-name \"hw.ncpu\")\n")
	sb.WriteString("  (sysctl-name \"hw.nperflevels\")\n")
	sb.WriteString("  (sysctl-name \"hw.packages\")\n")
	sb.WriteString("  (sysctl-name \"hw.pagesize_compat\")\n")
	sb.WriteString("  (sysctl-name \"hw.pagesize\")\n")
	sb.WriteString("  (sysctl-name \"hw.physicalcpu\")\n")
	sb.WriteString("  (sysctl-name \"hw.physicalcpu_max\")\n")
	sb.WriteString("  (sysctl-name \"hw.tbfrequency_compat\")\n")
	sb.WriteString("  (sysctl-name \"hw.vectorunit\")\n")
	// Kernel info
	sb.WriteString("  (sysctl-name \"kern.argmax\")\n")
	sb.WriteString("  (sysctl-name \"kern.bootargs\")\n")
	sb.WriteString("  (sysctl-name \"kern.hostname\")\n")
	sb.WriteString("  (sysctl-name \"kern.maxfiles\")\n")
	sb.WriteString("  (sysctl-name \"kern.maxfilesperproc\")\n")
	sb.WriteString("  (sysctl-name \"kern.maxproc\")\n")
	sb.WriteString("  (sysctl-name \"kern.ngroups\")\n")
	sb.WriteString("  (sysctl-name \"kern.osproductversion\")\n")
	sb.WriteString("  (sysctl-name \"kern.osrelease\")\n")
	sb.WriteString("  (sysctl-name \"kern.ostype\")\n")
	sb.WriteString("  (sysctl-name \"kern.osvariant_status\")\n")
	sb.WriteString("  (sysctl-name \"kern.osversion\")\n")
	sb.WriteString("  (sysctl-name \"kern.secure_kernel\")\n")
	sb.WriteString("  (sysctl-name \"kern.tcsm_available\")\n")
	sb.WriteString("  (sysctl-name \"kern.tcsm_enable\")\n")
	sb.WriteString("  (sysctl-name \"kern.usrstack64\")\n")
	sb.WriteString("  (sysctl-name \"kern.version\")\n")
	sb.WriteString("  (sysctl-name \"kern.willshutdown\")\n")
	// machdep info
	sb.WriteString("  (sysctl-name \"machdep.cpu.brand_string\")\n")
	sb.WriteString("  (sysctl-name \"machdep.ptrauth_enabled\")\n")
	// Security info
	sb.WriteString("  (sysctl-name \"security.mac.lockdown_mode_state\")\n")
	// Other
	sb.WriteString("  (sysctl-name \"sysctl.proc_cputype\")\n")
	sb.WriteString("  (sysctl-name \"vm.loadavg\")\n")
	// Prefixes for more sysctls
	sb.WriteString("  (sysctl-name-prefix \"hw.optional.arm\")\n")
	sb.WriteString("  (sysctl-name-prefix \"hw.optional.arm.\")\n")
	sb.WriteString("  (sysctl-name-prefix \"hw.optional.armv8_\")\n")
	sb.WriteString("  (sysctl-name-prefix \"hw.perflevel\")\n")
	sb.WriteString("  (sysctl-name-prefix \"kern.proc.all\")\n")
	sb.WriteString("  (sysctl-name-prefix \"kern.proc.pgrp.\")\n")
	sb.WriteString("  (sysctl-name-prefix \"kern.proc.pid.\")\n")
	sb.WriteString("  (sysctl-name-prefix \"machdep.cpu.\")\n")
	sb.WriteString("  (sysctl-name-prefix \"net.routetable.\")\n")
	sb.WriteString(")\n\n")

	// V8 thread calculations
	sb.WriteString(";; V8 thread calculations\n")
	sb.WriteString("(allow sysctl-write\n")
	sb.WriteString("  (sysctl-name \"kern.tcsm_enable\")\n")
	sb.WriteString(")\n\n")

	// Distributed notifications
	sb.WriteString(";; Distributed notifications\n")
	sb.WriteString("(allow distributed-notification-post)\n\n")

	// Specific mach-lookup for security
	sb.WriteString(";; Specific mach-lookup for security\n")
	sb.WriteString("(allow mach-lookup (global-name \"com.apple.SecurityServer\"))\n\n")

	// Device file I/O
	sb.WriteString(";; Device file I/O\n")
	sb.WriteString("(allow file-ioctl (literal \"/dev/null\"))\n")
	sb.WriteString("(allow file-ioctl (literal \"/dev/zero\"))\n")
	sb.WriteString("(allow file-ioctl (literal \"/dev/random\"))\n")
	sb.WriteString("(allow file-ioctl (literal \"/dev/urandom\"))\n")
	sb.WriteString("(allow file-ioctl (literal \"/dev/dtracehelper\"))\n")
	sb.WriteString("(allow file-ioctl (literal \"/dev/tty\"))\n\n")

	sb.WriteString("(allow file-ioctl file-read-data file-write-data\n")
	sb.WriteString("  (require-all\n")
	sb.WriteString("    (literal \"/dev/null\")\n")
	sb.WriteString("    (vnode-type CHARACTER-DEVICE)\n")
	sb.WriteString("  )\n")
	sb.WriteString(")\n\n")

	// File metadata
	sb.WriteString(";; File metadata for getcwd() and similar\n")
	sb.WriteString("(allow file-read-metadata)\n\n")

	// System configuration and libraries
	sb.WriteString(";; System configuration and libraries\n")
	sb.WriteString("(allow file-read* (subpath \"/dev\"))\n")
	sb.WriteString("(allow file-read* (subpath \"/etc\"))\n\n")

	// Filesystem rules
	if err := t.translateFilesystem(policy, &sb); err != nil {
		return "", fmt.Errorf("failed to translate filesystem rules: %w", err)
	}

	// Network rules
	if err := t.translateNetwork(policy, &sb); err != nil {
		return "", fmt.Errorf("failed to translate network rules: %w", err)
	}

	// Process execution rules
	if err := t.translateProcess(policy, &sb); err != nil {
		return "", fmt.Errorf("failed to translate process rules: %w", err)
	}

	// PTY support (optional)
	if policy.AllowPTY {
		sb.WriteString(";; Pseudo-terminal (PTY) support\n")
		sb.WriteString("(allow pseudo-tty)\n")
		sb.WriteString("(allow file-ioctl\n")
		sb.WriteString("  (literal \"/dev/ptmx\")\n")
		sb.WriteString("  (regex #\"^/dev/ttys\")\n")
		sb.WriteString(")\n")
		sb.WriteString("(allow file-read* file-write*\n")
		sb.WriteString("  (literal \"/dev/ptmx\")\n")
		sb.WriteString("  (regex #\"^/dev/ttys\")\n")
		sb.WriteString(")\n\n")
	}

	return sb.String(), nil
}

// translateFilesystem translates filesystem access rules.
func (t *seatbeltPolicyTranslator) translateFilesystem(policy *sandbox.SandboxPolicy, sb *strings.Builder) error {
	sb.WriteString(";; Filesystem access\n")

	// Expand and add allow read rules
	for _, pattern := range policy.Filesystem.AllowRead {
		expanded, err := util.ExpandVariables(pattern)
		if err != nil {
			return fmt.Errorf("failed to expand pattern %s: %w", pattern, err)
		}

		// Use regex matching for glob patterns, subpath for literals
		if util.ContainsGlob(expanded) {
			globDoubleStarAutoAllowParentDirIfNeeded(sb, pattern, expanded, "file-read*")

			regexPattern := util.GlobToRegex(expanded)
			sb.WriteString(fmt.Sprintf("(allow file-read* (regex \"%s\"))\n", regexPattern))
		} else {
			sb.WriteString(fmt.Sprintf("(allow file-read* (subpath \"%s\"))\n", expanded))
		}
	}

	sb.WriteString("\n")

	// Auto-allow TMPDIR parent on macOS when write restrictions are enabled
	// This is necessary because package managers need temp file access
	hasWriteRestrictions := len(policy.Filesystem.AllowWrite) > 0
	if hasWriteRestrictions {
		tmpdirParents := util.GetTmpdirParent()
		if len(tmpdirParents) > 0 {
			sb.WriteString(";; Auto-allow TMPDIR parent on macOS\n")
			for _, parent := range tmpdirParents {
				sb.WriteString(fmt.Sprintf("(allow file-write* (subpath \"%s\"))\n", parent))
			}
			sb.WriteString("\n")
		}
	}

	// Expand and add allow write rules
	for _, pattern := range policy.Filesystem.AllowWrite {
		expanded, err := util.ExpandVariables(pattern)
		if err != nil {
			return fmt.Errorf("failed to expand pattern %s: %w", pattern, err)
		}

		// Use regex matching for glob patterns, subpath for literals
		if util.ContainsGlob(expanded) {
			globDoubleStarAutoAllowParentDirIfNeeded(sb, pattern, expanded, "file-write*")

			regexPattern := util.GlobToRegex(expanded)
			sb.WriteString(fmt.Sprintf("(allow file-write* (regex \"%s\"))\n", regexPattern))
		} else {
			sb.WriteString(fmt.Sprintf("(allow file-write* (subpath \"%s\"))\n", expanded))
		}
	}

	sb.WriteString("\n")

	// Deny rules have higher priority (applied after allow)
	// Note: Seatbelt evaluates rules in order, so denies after allows will override
	expandedDenyRead := []string{}
	for _, pattern := range policy.Filesystem.DenyRead {
		expanded, err := util.ExpandVariables(pattern)
		if err != nil {
			return fmt.Errorf("failed to expand pattern %s: %w", pattern, err)
		}

		// Use regex matching for glob patterns, subpath for literals
		if util.ContainsGlob(expanded) {
			regexPattern := util.GlobToRegex(expanded)
			sb.WriteString(fmt.Sprintf("(deny file-read* (regex \"%s\") (with message \"%s\"))\n", regexPattern, t.logTag))
		} else {
			sb.WriteString(fmt.Sprintf("(deny file-read* (subpath \"%s\") (with message \"%s\"))\n", expanded, t.logTag))
		}
		expandedDenyRead = append(expandedDenyRead, expanded)
	}

	// Add file movement protection for deny read paths
	if t.enableMoveBlockingMitigation && (len(expandedDenyRead) > 0) {
		sb.WriteString("\n;; Prevent bypassing read restrictions via file movement\n")
		for _, rule := range generateMoveBlockingRules(expandedDenyRead, t.logTag) {
			sb.WriteString(rule + "\n")
		}
	}

	sb.WriteString("\n")

	expandedDenyWrite := []string{}
	for _, pattern := range policy.Filesystem.DenyWrite {
		expanded, err := util.ExpandVariables(pattern)
		if err != nil {
			return fmt.Errorf("failed to expand pattern %s: %w", pattern, err)
		}

		// Use regex matching for glob patterns, subpath for literals
		if util.ContainsGlob(expanded) {
			regexPattern := util.GlobToRegex(expanded)
			sb.WriteString(fmt.Sprintf("(deny file-write* (regex \"%s\") (with message \"%s\"))\n", regexPattern, t.logTag))
		} else {
			sb.WriteString(fmt.Sprintf("(deny file-write* (subpath \"%s\") (with message \"%s\"))\n", expanded, t.logTag))
		}
		expandedDenyWrite = append(expandedDenyWrite, expanded)
	}

	sb.WriteString("\n")

	if t.enableDangerousFileBlocking {
		// Add mandatory deny patterns for security (credentials, git hooks, etc.)
		sb.WriteString(";; Mandatory security denies (credentials, git hooks, etc.)\n")
		mandatoryDenies := util.GetMandatoryDenyPatterns(policy.AllowGitConfig)
		for _, pattern := range mandatoryDenies {
			// Expand variables if needed
			expanded, err := util.ExpandVariables(pattern)
			if err != nil {
				return fmt.Errorf("failed to expand mandatory deny pattern %s: %w", pattern, err)
			}

			// Use regex matching for glob patterns, subpath for literals
			if util.ContainsGlob(expanded) {
				regexPattern := util.GlobToRegex(expanded)
				sb.WriteString(fmt.Sprintf("(deny file-write* (regex \"%s\") (with message \"%s\"))\n", regexPattern, t.logTag))
				sb.WriteString(fmt.Sprintf("(deny file-read* (regex \"%s\") (with message \"%s\"))\n", regexPattern, t.logTag))
			} else {
				sb.WriteString(fmt.Sprintf("(deny file-write* (subpath \"%s\") (with message \"%s\"))\n", expanded, t.logTag))
				sb.WriteString(fmt.Sprintf("(deny file-read* (subpath \"%s\") (with message \"%s\"))\n", expanded, t.logTag))
			}
			expandedDenyWrite = append(expandedDenyWrite, expanded)
		}

		sb.WriteString("\n")
	}

	// Add file movement protection for all deny write paths (user + mandatory)
	if t.enableMoveBlockingMitigation && (len(expandedDenyWrite) > 0) {
		sb.WriteString(";; Prevent bypassing write restrictions via file movement\n")
		for _, rule := range generateMoveBlockingRules(expandedDenyWrite, t.logTag) {
			sb.WriteString(rule + "\n")
		}
	}

	sb.WriteString("\n")

	return nil
}

// translateNetwork translates network access rules.
func (t *seatbeltPolicyTranslator) translateNetwork(policy *sandbox.SandboxPolicy, sb *strings.Builder) error {
	sb.WriteString(";; Network access\n")

	// Check if deny all is present
	denyAll := false
	for _, pattern := range policy.Network.DenyOutbound {
		if pattern == "*:*" {
			denyAll = true
			break
		}
	}

	// If there are allow outbound rules, allow network-outbound generally
	// (Seatbelt doesn't support fine-grained host:port filtering in all cases)
	// Note: This is a limitation of Seatbelt - for more fine-grained control,
	// consider using a network filtering solution or firewall rules
	if len(policy.Network.AllowOutbound) > 0 {
		sb.WriteString(";; Network outbound allowed to specific hosts\n")
		sb.WriteString(";; Note: Seatbelt has limited host-based filtering, consider using firewall rules for strict control\n")
		sb.WriteString("(allow network-outbound)\n")
	} else if denyAll {
		// If there are no allow rules but deny all is set, explicitly deny network
		// This handles the case where user wants to completely block network access
		sb.WriteString(";; Network outbound denied (no allowed hosts specified)\n")
		sb.WriteString("(deny network-outbound)\n")
	}

	// Note: We don't add an explicit deny rule when both allow and deny_all are present
	// because the default (deny default) at the top of the profile handles blocking
	// everything that isn't explicitly allowed. Adding an explicit deny here would
	// override the allow rule above, breaking network access entirely.

	sb.WriteString("\n")

	return nil
}

// translateProcess translates process execution rules.
func (t *seatbeltPolicyTranslator) translateProcess(policy *sandbox.SandboxPolicy, sb *strings.Builder) error {
	sb.WriteString(";; Process execution\n")

	// Add allow exec rules
	for _, exePath := range policy.Process.AllowExec {
		expanded, err := util.ExpandVariables(exePath)
		if err != nil {
			return fmt.Errorf("failed to expand exec path %s: %w", exePath, err)
		}

		if util.ContainsGlob(expanded) {
			// For glob patterns, use regex matching for precise control
			regexPattern := util.GlobToRegex(expanded)
			sb.WriteString(fmt.Sprintf("(allow process-exec* (regex \"%s\"))\n", regexPattern))
		} else {
			sb.WriteString(fmt.Sprintf("(allow process-exec* (literal \"%s\"))\n", expanded))
		}
	}

	sb.WriteString("\n")

	// Add deny exec rules
	for _, exePath := range policy.Process.DenyExec {
		expanded, err := util.ExpandVariables(exePath)
		if err != nil {
			return fmt.Errorf("failed to expand exec path %s: %w", exePath, err)
		}

		if util.ContainsGlob(expanded) {
			// For glob patterns, use regex matching for precise control
			regexPattern := util.GlobToRegex(expanded)
			sb.WriteString(fmt.Sprintf("(deny process-exec* (regex \"%s\") (with message \"%s\"))\n", regexPattern, t.logTag))
		} else {
			sb.WriteString(fmt.Sprintf("(deny process-exec* (literal \"%s\") (with message \"%s\"))\n", expanded, t.logTag))
		}
	}

	sb.WriteString("\n")

	return nil
}
