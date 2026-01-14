//go:build linux
// +build linux

package platform

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/safedep/dry/log"
	"github.com/safedep/dry/utils"
	"github.com/safedep/pmg/sandbox"
	"github.com/safedep/pmg/sandbox/util"
)

// bubblewrapPolicyTranslator translates PMG SandboxPolicy to Bubblewrap (bwrap) CLI arguments.
//
// Bubblewrap uses command-line arguments instead of profile files (like Seatbelt).
// The translator generates arguments for:
// - Filesystem bind mounts (--bind, --ro-bind, --dev-bind)
// - Network isolation (--unshare-net)
// - Process isolation (--unshare-pid, --unshare-ipc)
// - Device access (--dev-bind /dev/null, etc.)
// - Essential system permissions
type bubblewrapPolicyTranslator struct {
	config *bubblewrapConfig
}

// newBubblewrapPolicyTranslator creates a new translator with the given config.
func newBubblewrapPolicyTranslator(config *bubblewrapConfig) *bubblewrapPolicyTranslator {
	return &bubblewrapPolicyTranslator{
		config: config,
	}
}

// translate converts a PMG SandboxPolicy to bwrap CLI arguments.
// Returns a slice of arguments to pass to the bwrap command.
func (t *bubblewrapPolicyTranslator) translate(policy *sandbox.SandboxPolicy) ([]string, error) {
	args := []string{}

	// 1. Add essential system permissions (filesystem, devices, proc)
	systemArgs, err := t.addEssentialSystemPermissions()
	if err != nil {
		return nil, fmt.Errorf("failed to add essential system permissions: %w", err)
	}

	args = append(args, systemArgs...)

	// 2. Add isolation namespaces
	isolationArgs := t.addIsolationNamespaces(policy)
	args = append(args, isolationArgs...)

	// 3. Add filesystem rules (allow read, allow write, deny patterns)
	filesystemArgs, err := t.translateFilesystem(policy)
	if err != nil {
		return nil, fmt.Errorf("failed to translate filesystem rules: %w", err)
	}

	args = append(args, filesystemArgs...)

	// 4. Add PTY support if needed
	if utils.SafelyGetValue(policy.AllowPTY) {
		ptyArgs := t.addPTYSupport()
		args = append(args, ptyArgs...)
	}

	// 5. Add tmpdir support (package managers need writable temp directory)
	tmpdirArgs := t.addTmpdirSupport()
	args = append(args, tmpdirArgs...)

	// 6. Check total argument limit and log warning if exceeded
	// Do not fail, let bwrap fail naturally if it does.
	if len(args) > t.config.totalArgsLimit {
		log.Warnf("Total bwrap arguments (%d) exceeds safety limit (%d), sandbox may fail with 'Argument list too long' error",
			len(args), t.config.totalArgsLimit)
	}

	log.Debugf("Translated policy '%s' to %d bwrap arguments (limit: %d)", policy.Name, len(args), t.config.totalArgsLimit)

	return args, nil
}

// addEssentialSystemPermissions adds bind mounts for essential system paths and devices
// that package managers need to function properly.
func (t *bubblewrapPolicyTranslator) addEssentialSystemPermissions() ([]string, error) {
	args := []string{}

	// Add essential system paths (read-only)
	for _, path := range t.config.getEssentialSystemPaths() {
		args = append(args, "--ro-bind-try", path, path)
	}

	// Add essential device files
	for _, device := range t.config.getEssentialDevices() {
		args = append(args, "--dev-bind-try", device, device)
	}

	// Add proc filesystem (read-only for safety)
	for _, procPath := range t.config.procPaths {
		args = append(args, "--proc", procPath)
	}

	return args, nil
}

// addIsolationNamespaces adds namespace isolation arguments based on policy and config.
func (t *bubblewrapPolicyTranslator) addIsolationNamespaces(policy *sandbox.SandboxPolicy) []string {
	args := []string{}

	// Network isolation
	hasAllowRules := len(policy.Network.AllowOutbound) > 0
	hasDenyAll := false
	for _, pattern := range policy.Network.DenyOutbound {
		if pattern == "*:*" {
			hasDenyAll = true
			break
		}
	}

	if t.config.shouldUnshareNetwork(hasAllowRules, hasDenyAll) {
		args = append(args, "--unshare-net")
		log.Debugf("Network isolated (--unshare-net)")
	} else {
		log.Debugf("Network allowed (no --unshare-net)")
	}

	// PID namespace isolation
	if t.config.unsharePID {
		args = append(args, "--unshare-pid")
	}

	// IPC namespace isolation
	if t.config.unshareIPC {
		args = append(args, "--unshare-ipc")
	}

	// New session
	if t.config.newSession {
		args = append(args, "--new-session")
	}

	// Die with parent
	if t.config.dieWithParent {
		args = append(args, "--die-with-parent")
	}

	return args
}

// translateFilesystem converts filesystem policy rules to bwrap bind mount arguments.
//
// Bubblewrap filesystem isolation works via bind mounts:
// - --ro-bind: Read-only bind mount
// - --bind: Read-write bind mount
// - --dev-bind: Device file bind mount
// - Paths not mounted are inaccessible (deny-by-default)
//
// Strategy:
// 1. Start with essential system paths (added separately)
// 2. Add user-specified allow_read paths FIRST (read-only bind mounts)
//    This establishes the base filesystem view (e.g., "/" for full access)
// 3. Add user-specified allow_write paths SECOND (read-write bind mounts)
//    These OVERRIDE earlier read-only binds (bwrap: later mounts win)
// 4. Handle deny patterns by mounting /dev/null or read-only for directories
// 5. Add mandatory deny patterns
func (t *bubblewrapPolicyTranslator) translateFilesystem(policy *sandbox.SandboxPolicy) ([]string, error) {
	args := []string{}

	// Track paths we've already bound to avoid duplicates
	boundPaths := make(map[string]bool)

	// Add essential system paths to bound paths (already handled separately)
	for _, path := range t.config.getEssentialSystemPaths() {
		boundPaths[path] = true
	}

	// Mark tmpdir as already bound (will be handled by addTmpdirSupport())
	// This prevents conflicts from policy patterns like /tmp/**
	tmpDir := os.TempDir()
	boundPaths[tmpDir] = true

	// 1. Process allow_read rules FIRST (read-only bind mounts)
	// This establishes the base read-only filesystem view (including "/" if specified)
	for _, pattern := range policy.Filesystem.AllowRead {
		expanded, err := util.ExpandVariables(pattern)
		if err != nil {
			log.Warnf("Failed to expand variables in allow_read pattern '%s': %v", pattern, err)
			continue
		}

		readArgs, err := t.processReadRule(expanded, boundPaths)
		if err != nil {
			log.Warnf("Failed to process allow_read rule '%s': %v", expanded, err)
			continue
		}
		args = append(args, readArgs...)
	}

	// 2. Process allow_write rules SECOND (read-write bind mounts)
	// These OVERRIDE earlier read-only binds (bwrap: later mounts win)
	// Use a separate map so we don't skip paths that need write access
	writeBoundPaths := make(map[string]bool)
	writeBoundPaths[tmpDir] = true // tmpdir handled by addTmpdirSupport
	for _, pattern := range policy.Filesystem.AllowWrite {
		expanded, err := util.ExpandVariables(pattern)
		if err != nil {
			log.Warnf("Failed to expand variables in allow_write pattern '%s': %v", pattern, err)
			continue
		}

		writeArgs, err := t.processWriteRule(expanded, writeBoundPaths)
		if err != nil {
			log.Warnf("Failed to process allow_write rule '%s': %v", expanded, err)
			continue
		}
		args = append(args, writeArgs...)
	}

	// 3. Process deny_write rules (mount /dev/null to prevent creation)
	allowGitConfig := utils.SafelyGetValue(policy.AllowGitConfig)
	denyPatterns := append([]string{}, policy.Filesystem.DenyWrite...)

	// Add mandatory deny patterns (credentials - these get completely hidden)
	mandatoryDenies := util.GetMandatoryDenyPatterns(allowGitConfig)
	denyPatterns = append(denyPatterns, mandatoryDenies...)

	for _, pattern := range denyPatterns {
		expanded, err := util.ExpandVariables(pattern)
		if err != nil {
			log.Warnf("Failed to expand variables in deny pattern '%s': %v", pattern, err)
			continue
		}

		denyArgs, err := t.processDenyRule(expanded)
		if err != nil {
			// Deny rules failing is not critical (file may not exist yet)
			log.Debugf("Deny rule '%s' skipped: %v", expanded, err)
			continue
		}
		args = append(args, denyArgs...)
	}

	// 4. Process mandatory credential directories - completely hide them with tmpfs
	// This blocks both read AND write access (more secure than read-only mount)
	hiddenDirs := make(map[string]bool) // Track to avoid duplicates
	for _, pattern := range mandatoryDenies {
		expanded, err := util.ExpandVariables(pattern)
		if err != nil {
			continue
		}

		var dirsToHide []string
		if util.ContainsGlob(expanded) {
			// Expand glob pattern to find matching directories
			matches, err := filepath.Glob(expanded)
			if err != nil {
				continue
			}
			dirsToHide = matches
		} else {
			dirsToHide = []string{expanded}
		}

		for _, dir := range dirsToHide {
			if hiddenDirs[dir] {
				continue
			}
			if info, err := os.Stat(dir); err == nil && info.IsDir() {
				args = append(args, "--tmpfs", dir)
				hiddenDirs[dir] = true
				log.Debugf("Hiding credential directory '%s' with tmpfs", dir)
			}
		}
	}

	// 5. Process deny_exec rules (mount /dev/null over executables)
	for _, exePath := range policy.Process.DenyExec {
		expanded, err := util.ExpandVariables(exePath)
		if err != nil {
			log.Warnf("Failed to expand variables in deny_exec pattern '%s': %v", exePath, err)
			continue
		}

		// Handle glob patterns (e.g., /usr/bin/python*)
		if util.ContainsGlob(expanded) {
			matches, err := filepath.Glob(expanded)
			if err != nil {
				log.Warnf("Failed to expand deny_exec glob '%s': %v", expanded, err)
				continue
			}
			for _, match := range matches {
				if info, err := os.Stat(match); err == nil && !info.IsDir() {
					args = append(args, "--ro-bind", "/dev/null", match)
					log.Debugf("Blocked execution of '%s'", match)
				}
			}
		} else {
			// Literal path
			if info, err := os.Stat(expanded); err == nil && !info.IsDir() {
				args = append(args, "--ro-bind", "/dev/null", expanded)
				log.Debugf("Blocked execution of '%s'", expanded)
			}
		}
	}

	return args, nil
}

// processReadRule handles a single allow_read rule, expanding globs and creating ro-bind mounts.
func (t *bubblewrapPolicyTranslator) processReadRule(path string, boundPaths map[string]bool) ([]string, error) {
	args := []string{}

	// Check if path contains glob pattern
	if util.ContainsGlob(path) {
		// Check if the base directory is already bound
		baseDir := t.extractParentDir(path)
		if boundPaths[baseDir] {
			log.Debugf("Skipping pattern '%s' - base directory '%s' already bound", path, baseDir)
			return args, nil
		}

		// Expand glob pattern to concrete paths with fallback detection
		paths, useFallback, err := t.expandGlobPattern(path, t.config.maxGlobDepth, t.config.maxGlobPaths)
		if err != nil {
			return nil, fmt.Errorf("failed to expand glob pattern: %w", err)
		}

		if useFallback {
			// Coarse-grained: bind parent directory
			for _, parentDir := range paths {
				if !boundPaths[parentDir] {
					args = append(args, "--ro-bind-try", parentDir, parentDir)
					boundPaths[parentDir] = true
					log.Debugf("Coarse-grained fallback: bound parent directory '%s' (read-only)", parentDir)
				}
			}
		} else {
			// Fine-grained: bind individual paths
			for _, p := range paths {
				if !boundPaths[p] {
					args = append(args, "--ro-bind-try", p, p)
					boundPaths[p] = true
				}
			}
		}
	} else {
		// Literal path - create read-only bind
		if !boundPaths[path] {
			args = append(args, "--ro-bind-try", path, path)
			boundPaths[path] = true
		}
	}

	return args, nil
}

// processWriteRule handles a single allow_write rule, expanding globs and creating rw-bind mounts.
func (t *bubblewrapPolicyTranslator) processWriteRule(path string, boundPaths map[string]bool) ([]string, error) {
	args := []string{}

	// Check if path contains glob pattern
	if util.ContainsGlob(path) {
		// Check if the base directory is already bound (e.g., /tmp already bound, skip /tmp/**)
		baseDir := t.extractParentDir(path)
		if boundPaths[baseDir] {
			log.Debugf("Skipping pattern '%s' - base directory '%s' already bound", path, baseDir)
			return args, nil
		}

		// Expand glob pattern to concrete paths with fallback detection
		paths, useFallback, err := t.expandGlobPattern(path, t.config.maxGlobDepth, t.config.maxGlobPaths)
		if err != nil {
			return nil, fmt.Errorf("failed to expand glob pattern: %w", err)
		}

		if useFallback {
			// Coarse-grained: bind parent directory
			for _, parentDir := range paths {
				if !boundPaths[parentDir] {
					args = append(args, "--bind-try", parentDir, parentDir)
					boundPaths[parentDir] = true
					log.Debugf("Coarse-grained fallback: bound parent directory '%s' (read-write)", parentDir)
				} else {
					// Path already bound, skip (likely already bound as read-only from essential paths)
					log.Debugf("Parent directory '%s' already bound, skipping duplicate bind", parentDir)
				}
			}
		} else {
			// Fine-grained: bind individual paths
			for _, p := range paths {
				// Check if path exists - if not, bind parent directory instead
				// This allows creating new directories (e.g., node_modules/** when node_modules doesn't exist)
				pathToBind := p
				if _, err := os.Stat(p); os.IsNotExist(err) {
					parentDir := filepath.Dir(p)
					if parentDir != "" && parentDir != "." && parentDir != "/" {
						pathToBind = parentDir
						log.Debugf("Path '%s' doesn't exist, binding parent '%s' as writable to allow creation", p, parentDir)
					}
				}

				if !boundPaths[pathToBind] {
					args = append(args, "--bind-try", pathToBind, pathToBind)
					boundPaths[pathToBind] = true
				} else {
					// Path already bound, add another bind to upgrade to read-write
					// bwrap: later mounts override earlier ones
					args = append(args, "--bind-try", pathToBind, pathToBind)
					log.Debugf("Path '%s' already bound, adding write bind to override", pathToBind)
				}
			}
		}
	} else {
		// Literal path - create read-write bind
		if !boundPaths[path] {
			args = append(args, "--bind-try", path, path)
			boundPaths[path] = true
		}
	}

	return args, nil
}

// processDenyRule handles deny rules by mounting /dev/null to prevent file creation.
// This technique is borrowed from Anthropic's sandbox-runtime.
func (t *bubblewrapPolicyTranslator) processDenyRule(path string) ([]string, error) {
	args := []string{}

	// For glob patterns, expand and deny each path
	if util.ContainsGlob(path) {
		// For deny rules, we scan for existing files matching the pattern
		// Note: For deny rules, we ignore the fallback indicator since we want to
		// deny all matched paths individually for maximum security
		paths, _, err := t.expandGlobPattern(path, t.config.mandatoryDenyScanDepth, t.config.maxGlobPaths)
		if err != nil {
			// If glob expansion fails, it's not critical for deny rules
			return args, nil
		}

		for _, p := range paths {
			info, err := os.Stat(p)
			if err == nil {
				if info.IsDir() {
					// For directories, mount as read-only to prevent writes
					// This overrides any previous writable bind of parent directories
					args = append(args, "--ro-bind-try", p, p)
					log.Debugf("Deny rule: mounted directory '%s' as read-only", p)
				} else {
					// For files, mount /dev/null to prevent access
					args = append(args, "--ro-bind", "/dev/null", p)
				}
			}
		}
	} else {
		// For literal paths, check if they exist
		if info, err := os.Stat(path); err == nil {
			if info.IsDir() {
				// For directories, mount as read-only to prevent writes
				// This overrides any previous writable bind of parent directories
				args = append(args, "--ro-bind-try", path, path)
				log.Debugf("Deny rule: mounted directory '%s' as read-only", path)
			} else {
				// File exists - mount /dev/null over it
				args = append(args, "--ro-bind", "/dev/null", path)
			}
		} else if os.IsNotExist(err) {
			// File doesn't exist - skip blocking it
			// Rationale: bwrap cannot create mount points in read-only parent directories.
			// Non-existent files are already protected by deny-by-default (not in allow_write).
			log.Debugf("Deny rule: skipping non-existent path '%s' (already protected by deny-by-default)", path)
		}
	}

	return args, nil
}

// findFirstNonExistentPath walks up the directory tree to find the first path component
// that doesn't exist. This allows us to block file creation by mounting /dev/null.
//
// Example: If /home/user/.env doesn't exist but /home/user does, returns /home/user/.env
func (t *bubblewrapPolicyTranslator) findFirstNonExistentPath(path string) string {
	path = filepath.Clean(path)

	// Walk up the tree
	for path != "/" && path != "." {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			// Check if parent exists
			parent := filepath.Dir(path)
			if _, err := os.Stat(parent); err == nil {
				// Parent exists, this is the first non-existent path
				return path
			}
		}
		path = filepath.Dir(path)
	}

	return ""
}

// expandGlobPattern expands a glob pattern to a list of concrete paths.
// Implements depth limiting and path count limiting to prevent DoS.
// Returns (paths, useFallback, error) where useFallback indicates if
// coarse-grained parent directory fallback should be used.
func (t *bubblewrapPolicyTranslator) expandGlobPattern(pattern string, maxDepth int, maxPaths int) ([]string, bool, error) {
	// Handle ** globstar patterns specially
	if strings.Contains(pattern, "**") {
		paths, err := t.expandGlobstarPattern(pattern, maxDepth, maxPaths)
		if err != nil {
			return nil, false, err
		}

		// Check if we should use fallback
		if len(paths) > t.config.globFallbackThreshold {
			log.Warnf("Glob pattern '%s' matched %d paths (threshold: %d), using coarse-grained parent directory fallback for scalability",
				pattern, len(paths), t.config.globFallbackThreshold)

			parentDir := t.extractParentDir(pattern)
			return []string{parentDir}, true, nil
		}

		return paths, false, nil
	}

	// Use filepath.Glob for simple patterns (*, ?, [])
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, false, fmt.Errorf("glob expansion failed: %w", err)
	}

	// Check fallback threshold before applying maxPaths limit
	if len(matches) > t.config.globFallbackThreshold {
		log.Warnf("Glob pattern '%s' matched %d paths (threshold: %d), using coarse-grained parent directory fallback for scalability",
			pattern, len(matches), t.config.globFallbackThreshold)
		parentDir := t.extractParentDir(pattern)
		return []string{parentDir}, true, nil
	}

	// Limit number of matches (shouldn't happen if fallback threshold < maxPaths)
	if len(matches) > maxPaths {
		log.Warnf("Glob pattern '%s' matched %d paths, limiting to %d", pattern, len(matches), maxPaths)
		matches = matches[:maxPaths]
	}

	return matches, false, nil
}

// expandGlobstarPattern expands patterns containing ** (recursive glob).
// This requires custom implementation since filepath.Glob doesn't support **.
func (t *bubblewrapPolicyTranslator) expandGlobstarPattern(pattern string, maxDepth int, maxPaths int) ([]string, error) {
	// Split pattern at **
	parts := strings.Split(pattern, "**")
	if len(parts) != 2 {
		return nil, fmt.Errorf("only one ** globstar supported per pattern")
	}

	basePath := strings.TrimSuffix(parts[0], "/")
	suffix := strings.TrimPrefix(parts[1], "/")

	// If base path is empty, it would walk from root which is prohibitively expensive.
	// Skip such patterns to prevent filesystem scan timeouts.
	if basePath == "" {
		log.Debugf("Skipping globstar pattern '%s' with empty base path (would walk from root)", pattern)
		return []string{}, nil
	}

	// Expand base path variables
	var err error
	basePath, err = util.ExpandVariables(basePath)
	if err != nil {
		return nil, fmt.Errorf("failed to expand base path: %w", err)
	}

	// Check if base path exists
	if _, err := os.Stat(basePath); os.IsNotExist(err) {
		// Base path doesn't exist yet, return just the base
		return []string{basePath}, nil
	}

	matches := []string{}

	// Walk the directory tree with depth limiting
	err = t.walkWithDepthLimit(basePath, suffix, maxDepth, maxPaths, &matches)
	if err != nil {
		return nil, fmt.Errorf("failed to walk directory tree: %w", err)
	}

	return matches, nil
}

// walkWithDepthLimit walks a directory tree with depth limiting.
func (t *bubblewrapPolicyTranslator) walkWithDepthLimit(root string, suffix string, maxDepth int, maxPaths int, matches *[]string) error {
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Skip paths we can't access
			return nil
		}

		// Calculate depth
		relPath, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		depth := len(strings.Split(relPath, string(filepath.Separator)))

		// Enforce depth limit
		if maxDepth > 0 && depth > maxDepth {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Match suffix
		if suffix == "" || strings.HasSuffix(path, suffix) {
			*matches = append(*matches, path)

			// Enforce path count limit
			if len(*matches) >= maxPaths {
				return filepath.SkipAll
			}
		}

		return nil
	})

	return err
}

// extractParentDir extracts the parent directory from a glob pattern.
// This is used for coarse-grained fallback when glob expansion yields too many paths.
//
// Examples:
//   - ${CWD}/node_modules/** → ${CWD}/node_modules
//   - ${HOME}/.cache/pnpm/** → ${HOME}/.cache/pnpm
//   - /tmp/*.txt → /tmp
//   - /usr/lib/**/*.so → /usr/lib
//   - ${CWD}/package.json.* → ${CWD}
func (t *bubblewrapPolicyTranslator) extractParentDir(pattern string) string {
	// Remove trailing /** or /*
	pattern = strings.TrimSuffix(pattern, "/**")
	pattern = strings.TrimSuffix(pattern, "/*")

	// Remove any remaining glob characters and find the parent directory
	idx := strings.IndexAny(pattern, "*?[")
	if idx >= 0 {
		// Glob found - truncate at glob character and get the directory
		pattern = pattern[:idx]
		// Get the directory containing the file/pattern
		pattern = filepath.Dir(pattern)
	}

	// Clean up trailing separator
	pattern = strings.TrimSuffix(pattern, string(filepath.Separator))

	// If pattern is now empty or just a separator, default to current directory
	if pattern == "" || pattern == string(filepath.Separator) {
		return "."
	}

	return pattern
}

// addPTYSupport adds arguments for pseudo-terminal support.
// Required for interactive package manager commands.
func (t *bubblewrapPolicyTranslator) addPTYSupport() []string {
	args := []string{}

	// Bind /dev/pts for PTY allocation
	args = append(args, "--dev-bind-try", "/dev/pts", "/dev/pts")

	// Bind /dev/ptmx for PTY master
	args = append(args, "--dev-bind-try", "/dev/ptmx", "/dev/ptmx")

	return args
}

// addTmpdirSupport adds arguments for temporary directory access.
// Package managers need writable temp space for downloads, extraction, etc.
func (t *bubblewrapPolicyTranslator) addTmpdirSupport() []string {
	args := []string{}

	tmpDir := os.TempDir()

	// Bind tmp directory as writable
	// Use --bind instead of --bind-try to ensure it's available
	args = append(args, "--bind", tmpDir, tmpDir)

	return args
}
