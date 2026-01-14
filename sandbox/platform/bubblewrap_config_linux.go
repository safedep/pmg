//go:build linux
// +build linux

package platform

import (
	"os"
	"path/filepath"
)

// bubblewrapConfig contains configuration for Bubblewrap sandbox behavior.
// This allows for tuning sandbox isolation without hardcoding magic values
// throughout the translator.
type bubblewrapConfig struct {
	// Essential system paths that are always mounted read-only for package managers
	// to function. These paths provide access to system libraries, binaries, and
	// runtime dependencies.
	essentialSystemPaths []string

	// Essential device files that must be accessible in the sandbox.
	// These are critical for basic I/O operations and random number generation.
	essentialDevices []string

	// Proc filesystem paths to mount. The /proc filesystem provides runtime
	// information about processes, system resources, and kernel parameters.
	procPaths []string

	// Maximum depth for glob pattern expansion. Limits filesystem traversal
	// to prevent excessive scanning of deep directory trees.
	// Set to 0 for unlimited depth (not recommended).
	maxGlobDepth int

	// Maximum number of paths to expand from a single glob pattern.
	// Prevents memory exhaustion from patterns matching huge directory trees.
	maxGlobPaths int

	// Whether to unshare the network namespace by default if policy has no network rules.
	// When true and no network rules specified, completely isolates network access.
	unshareNetworkByDefault bool

	// Whether to unshare the PID namespace. Isolates process tree visibility.
	// Recommended for security but may break some package managers that inspect processes.
	unsharePID bool

	// Whether to unshare the IPC namespace. Isolates System V IPC and POSIX message queues.
	unshareIPC bool

	// Whether to create a new session (setsid). Detaches from terminal session.
	newSession bool

	// Whether to die when parent process exits. Ensures cleanup of orphaned sandboxes.
	dieWithParent bool

	// Seccomp filter configuration
	seccomp seccompConfig

	// Mandatory deny file patterns (overrides user policy)
	// These files are always protected regardless of user configuration.
	mandatoryDenyPatterns []string

	// Maximum depth to scan for mandatory deny patterns (e.g., .env files in subdirectories)
	// Set to 0 to only check literal paths, higher values scan subdirectories.
	mandatoryDenyScanDepth int
}

// seccompConfig contains seccomp-bpf filter settings
type seccompConfig struct {
	// Whether to enable seccomp filtering
	enabled bool

	// Path to seccomp filter file (BPF bytecode)
	// If empty, uses built-in default filter
	filterPath string

	// Syscalls to deny (blocklist approach)
	// Common dangerous syscalls: ptrace, kexec_load, module_init, etc.
	deniedSyscalls []string
}

// newDefaultBubblewrapConfig creates a bubblewrap config with safe default values.
// These defaults are based on:
// - Common Linux filesystem layouts (FHS - Filesystem Hierarchy Standard)
// - Anthropic Sandbox Runtime implementation patterns
// - Flatpak's bubblewrap usage
// - Chrome/Docker seccomp profiles
func newDefaultBubblewrapConfig() *bubblewrapConfig {
	return &bubblewrapConfig{
		// Essential system paths (read-only)
		// Based on Filesystem Hierarchy Standard (FHS)
		essentialSystemPaths: []string{
			"/usr",     // User binaries, libraries, documentation
			"/lib",     // Essential shared libraries
			"/lib64",   // 64-bit libraries (on x86_64 systems)
			"/bin",     // Essential command binaries (may be symlink to /usr/bin)
			"/sbin",    // System binaries (may be symlink to /usr/sbin)
			"/etc",     // System configuration files (read-only access needed for DNS, etc.)
			"/opt",     // Optional application software packages
			"/var/lib", // Variable state information (package databases, etc.)
			"/sys",     // Sysfs - kernel and device information
		},

		// Essential device files
		// Required for basic I/O, randomness, and null device operations
		essentialDevices: []string{
			"/dev/null",
			"/dev/zero",
			"/dev/random",
			"/dev/urandom",
			"/dev/full",
			"/dev/tty", // For terminal operations
		},

		// Proc filesystem paths
		// Provides process and system information
		procPaths: []string{
			"/proc", // Full proc filesystem
		},

		// Glob expansion limits
		// Conservative defaults to prevent DoS via huge glob patterns
		maxGlobDepth: 5,     // Scan up to 5 directory levels
		maxGlobPaths: 10000, // Maximum 10k paths per glob pattern

		// Network isolation (default: isolate network if no rules)
		unshareNetworkByDefault: true,

		// Process/IPC isolation
		unsharePID:    true, // Isolate PID namespace
		unshareIPC:    true, // Isolate IPC namespace
		newSession:    true, // Create new session
		dieWithParent: true, // Cleanup on parent exit

		// Seccomp configuration
		seccomp: seccompConfig{
			enabled:    false, // Disabled by default (Phase 4 enhancement)
			filterPath: "",    // Use built-in filter when enabled
			deniedSyscalls: []string{
				// Dangerous syscalls that should be blocked
				"ptrace",          // Process tracing (debugging/injection)
				"kexec_load",      // Load new kernel
				"module_init",     // Load kernel modules
				"reboot",          // System reboot
				"swapon",          // Enable swap
				"swapoff",         // Disable swap
				"mount",           // Mount filesystems
				"umount",          // Unmount filesystems
				"pivot_root",      // Change root filesystem
				"chroot",          // Change root directory
				"unshare",         // Create new namespaces (prevent nested sandboxing)
				"setns",           // Join existing namespace
				"acct",            // Process accounting
				"add_key",         // Add key to kernel keyring
				"request_key",     // Request key from kernel
				"keyctl",          // Manipulate kernel keyring
				"ioperm",          // Set port I/O permissions
				"iopl",            // Set I/O privilege level
				"perf_event_open", // Performance monitoring
			},
		},

		// Mandatory deny patterns
		// These files are ALWAYS protected, regardless of user policy
		mandatoryDenyPatterns: getMandatoryDenyPatterns(),

		// Scan depth for finding dangerous files in project directories
		mandatoryDenyScanDepth: 3, // Check up to 3 levels deep
	}
}

// getMandatoryDenyPatterns returns file patterns that must always be denied write access.
// These patterns protect credentials, secrets, and security-critical files.
func getMandatoryDenyPatterns() []string {
	home, _ := os.UserHomeDir()

	patterns := []string{
		// Environment files (secrets, API keys)
		".env",
		".env.*", // .env.local, .env.production, etc.

		// Cloud provider credentials
		".aws",           // AWS credentials
		".aws/**",        // AWS config files
		".gcloud",        // Google Cloud credentials
		".gcloud/**",     // GCloud config
		".azure",         // Azure credentials
		".azure/**",      // Azure config
		".config/gcloud", // Alternative GCloud location

		// SSH keys
		".ssh",       // SSH directory
		".ssh/**",    // All SSH files
		"id_rsa",     // SSH private key
		"id_ed25519", // Ed25519 SSH key
		"id_ecdsa",   // ECDSA SSH key

		// GPG/PGP keys
		".gnupg",
		".gnupg/**",

		// Kubernetes credentials
		".kube",
		".kube/**",
		".kubeconfig",

		// Docker credentials
		".docker/config.json",

		// Git security-critical files
		".git/hooks",    // Git hooks (can execute arbitrary code)
		".git/hooks/**", // All git hooks
		".gitconfig",    // Global git config

		// Shell configurations (backdoor risk)
		".bashrc",
		".bash_profile",
		".zshrc",
		".zprofile",
		".profile",

		// NPM/Node credentials
		".npmrc", // May contain auth tokens (read-only is fine, write is dangerous)

		// Python credentials
		".pypirc", // PyPI credentials

		// Database credentials
		".pgpass",        // PostgreSQL password file
		".my.cnf",        // MySQL config
		".mysql_history", // MySQL command history (may contain passwords)

		// Browser/session data
		".mozilla",
		".chrome",
		".chromium",

		// Additional credential stores
		".netrc",  // Network authentication
		".docker", // Docker configs
	}

	// Add home-directory-prefixed versions for absolute path matching
	homePrefixed := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		homePrefixed = append(homePrefixed, filepath.Join(home, pattern))
	}

	return append(patterns, homePrefixed...)
}

// shouldUnshareNetwork determines whether to isolate network based on policy.
// Returns true if network should be completely isolated (--unshare-net).
func (c *bubblewrapConfig) shouldUnshareNetwork(hasAllowRules bool, hasDenyAll bool) bool {
	// If policy explicitly denies all network ("*:*"), isolate
	if hasDenyAll {
		return true
	}

	// If no allow rules and default is to isolate, unshare
	if !hasAllowRules && c.unshareNetworkByDefault {
		return true
	}

	// Otherwise, allow network (no --unshare-net)
	return false
}

// getEssentialSystemPaths returns essential system paths for read-only binding.
// Filters out paths that don't exist on this system (e.g., /lib64 on 32-bit).
func (c *bubblewrapConfig) getEssentialSystemPaths() []string {
	existingPaths := make([]string, 0, len(c.essentialSystemPaths))
	for _, path := range c.essentialSystemPaths {
		if _, err := os.Stat(path); err == nil {
			existingPaths = append(existingPaths, path)
		}
	}
	return existingPaths
}

// getEssentialDevices returns essential device files for binding.
// Filters out devices that don't exist on this system.
func (c *bubblewrapConfig) getEssentialDevices() []string {
	existingDevices := make([]string, 0, len(c.essentialDevices))
	for _, device := range c.essentialDevices {
		if _, err := os.Stat(device); err == nil {
			existingDevices = append(existingDevices, device)
		}
	}
	return existingDevices
}
