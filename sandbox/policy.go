package sandbox

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode"

	"github.com/safedep/dry/utils"
	"github.com/safedep/pmg/sandbox/util"
)

// SandboxPolicy represents a parsed and validated sandbox policy that defines
// filesystem, network, and process execution restrictions for package managers.
// Policy violations will block execution. Policy supports inheritance from parent policies.
type SandboxPolicy struct {
	// These fields are not affected by inheritance and are set from the child policy.
	Name            string   `yaml:"name" json:"name"`
	Description     string   `yaml:"description" json:"description"`
	Inherits        string   `yaml:"inherits,omitempty" json:"inherits,omitempty"`
	PackageManagers []string `yaml:"package_managers" json:"package_managers"`

	// Presets are expanded by the registry after inheritance resolution.
	// Names are kept post-expansion for provenance display.
	Presets []string `yaml:"presets,omitempty" json:"presets,omitempty"`

	// Lineage is the resolved inheritance chain from the base profile to
	// this one: built-in names and file paths. The registry sets it, so it
	// is not read from YAML.
	Lineage []string `yaml:"-" json:"lineage,omitempty"`

	// own is the policy as its file wrote it, before the merge with its
	// parents. The linter reads it, so a finding names an entry the user
	// can edit.
	own *SandboxPolicy

	// These fields are affected by inheritance and are merged with the parent policy.
	// Any new values added here should be handled in the MergeWithParent method.
	Filesystem  FilesystemPolicy  `yaml:"filesystem" json:"filesystem"`
	Network     NetworkPolicy     `yaml:"network" json:"network"`
	Process     ProcessPolicy     `yaml:"process" json:"process"`
	Environment EnvironmentPolicy `yaml:"environment" json:"environment"`

	// The boolean fields are pointers to allow for nil values so that the YAML parser
	// can set the values from the child policy if present. We can differentiate between
	// nil and false values. Any new values added here should be handled in the
	// MergeWithParent method. When present in the child policy, the parent value is ignored.
	// When not present in the child policy, the parent value is used.

	// AllowGitConfig allows write access to .git/config file.
	AllowGitConfig *bool `yaml:"allow_git_config" json:"allow_git_config"`

	// AllowPTY allows pseudo-terminal (PTY) operations.
	AllowPTY *bool `yaml:"allow_pty" json:"allow_pty"`

	// AllowUnixSockets opens unix sockets. It is false by default, because a
	// host socket, such as the SSH agent, reaches outside the sandbox.
	AllowUnixSockets *bool `yaml:"allow_unix_sockets" json:"allow_unix_sockets"`

	// AllowNetworkBind allows binding to localhost (127.0.0.1 / ::1) for listening.
	AllowNetworkBind *bool `yaml:"allow_network_bind" json:"allow_network_bind"`

	// NetworkViaProxyOnly confines all outbound network access to the PMG
	// proxy. Requires the proxy flow; drivers fail closed without a running
	// proxy.
	NetworkViaProxyOnly *bool `yaml:"network_via_proxy_only" json:"network_via_proxy_only"`

	// AllowDirectDNS re-opens direct DNS (mDNSResponder) under
	// NetworkViaProxyOnly. No effect otherwise. Default false: the proxy
	// resolves names and direct DNS is an exfiltration channel.
	AllowDirectDNS *bool `yaml:"allow_direct_dns" json:"allow_direct_dns"`
}

// FilesystemPolicy defines allowed and denied filesystem access patterns.
// Deny rules have higher priority than allow rules.
type FilesystemPolicy struct {
	AllowRead  []string `yaml:"allow_read" json:"allow_read"`
	AllowWrite []string `yaml:"allow_write" json:"allow_write"`
	DenyRead   []string `yaml:"deny_read" json:"deny_read"`
	DenyWrite  []string `yaml:"deny_write" json:"deny_write"`
}

// NetworkPolicy defines allowed and denied network access patterns.
// Outbound patterns are in the format "host:port" or "*:*" for wildcards.
type NetworkPolicy struct {
	AllowOutbound []string `yaml:"allow_outbound" json:"allow_outbound"`
	DenyOutbound  []string `yaml:"deny_outbound" json:"deny_outbound"`
	AllowBind     []string `yaml:"allow_bind" json:"allow_bind"`

	// AllowUnixConnect lists the exact paths of the unix sockets that a
	// process may connect to. Other unix sockets stay closed. No effect
	// when allow_unix_sockets opens every unix socket.
	AllowUnixConnect []string `yaml:"allow_unix_connect,omitempty" json:"allow_unix_connect,omitempty"`

	// AllowUnixConnectWithoutKernelCheck lets the Landlock driver below
	// Landlock ABI 9 check allow_unix_connect in the supervisor. A process
	// can race that check and reach any unix socket, so the profile must
	// accept the race. Default false. A child wins when it sets the key.
	AllowUnixConnectWithoutKernelCheck *bool `yaml:"allow_unix_connect_without_kernel_check,omitempty" json:"allow_unix_connect_without_kernel_check,omitempty"`

	// DenyIPLiterals denies an IP literal, an address and not a name,
	// unless an allow rule names that exact address. An allow list of
	// names does not stop a client that connects to an address, and a
	// wildcard never names one. Default false. A child wins when it sets
	// the key. Under global_lockdown a child may set true and not false.
	DenyIPLiterals *bool `yaml:"deny_ip_literals,omitempty" json:"deny_ip_literals,omitempty"`
}

// ProcessPolicy defines allowed and denied process execution patterns.
// Patterns can be specific paths or glob patterns.
type ProcessPolicy struct {
	AllowExec []string `yaml:"allow_exec" json:"allow_exec"`
	DenyExec  []string `yaml:"deny_exec" json:"deny_exec"`
}

// EnvironmentPolicy controls which environment variables are scrubbed from the
// child process. Deny extends the built-in util.DANGEROUS_ENV_VARS list; Allow
// suppresses matching denies (allow wins). Patterns are case-insensitive name
// globs. Enforcement happens in sandbox/util.ScrubEnv at process spawn.
type EnvironmentPolicy struct {
	Allow []string `yaml:"allow" json:"allow"`
	Deny  []string `yaml:"deny" json:"deny"`
}

// Validate validates the sandbox policy for correctness before inheritance resolution.
// Returns an error if the policy is invalid. The package managers and the
// rules can come from a parent, so ValidateResolved checks them after the
// merge.
func (p *SandboxPolicy) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("policy name is required")
	}

	for _, entry := range p.Network.AllowBind {
		if _, err := util.ParseBindAddress(entry); err != nil {
			return fmt.Errorf("network.allow_bind: %w", err)
		}
	}

	for _, entry := range p.Network.AllowUnixConnect {
		if err := validateUnixSocketPath(entry); err != nil {
			return fmt.Errorf("network.allow_unix_connect: %w", err)
		}
	}

	return nil
}

// UnixConnectPaths returns the expanded socket paths of
// network.allow_unix_connect for a driver to enforce. It returns nil when
// allow_unix_sockets opens every unix socket, so a driver checks the list
// only when the list decides.
func (p *SandboxPolicy) UnixConnectPaths() ([]string, error) {
	if utils.SafelyGetValue(p.AllowUnixSockets) {
		return nil, nil
	}

	var paths []string
	for _, entry := range p.Network.AllowUnixConnect {
		path, err := expandUnixSocketPath(entry, ResolveOptions{})
		if err != nil {
			return nil, err
		}
		paths = append(paths, path)
	}
	return paths, nil
}

// expandUnixSocketPath expands the variables of one entry. The kernel looks
// the path up, so a "." or ".." from a variable keeps its kernel meaning only
// if pmg does not clean it away. PMG refuses such a path instead.
func expandUnixSocketPath(entry string, opts ResolveOptions) (string, error) {
	raw, err := util.ExpandVariablesUncleaned(entry, opts.CWD, opts.Home, opts.TmpDir)
	if err != nil {
		return "", fmt.Errorf("network.allow_unix_connect: %w", err)
	}
	if err := ValidateUnixSocketTarget(raw); err != nil {
		return "", fmt.Errorf("network.allow_unix_connect: %q expands to an invalid path: %w", entry, err)
	}
	return filepath.Clean(raw), nil
}

// maxUnixConnectLinks matches the kernel limit on symlinks in one lookup.
const maxUnixConnectLinks = 40

// UnixSocketRoute is the way from one listed path to its socket.
type UnixSocketRoute struct {
	// Path is the listed path, expanded.
	Path string
	// Socket is the resolved socket path, or empty when a name on the way
	// does not exist.
	Socket string
	// Names are the names that a run must not create, remove or replace:
	// Path, the socket name through each symlink on the way, which makes
	// each link an ancestor of a denied name, and Socket or the first name
	// that does not exist.
	Names []string
}

// UnixSocketRoutes walks each path of UnixConnectPaths to its socket. A run
// that replaced a name on the way would choose the socket that a later run
// reaches, so a driver denies writes to each name.
func (p *SandboxPolicy) UnixSocketRoutes() ([]UnixSocketRoute, error) {
	paths, err := p.UnixConnectPaths()
	if err != nil {
		return nil, err
	}

	routes := make([]UnixSocketRoute, 0, len(paths))
	for _, path := range paths {
		route, err := walkUnixSocketPath(path)
		if err != nil {
			return nil, fmt.Errorf("network.allow_unix_connect: %s: %w", path, err)
		}
		for _, name := range route.Names {
			if err := ValidateUnixSocketTarget(name); err != nil {
				return nil, fmt.Errorf("network.allow_unix_connect: %s links to an invalid path: %w", path, err)
			}
		}
		routes = append(routes, route)
	}
	return routes, nil
}

// walkUnixSocketPath looks path up one name at a time, as the kernel does: a
// symlink target replaces the link, and ".." leaves the resolved directory.
// A name that pmg cannot look up ends the walk. The sandbox runs as the same
// user, so it cannot reach or replace that name either.
func walkUnixSocketPath(path string) (UnixSocketRoute, error) {
	route := UnixSocketRoute{Path: path, Names: []string{path}}
	resolved := "/"
	rest := strings.Split(path, "/")
	links := 0
	for len(rest) > 0 {
		name := rest[0]
		rest = rest[1:]
		switch name {
		case "", ".":
			continue
		case "..":
			resolved = filepath.Dir(resolved)
			continue
		}

		next := filepath.Join(resolved, name)
		info, err := os.Lstat(next)
		if err != nil {
			route.addName(next)
			return route, nil
		}
		if info.Mode()&fs.ModeSymlink == 0 {
			// The kernel fails a lookup through a file with ENOTDIR. The
			// name is denied, so a run cannot make it a directory or a link.
			if len(rest) > 0 && !info.IsDir() {
				route.addName(next)
				return route, nil
			}
			resolved = next
			continue
		}

		links++
		if links > maxUnixConnectLinks {
			return UnixSocketRoute{}, fmt.Errorf("follows more than %d links", maxUnixConnectLinks)
		}
		if slices.Contains(rest, "..") {
			return UnixSocketRoute{}, fmt.Errorf("%s is a symlink followed by \"..\", which no exact path can protect", next)
		}
		route.addName(filepath.Join(append([]string{next}, rest...)...))
		target, err := os.Readlink(next)
		if err != nil {
			return route, nil
		}
		if filepath.IsAbs(target) {
			resolved = "/"
		}
		rest = append(strings.Split(target, "/"), rest...)
	}
	route.Socket = resolved
	route.addName(resolved)
	return route, nil
}

func (r *UnixSocketRoute) addName(name string) {
	if !slices.Contains(r.Names, name) {
		r.Names = append(r.Names, name)
	}
}

// validateUnixSocketPath accepts an exact pathname socket, absolute or
// rooted in a variable. A glob cannot name one inode for the kernel to
// check. Seatbelt string literals carry no escapes, so a quote or a
// backslash could change the rule.
func validateUnixSocketPath(path string) error {
	if !strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "${") {
		return fmt.Errorf("%q: must be an absolute path or start with a variable", path)
	}
	return validateSocketPathChars(path)
}

// hasDotComponent reports a "." or ".." name, which filepath.Clean removes
// with a meaning that differs from the kernel lookup after a symlink.
func hasDotComponent(path string) bool {
	for name := range strings.SplitSeq(path, "/") {
		if name == "." || name == ".." {
			return true
		}
	}
	return false
}

// ValidateUnixSocketTarget checks a socket path that a driver resolved,
// such as the target of a symlink, before the driver writes it into a rule.
// The translators expand variables in each deny, so a "${" left in a
// resolved name would make the deny name another path than the socket.
func ValidateUnixSocketTarget(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%q: must be an absolute path", path)
	}
	if strings.Contains(path, "${") {
		return fmt.Errorf("%q: must not hold an unexpanded variable", path)
	}
	return validateSocketPathChars(path)
}

// validateSocketPathChars also checks an expanded path and a link target,
// because a variable or a link can carry any character. The write denies on
// these paths are glob patterns, so a glob character would stop the deny
// from matching the socket.
func validateSocketPathChars(path string) error {
	if util.ContainsGlob(path) {
		return fmt.Errorf("%q: must be an exact path, not a glob", path)
	}
	if hasDotComponent(path) {
		return fmt.Errorf("%q: must not hold a . or .. component", path)
	}
	if strings.ContainsFunc(path, func(r rune) bool { return r == '"' || r == '\\' || unicode.IsControl(r) }) {
		return fmt.Errorf("%q: must not contain a quote, a backslash or a control character", path)
	}
	return nil
}

// ValidateResolved validates a policy after inheritance has been resolved.
// This is called after MergeWithParent to ensure the final policy is valid.
func (p *SandboxPolicy) ValidateResolved() error {
	if err := p.Validate(); err != nil {
		return err
	}

	if len(p.PackageManagers) == 0 {
		return fmt.Errorf("policy must specify at least one package manager")
	}

	// Check that at least one access rule is defined (after inheritance)
	hasRules := len(p.Filesystem.AllowRead) > 0 ||
		len(p.Filesystem.AllowWrite) > 0 ||
		len(p.Filesystem.DenyRead) > 0 ||
		len(p.Filesystem.DenyWrite) > 0 ||
		len(p.Network.AllowOutbound) > 0 ||
		len(p.Network.DenyOutbound) > 0 ||
		utils.SafelyGetValue(p.Network.DenyIPLiterals) ||
		len(p.Process.AllowExec) > 0 ||
		len(p.Process.DenyExec) > 0 ||
		len(p.Environment.Allow) > 0 ||
		len(p.Environment.Deny) > 0

	if !hasRules {
		return fmt.Errorf("policy must define at least one access rule (after inheritance resolution)")
	}

	return nil
}

// Parent returns the profile this one inherited from, or "" for a base
// profile. After resolution Inherits is empty, so the chain is the record.
func (p *SandboxPolicy) Parent() string {
	if len(p.Lineage) < 2 {
		return ""
	}
	return p.Lineage[len(p.Lineage)-2]
}

// AppliesToPackageManager returns true if this policy applies to the given package manager.
func (p *SandboxPolicy) AppliesToPackageManager(pm string) bool {
	pmLower := strings.ToLower(pm)
	for _, supported := range p.PackageManagers {
		if strings.ToLower(supported) == pmLower {
			return true
		}
	}

	return false
}

// MergeWithParent merges the child policy with its parent policy.
// Lists are unioned (additive), booleans are overridden, and the parent's
// package_managers apply when the child sets none.
// This method modifies the receiver (child policy) in place.
func (child *SandboxPolicy) MergeWithParent(parent *SandboxPolicy) {
	if len(child.PackageManagers) == 0 {
		child.PackageManagers = append([]string(nil), parent.PackageManagers...)
	}

	// Union filesystem lists
	child.Filesystem.AllowRead = unionStringSlices(parent.Filesystem.AllowRead, child.Filesystem.AllowRead)
	child.Filesystem.AllowWrite = unionStringSlices(parent.Filesystem.AllowWrite, child.Filesystem.AllowWrite)
	child.Filesystem.DenyRead = unionStringSlices(parent.Filesystem.DenyRead, child.Filesystem.DenyRead)
	child.Filesystem.DenyWrite = unionStringSlices(parent.Filesystem.DenyWrite, child.Filesystem.DenyWrite)

	// Union network lists
	child.Network.AllowOutbound = unionStringSlices(parent.Network.AllowOutbound, child.Network.AllowOutbound)
	child.Network.DenyOutbound = unionStringSlices(parent.Network.DenyOutbound, child.Network.DenyOutbound)
	child.Network.AllowBind = unionStringSlices(parent.Network.AllowBind, child.Network.AllowBind)
	child.Network.AllowUnixConnect = unionStringSlices(parent.Network.AllowUnixConnect, child.Network.AllowUnixConnect)
	if child.Network.AllowUnixConnectWithoutKernelCheck == nil {
		child.Network.AllowUnixConnectWithoutKernelCheck = utils.PtrTo(utils.SafelyGetValue(parent.Network.AllowUnixConnectWithoutKernelCheck))
	}
	if child.Network.DenyIPLiterals == nil {
		child.Network.DenyIPLiterals = utils.PtrTo(utils.SafelyGetValue(parent.Network.DenyIPLiterals))
	}

	// Union process lists
	child.Process.AllowExec = unionStringSlices(parent.Process.AllowExec, child.Process.AllowExec)
	child.Process.DenyExec = unionStringSlices(parent.Process.DenyExec, child.Process.DenyExec)

	// Union environment lists
	child.Environment.Allow = unionStringSlices(parent.Environment.Allow, child.Environment.Allow)
	child.Environment.Deny = unionStringSlices(parent.Environment.Deny, child.Environment.Deny)

	// Union preset references
	child.Presets = unionStringSlices(parent.Presets, child.Presets)

	// Set boolean fields by duplicating the parent value if not present in the child.
	if child.AllowPTY == nil {
		child.AllowPTY = utils.PtrTo(utils.SafelyGetValue(parent.AllowPTY))
	}

	if child.AllowGitConfig == nil {
		child.AllowGitConfig = utils.PtrTo(utils.SafelyGetValue(parent.AllowGitConfig))
	}

	if child.AllowUnixSockets == nil {
		child.AllowUnixSockets = utils.PtrTo(utils.SafelyGetValue(parent.AllowUnixSockets))
	}

	if child.AllowNetworkBind == nil {
		child.AllowNetworkBind = utils.PtrTo(utils.SafelyGetValue(parent.AllowNetworkBind))
	}

	if child.NetworkViaProxyOnly == nil {
		child.NetworkViaProxyOnly = utils.PtrTo(utils.SafelyGetValue(parent.NetworkViaProxyOnly))
	}

	if child.AllowDirectDNS == nil {
		child.AllowDirectDNS = utils.PtrTo(utils.SafelyGetValue(parent.AllowDirectDNS))
	}
}

// ownRules returns the policy as its file wrote it, or the policy itself
// when it inherits nothing.
func (p *SandboxPolicy) ownRules() *SandboxPolicy {
	if p.own != nil {
		return p.own
	}
	return p
}

// unionStringSlices returns a new slice containing all unique elements from both slices.
// Order is preserved: parent entries first, then child entries (excluding duplicates).
func unionStringSlices(parent, child []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(parent)+len(child))

	// Add all parent entries
	for _, item := range parent {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	// Add child entries that aren't duplicates
	for _, item := range child {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}
