package sandbox

import (
	"context"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strconv"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/dry/utils"
	"github.com/safedep/pmg/errcodes"
)

// ExecutionContext carries runtime data known only at spawn time.
type ExecutionContext struct {
	// ProxyAddr is the loopback TCP address of the running PMG proxy
	// (e.g. "127.0.0.1:54321"). Empty when no proxy flow is active.
	ProxyAddr string
}

// ValidateNetworkLockdown enforces the network_via_proxy_only fail-closed contract
// for drivers that support it. Returns the validated proxy port, or "" when
// lockdown is off.
func ValidateNetworkLockdown(policy *SandboxPolicy, rt *ExecutionContext) (string, error) {
	if !utils.SafelyGetValue(policy.NetworkViaProxyOnly) {
		return "", nil
	}

	if rt == nil || rt.ProxyAddr == "" {
		return "", usefulerror.NewUsefulError().
			WithCode(errcodes.SandboxRequiresProxy).
			WithHumanError("network_via_proxy_only requires the PMG proxy flow").
			WithHelp("This sandbox profile confines all network access to the PMG proxy, but no proxy is running.").
			Wrap(fmt.Errorf("policy %s requires the PMG proxy flow: network_via_proxy_only is set but no proxy address was provided", policy.Name))
	}

	host, port, err := net.SplitHostPort(rt.ProxyAddr)
	if err != nil {
		return "", fmt.Errorf("network_via_proxy_only: proxy address %q is not host:port and not loopback: %w", rt.ProxyAddr, err)
	}

	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", fmt.Errorf("network_via_proxy_only: refusing non-loopback proxy address %q", rt.ProxyAddr)
	}

	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		return "", fmt.Errorf("network_via_proxy_only: refusing non-numeric or out-of-range proxy port in %q", rt.ProxyAddr)
	}

	return port, nil
}

// DriverName identifies a sandbox driver implementation. Returned by
// Sandbox.Name() and used wherever code needs to refer to a specific driver.
type DriverName string

const (
	DriverSeatbelt   DriverName = "seatbelt"
	DriverBubblewrap DriverName = "bubblewrap"
	DriverLandlock   DriverName = "landlock"
)

// ViolationKind is PMG's normalized taxonomy for sandbox denials.
type ViolationKind string

const (
	ViolationKindFSRead           ViolationKind = "fs_read"
	ViolationKindFSWrite          ViolationKind = "fs_write"
	ViolationKindFSDeleteOrRename ViolationKind = "fs_delete_or_rename"
	ViolationKindExec             ViolationKind = "exec"
	ViolationKindNetworkConnect   ViolationKind = "network_connect"
	ViolationKindNetworkBind      ViolationKind = "network_bind"
	ViolationKindGenericDeny      ViolationKind = "generic_deny"
	ViolationKindEnvScrub         ViolationKind = "env_scrub"
)

// ViolationReport is a best-effort sandbox violation summary collected from a
// sandbox implementation after command execution fails.
type ViolationReport struct {
	SandboxName   DriverName
	PolicyName    string
	CorrelationID string
	Violations    []Violation

	// OutputDerived marks a report parsed from the sandboxed command's own
	// output rather than read from a kernel or platform channel. A malicious
	// package can print a denial that never happened, naming any target it
	// likes, so these violations are shown as diagnostics but never converted
	// into an override suggestion the user could be talked into persisting.
	OutputDerived bool
}

// Violation captures one sandbox denial event.
type Violation struct {
	Kind       ViolationKind
	RawKind    string
	Target     string
	RuleTarget string
	Process    string
	RawLog     string
	RuleLabel  string
}

type violationReporter interface {
	BestEffortViolation(err error) (*ViolationReport, error)
}

// diagnosticsWriter is implemented by drivers that collect diagnostics from the
// command's own output rather than from a kernel or platform channel.
type diagnosticsWriter interface {
	DiagnosticsWriter() io.Writer
}

// EnvScrub records the environment variables removed from a child process by
// the resolved environment policy. The driver and policy are captured here
// because no driver observes a scrub.
type EnvScrub struct {
	Names       []string
	SandboxName DriverName
	PolicyName  string
	Process     string
}

// ExecutionResult represents the result of executing a command in a sandbox.
// It contains sandbox internal state and allows for future extension with
// additional metadata (e.g., exit codes, resource usage, violation events).
// Callers must call Close() after cmd.Run() completes to clean up resources.
type ExecutionResult struct {
	executed bool
	sandbox  Sandbox
	envScrub EnvScrub
}

// ExecutionResultOpt is a function that can be used to configure an ExecutionResult.
type ExecutionResultOpt func(*ExecutionResult)

// WithSandbox sets the sandbox for the ExecutionResult.
func WithExecutionResultSandbox(sb Sandbox) ExecutionResultOpt {
	return func(r *ExecutionResult) {
		r.sandbox = sb
	}
}

// WithExecuted sets the executed flag for the ExecutionResult.
func WithExecutionResultExecuted(executed bool) ExecutionResultOpt {
	return func(r *ExecutionResult) {
		r.executed = executed
	}
}

// NewExecutionResult creates a new ExecutionResult.
func NewExecutionResult(opts ...ExecutionResultOpt) *ExecutionResult {
	r := &ExecutionResult{}
	for _, opt := range opts {
		opt(r)
	}

	return r
}

// ShouldRun returns true if the caller should execute cmd.Run().
func (r *ExecutionResult) ShouldRun() bool {
	return !r.executed
}

// SetEnvScrub records the environment variables scrubbed from the child process.
func (r *ExecutionResult) SetEnvScrub(scrub EnvScrub) {
	r.envScrub = scrub
}

// EnvScrub returns the environment scrub recorded for this run.
func (r *ExecutionResult) EnvScrub() EnvScrub {
	if r == nil {
		return EnvScrub{}
	}

	return r.envScrub
}

// ScrubbedEnvCount returns how many environment variables were scrubbed from
// the child process. Used to hint at scrubbing as a possible cause when the
// child fails.
func (r *ExecutionResult) ScrubbedEnvCount() int {
	if r == nil {
		return 0
	}

	return len(r.envScrub.Names)
}

// BestEffortViolation returns sandbox-specific best-effort violation details.
// Implementations may use platform logs or other weak signals, so callers
// should treat the result as advisory.
func (r *ExecutionResult) BestEffortViolation(err error) (*ViolationReport, error) {
	if r == nil || r.sandbox == nil {
		return nil, nil
	}

	reporter, ok := r.sandbox.(violationReporter)
	if !ok {
		return nil, nil
	}

	return reporter.BestEffortViolation(err)
}

// DiagnosticsWriter returns a writer that execution paths routing command
// output themselves, such as a PTY session, must tee into for the sandbox to
// observe denials. Drivers that read a kernel or platform channel return nil.
func (r *ExecutionResult) DiagnosticsWriter() io.Writer {
	if r == nil || r.sandbox == nil {
		return nil
	}

	writer, ok := r.sandbox.(diagnosticsWriter)
	if !ok {
		return nil
	}

	return writer.DiagnosticsWriter()
}

// Close cleans up any resources allocated by the sandbox.
// Must be called after cmd.Run() completes.
func (r *ExecutionResult) Close() error {
	if r.sandbox != nil {
		return r.sandbox.Close()
	}

	return nil
}

// Sandbox represents a platform-specific sandbox executor that isolates
// package manager processes with controlled access to filesystem, network,
// and process execution resources.
type Sandbox interface {
	// Execute prepares or runs a command in the sandbox with the given policy.
	//
	// Behavior varies by implementation:
	// - CLI-based sandboxes (Seatbelt, Bubblewrap): Modify cmd in place by wrapping it
	//   with sandbox CLI (e.g., sandbox-exec). Returns ExecutionResult with executed=false.
	// - Library-based sandboxes: Execute the command directly within the sandbox.
	//   Returns ExecutionResult with executed=true.
	//
	// Returns:
	//   - ExecutionResult: Contains execution state and metadata
	//   - error: Non-nil if sandbox setup or execution failed
	//
	// rt carries runtime data known only at spawn time; drivers treat a nil
	// rt as &ExecutionContext{}.
	//
	// Callers must check result.ShouldRun() and only call cmd.Run() if true.
	Execute(ctx context.Context, cmd *exec.Cmd, policy *SandboxPolicy, rt *ExecutionContext) (*ExecutionResult, error)

	// Name returns the sandbox driver identifier.
	Name() DriverName

	// IsAvailable returns true if the sandbox is available and functional on this platform.
	IsAvailable() bool

	// Close cleans up any resources allocated by the sandbox (e.g., temporary files).
	// Must be called after cmd.Run() completes. Idempotent - safe to call multiple times.
	Close() error
}

// ProfileInfo describes a user profile discovered on disk.
type ProfileInfo struct {
	// Name is the profile name, derived from the file name without extension.
	Name string

	// Path is the absolute path to the profile file.
	Path string

	// Shadowed is true when a built-in profile of the same name exists and
	// will win during name-based resolution.
	Shadowed bool
}

// ProfileSource identifies where a profile came from.
type ProfileSource string

const (
	ProfileSourceBuiltin ProfileSource = "builtin"
	ProfileSourceUser    ProfileSource = "user"
)

// ProfileSummary describes a discoverable profile for listing purposes.
type ProfileSummary struct {
	Name            string
	Source          ProfileSource
	Path            string // "" for builtins; absolute path for user profiles
	Inherits        string
	PackageManagers []string
	Description     string
	Shadowed        bool // true when a user file is masked by a same-named builtin
}

// ResolveOptions tunes variable expansion when resolving a policy for display
// or diffing. Zero values mean "use the current process environment".
type ResolveOptions struct {
	CWD    string
	Home   string
	TmpDir string
}

// ProfileRegistry manages built-in and custom sandbox policies.
type ProfileRegistry interface {
	// GetProfile retrieves a policy by name.
	// Name can be a built-in profile (e.g., "npm-restrictive"), the bare name of a
	// user profile under UserProfileDir(), or a path to a custom YAML file.
	// Resolution order: built-ins first, then the user profile directory.
	GetProfile(name string) (*SandboxPolicy, error)

	// LoadCustomProfile loads a policy from a custom YAML file path.
	LoadCustomProfile(path string) (*SandboxPolicy, error)

	// ListProfiles returns all discoverable profiles: built-ins first, then
	// user profiles (including shadowed entries).
	ListProfiles() ([]ProfileSummary, error)

	// ResolveProfile loads name and returns a policy with all path-bearing
	// fields expanded against opts (or the process environment).
	ResolveProfile(name string, opts ResolveOptions) (*SandboxPolicy, error)

	// UserProfileDir returns the directory scanned for user profiles.
	UserProfileDir() string

	// ListUserProfiles enumerates *.yml / *.yaml files under UserProfileDir().
	// A missing directory returns an empty slice with no error.
	ListUserProfiles() ([]ProfileInfo, error)

	// BuiltinProfileYAML returns the embedded YAML bytes for a built-in
	// profile. Returns false if name is not a built-in.
	BuiltinProfileYAML(name string) ([]byte, bool)
}

// RegistryOption configures a ProfileRegistry.
type RegistryOption func(*registryOptions)

type registryOptions struct {
	userProfileDir string
	presetRegistry PresetRegistry
}

// WithUserProfileDir sets the directory the registry uses to discover user
// profiles. The directory does not need to exist at construction time.
func WithUserProfileDir(dir string) RegistryOption {
	return func(o *registryOptions) {
		o.userProfileDir = dir
	}
}

// WithPresetRegistry sets the preset registry used to expand `presets:`
// references in profiles. Defaults to a builtin-only preset registry.
func WithPresetRegistry(presets PresetRegistry) RegistryOption {
	return func(o *registryOptions) {
		o.presetRegistry = presets
	}
}

// NewProfileRegistry creates a new profile registry with built-in policies.
func NewProfileRegistry(opts ...RegistryOption) (ProfileRegistry, error) {
	return newDefaultProfileRegistry(opts...)
}
