package executor

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/safedep/dry/log"
	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/dry/utils"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/audit"
	"github.com/safedep/pmg/internal/netflags"
	"github.com/safedep/pmg/proxy/netpolicy"
	"github.com/safedep/pmg/sandbox"
	"github.com/safedep/pmg/sandbox/platform"
	"github.com/safedep/pmg/sandbox/util"
)

type applySandboxConfig struct {
	sb           sandbox.Sandbox
	rt           *sandbox.ExecutionContext
	processLabel string
}

// Resolution is the sandbox policy resolved for one run. A nil Policy means
// the run has no sandbox. The proxy reads the policy before the child
// starts, so a run resolves it once and hands the same value to both.
type Resolution struct {
	PackageManager string
	Policy         *sandbox.SandboxPolicy

	// NetworkMode is the posture of the proxy for the policy's network
	// rules, audit or enforce, from sandbox.network_mode.
	NetworkMode string

	// Network is the parsed network block of the policy, with the overlay
	// and the overrides applied. nil when the run has no sandbox.
	Network *netpolicy.Policy
}

// ApplySandboxOpt configures ApplySandbox.
type ApplySandboxOpt func(*applySandboxConfig)

// WithSandbox sets the sandbox to use for the command.
// When not set, the sandbox will be determined by the platform.
func WithSandbox(sb sandbox.Sandbox) ApplySandboxOpt {
	return func(c *applySandboxConfig) {
		c.sb = sb
	}
}

// WithExecutionContext provides runtime data known only at spawn time
// (e.g. the PMG proxy address) to the sandbox driver.
func WithExecutionContext(rt *sandbox.ExecutionContext) ApplySandboxOpt {
	return func(c *applySandboxConfig) {
		c.rt = rt
	}
}

// WithProcessLabel names the child in the env scrub record. It defaults to
// the policy lookup name, which is the program name for package managers but
// the exec workload for `pmg sandbox exec`.
func WithProcessLabel(label string) ApplySandboxOpt {
	return func(c *applySandboxConfig) {
		c.processLabel = label
	}
}

// ResolvePolicy loads the sandbox policy for pmName and applies the project
// overlay and the runtime overrides. It writes the override audit events and
// the overlay warning, so call it once per run.
//
// requireSandbox makes a disabled policy an error instead of a run without a
// sandbox. `pmg sandbox exec` sets it, because the user asked for the sandbox
// by name.
//
// This is a security sensitive operation. If sandbox is enabled via. config but not available on the platform,
// it will return an error to avoid running the command without sandbox protection.
func ResolvePolicy(pmName string, requireSandbox bool) (*Resolution, error) {
	// A config that failed closed holds defaults, with no policies and no
	// mode, so a run must not resolve a policy from it.
	if err := config.LoadError(); err != nil {
		return nil, err
	}

	cfg := config.Get()

	if !cfg.Config.Sandbox.Enabled {
		return &Resolution{PackageManager: pmName}, nil
	}

	if !platform.Supported() {
		return nil, usefulerror.NewUsefulError().
			WithCode(errcodes.InvalidArgument).
			WithHumanError(fmt.Sprintf("The sandbox is not supported on %s/%s", runtime.GOOS, runtime.GOARCH)).
			WithHelp("Set sandbox.enabled: false in the PMG config, or remove --sandbox from the command.").
			WithAdditionalHelp("See https://github.com/safedep/pmg/blob/main/docs/sandbox.md for the supported platforms.").
			Wrap(fmt.Errorf("sandbox not supported on %s/%s", runtime.GOOS, runtime.GOARCH))
	}

	build := newProfileRegistries
	if cfg.IsLocked() {
		build = newManagedProfileRegistries
	}
	registries, err := build(cfg)
	if err != nil {
		return nil, err
	}
	presetRegistry := registries.presets

	var policy *sandbox.SandboxPolicy

	if cfg.SandboxProfileOverride != "" {
		log.Debugf("Using sandbox profile override: %s", cfg.SandboxProfileOverride)

		policy, err = registries.loadOverride(cfg.SandboxProfileOverride)
		if err != nil {
			return nil, registries.loadError("Failed to load sandbox profile override", cfg.SandboxProfileOverride, err)
		}
	} else {
		log.Debugf("Looking up sandbox policy for %s", pmName)

		// When a policy is not configured for a package manager, we error out
		// This is to avoid running the command without sandbox protection.
		// To bypass sandbox for a specific package manager, users should explicitly
		// disable for the package manager in the config.
		policyRef, exists := cfg.Config.Sandbox.PolicyFor(pmName)
		if !exists {
			return nil, usefulerror.NewUsefulError().
				WithCode(errcodes.NotFound).
				WithHumanError(fmt.Sprintf("No sandbox policy configured for %s", pmName)).
				WithHelp("Please configure a sandbox policy for this package manager in the config file.").
				WithAdditionalHelp("See https://github.com/safedep/pmg/blob/main/docs/sandbox.md for more information.").
				Wrap(fmt.Errorf("no sandbox policy configured for %s", pmName))
		}

		// The policy is explicitly disabled for this package manager, so we skip sandbox
		if !policyRef.Enabled {
			if requireSandbox {
				msg := fmt.Sprintf("the %s sandbox policy is disabled in the PMG config", pmName)
				return nil, usefulerror.NewUsefulError().
					WithCode(errcodes.SandboxPolicyDisabled).
					WithHumanError(msg).
					WithHelp(fmt.Sprintf("This command never runs without a sandbox. Set sandbox.policies.%s.enabled to true.", pmName)).
					Wrap(errors.New(msg))
			}

			log.Warnf("sandbox policy %s is explicitly disabled for %s, skipping sandbox", policyRef.Profile, pmName)
			return &Resolution{PackageManager: pmName}, nil
		}

		log.Debugf("Loading sandbox policy %s", policyRef.Profile)

		policy, err = registries.load(policyRef.Profile)
		if err != nil {
			return nil, registries.loadError("Failed to load sandbox policy", policyRef.Profile, err)
		}
	}

	log.Debugf("Loaded sandbox policy %s", policy.Name)

	// The flag denies join the profile before the overlay and the presets,
	// so the preset filter drops a preset rule a flag deny covers, as it
	// does for an authored deny.
	if err := netflags.ApplyRules(&policy.Network, nil, cfg.SandboxNetworkDeny); err != nil {
		return nil, err
	}

	// Apply the per-repo project overlay (saved via `pmg sandbox allow`). When
	// global_lockdown is set, overlays are ignored so the locked baseline is
	// authoritative. An empty cwd is tolerated by ResolveRepoRoot's callers
	// downstream, so swallow a Getwd error here.
	cwd, _ := os.Getwd()
	if repoRoot, repoErr := sandbox.ResolveRepoRoot(cwd); repoErr != nil {
		log.Warnf("Project overlay: resolve repo root: %v", repoErr)
	} else if _, err := applyProjectOverlay(policy, cfg.SandboxOverlayDir(), repoRoot, cfg.IsLocked(), presetRegistry); err != nil {
		log.Warnf("Project overlay: apply: %v", err)
		// A failed overlay load means the user's saved allowances were silently
		// dropped. Echo to stderr so users at normal verbosity see why their
		// sandbox is more restrictive than expected.
		if _, werr := fmt.Fprintf(os.Stderr, "pmg: warning: project overlay could not be applied: %v\n", err); werr != nil {
			log.Warnf("failed to write overlay warning to stderr: %v", werr)
		}
	}

	// Apply runtime --sandbox-allow overrides to the policy before execution
	if len(cfg.SandboxAllowOverrides) > 0 {
		applyRuntimeOverrides(policy, cfg.SandboxAllowOverrides, presetRegistry)
		logSandboxOverrides(policy.Name, cfg.SandboxAllowOverrides)
	}

	if sandbox.ApplyWorktreeGitDirs(policy, cwd) {
		log.Debugf("Sandbox: applied linked worktree git directories for %s", cwd)
	}

	if !policy.AppliesToPackageManager(pmName) {
		return nil, fmt.Errorf("sandbox policy %s does not apply to %s", policy.Name, pmName)
	}

	// A saved allow and a net-connect override remove an equal deny. The
	// flag rules join again last, so a flag deny survives them and a flag
	// allow removes an equal profile deny. The matcher then treats a flag
	// rule like a profile rule, so the more specific rule wins.
	if err := netflags.ApplyRules(&policy.Network, cfg.SandboxNetworkAllow, cfg.SandboxNetworkDeny); err != nil {
		return nil, err
	}

	network, err := policy.Network.Compile()
	if err != nil {
		return nil, usefulerror.NewUsefulError().
			WithCode(errcodes.SandboxPolicyInvalid).
			WithHumanError(fmt.Sprintf("Sandbox policy %s has an invalid network rule: %v", policy.Name, err)).
			WithHelp("Write each rule as host:port, for example registry.npmjs.org:443. `pmg sandbox profile lint` lists every invalid rule.").
			Wrap(err)
	}
	warnIneffectiveNetConnectOverrides(policy.Name, network, cfg.SandboxAllowOverrides)

	return &Resolution{
		PackageManager: pmName,
		Policy:         policy,
		NetworkMode:    cmp.Or(cfg.Config.Sandbox.NetworkMode, config.SandboxNetworkModeAudit),
		Network:        network,
	}, nil
}

// profileRegistries holds the registries of one config, so every loader
// resolves a profile reference the same way. A managed set holds the
// built-ins, the templates of the managed config and the files next to it.
type profileRegistries struct {
	presets   sandbox.PresetRegistry
	profiles  sandbox.ProfileRegistry
	templates map[string]string
	configDir string
	managed   bool
}

func newProfileRegistries(cfg *config.RuntimeConfig) (*profileRegistries, error) {
	return buildProfileRegistries(cfg, false,
		[]sandbox.PresetRegistryOption{sandbox.WithUserPresetDir(cfg.SandboxPresetDir())},
		[]sandbox.RegistryOption{sandbox.WithUserProfileDir(cfg.SandboxProfileDir())},
	)
}

// newManagedProfileRegistries leaves out the user preset and profile
// directories. The user writes them, so a profile from them must not enter
// the chain of a locked config.
func newManagedProfileRegistries(cfg *config.RuntimeConfig) (*profileRegistries, error) {
	return buildProfileRegistries(cfg, true, nil, nil)
}

func buildProfileRegistries(cfg *config.RuntimeConfig, managed bool, presetOptions []sandbox.PresetRegistryOption, profileOptions []sandbox.RegistryOption) (*profileRegistries, error) {
	presets, err := sandbox.NewPresetRegistry(presetOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create preset registry: %w", err)
	}

	templates := cfg.SandboxPolicyTemplatePaths()
	profileOptions = append(profileOptions,
		sandbox.WithPresetRegistry(presets),
		sandbox.WithPolicyTemplates(templates),
	)
	profiles, err := sandbox.NewProfileRegistry(profileOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create profile registry: %w", err)
	}

	return &profileRegistries{
		presets:   presets,
		profiles:  profiles,
		templates: templates,
		configDir: filepath.Dir(cfg.ConfigFilePath()),
		managed:   managed,
	}, nil
}

// load resolves a reference from the config: a template name first, so a
// template that overrides a built-in profile wins over the built-in. The
// registry gets the same map, so a profile can inherit a template by name.
// A relative path resolves next to the config file before the working
// directory, so a repository cannot replace the user's file with one of
// the same path.
func (r *profileRegistries) load(ref string) (*sandbox.SandboxPolicy, error) {
	if templatePath, exists := r.templates[ref]; exists {
		ref = templatePath
	}
	if r.managed {
		return r.loadManaged(ref)
	}
	if IsProfilePath(ref) && !filepath.IsAbs(ref) {
		if next := filepath.Join(r.configDir, ref); fileExists(next) {
			ref = next
		}
	}
	return r.profiles.GetProfile(ref)
}

// loadManaged resolves a reference a locked config may hold: a built-in
// name, an absolute path, or a path relative to the managed config file.
// A relative path never falls back to the working directory. A bare name
// must be a built-in, because the registry looks in the working directory
// for any other name.
func (r *profileRegistries) loadManaged(ref string) (*sandbox.SandboxPolicy, error) {
	switch {
	case filepath.IsAbs(ref):
	case IsProfilePath(ref):
		ref = filepath.Join(r.configDir, ref)
	default:
		if _, builtin := r.profiles.BuiltinProfileYAML(ref); !builtin {
			return nil, fmt.Errorf("%w: %s is not a built-in profile, a policy template or a path", sandbox.ErrProfileNotFound, ref)
		}
	}
	return r.profiles.GetProfile(ref)
}

// loadOverride resolves a reference from the command line, where a
// relative path is in the working directory. A locked config refuses the
// flag before this runs. The managed set refuses here too, so a command
// without that check cannot load a file from the working directory.
func (r *profileRegistries) loadOverride(ref string) (*sandbox.SandboxPolicy, error) {
	if r.managed {
		return nil, fmt.Errorf("%w: a locked config takes no profile override", sandbox.ErrProfileNotFound)
	}
	return r.profiles.GetProfile(ref)
}

// IsProfilePath reports whether ref names a file and not a profile: it has
// a directory part or a YAML extension. A bare name is a built-in, a
// template or a user profile, whatever file the working directory holds.
func IsProfilePath(ref string) bool {
	ext := strings.ToLower(filepath.Ext(ref))
	return strings.ContainsAny(ref, `/\`) || ext == ".yml" || ext == ".yaml"
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// LoadProfile resolves ref as `pmg <pm>` resolves sandbox.policies.<pm>.profile:
// a template name, a built-in name, a user profile name, or a path.
func LoadProfile(cfg *config.RuntimeConfig, ref string) (*sandbox.SandboxPolicy, error) {
	registries, err := newProfileRegistries(cfg)
	if err != nil {
		return nil, err
	}

	policy, err := registries.load(ref)
	if err != nil {
		return nil, registries.loadError("Failed to load sandbox profile", ref, err)
	}
	return policy, nil
}

// LoadManagedProfile resolves ref as a locked config may name it: a
// built-in name, a template of the managed config, an absolute path, or a
// path relative to the managed config file. The chain resolves the same
// way. A user profile and a user preset are writable by the user, so the
// registry has none.
func LoadManagedProfile(cfg *config.RuntimeConfig, ref string) (*sandbox.SandboxPolicy, error) {
	registries, err := newManagedProfileRegistries(cfg)
	if err != nil {
		return nil, err
	}

	policy, err := registries.load(ref)
	if err != nil {
		return nil, registries.loadError("Failed to load the managed sandbox profile", ref, err)
	}
	return policy, nil
}

// loadError carries the cause to the user. A profile that exists but does
// not load points at the linter, which lists every issue. A managed set
// names what a locked config may hold.
func (r *profileRegistries) loadError(what, ref string, err error) error {
	if r.managed && errors.Is(err, sandbox.ErrProfileNotFound) {
		return usefulerror.NewUsefulError().
			WithCode(errcodes.NotFound).
			WithHumanError(fmt.Sprintf("%s: %v", what, err)).
			WithHelp("A globally managed configuration names a built-in profile, one of its policy templates, an absolute path, or a path relative to the managed config file.").
			Wrap(err)
	}
	return profileLoadError(what, ref, err)
}

func profileLoadError(what, ref string, err error) error {
	code := errcodes.InvalidArgument
	help := fmt.Sprintf("Run `pmg sandbox profile lint %s` to see every issue.", ref)
	if errors.Is(err, sandbox.ErrProfileNotFound) {
		code = errcodes.NotFound
		help = "Pass a built-in profile name, a user profile name, or the path of a profile file. `pmg sandbox profile list` shows the names."
	}
	return usefulerror.NewUsefulError().
		WithCode(code).
		WithHumanError(fmt.Sprintf("%s: %v", what, err)).
		WithHelp(help).
		WithAdditionalHelp("See more at: https://github.com/safedep/pmg/blob/main/docs/sandbox.md").
		Wrap(err)
}

// warnIneffectiveNetConnectOverrides names each net-connect override a
// wildcard deny still covers. The override removes an exact deny only.
func warnIneffectiveNetConnectOverrides(policyName string, network *netpolicy.Policy, overrides []config.SandboxAllowOverride) {
	for _, o := range overrides {
		if o.Type != config.SandboxAllowNetConnect {
			continue
		}
		rule, err := netpolicy.ParseRule(o.Value)
		if err != nil || network.Decide(rule.Host, rule.Port).Allowed {
			continue
		}
		log.Warnf("Sandbox override: net-connect=%s has no effect, a deny_outbound rule still covers it", o.Value)
		if _, werr := fmt.Fprintf(os.Stderr, "pmg: warning: --sandbox-allow net-connect=%s has no effect. A deny_outbound rule in policy %s still covers it.\n", o.Value, policyName); werr != nil {
			log.Warnf("failed to write override warning to stderr: %v", werr)
		}
	}
}

// ApplySandbox applies a resolved sandbox policy to cmd. A resolution with no
// policy leaves cmd unchanged.
//
// This is a security sensitive operation. It fails when the sandbox driver is
// not available, so the command never runs without the policy it resolved.
func ApplySandbox(ctx context.Context, cmd *exec.Cmd, res *Resolution, opts ...ApplySandboxOpt) (*sandbox.ExecutionResult, error) {
	if res == nil || res.Policy == nil {
		return sandbox.NewExecutionResult(), nil
	}

	applyConfig := &applySandboxConfig{}
	for _, opt := range opts {
		opt(applyConfig)
	}

	policy := res.Policy
	pmName := res.PackageManager

	var (
		sb  sandbox.Sandbox
		err error
	)
	if applyConfig.sb != nil {
		sb = applyConfig.sb
	} else {
		sb, err = platform.NewSandbox()
		if err != nil {
			return nil, fmt.Errorf("sandbox not available on this platform: %v", err)
		}
	}

	if !sb.IsAvailable() {
		return nil, usefulerror.NewUsefulError().
			WithCode(errcodes.InvalidArgument).
			WithHumanError(fmt.Sprintf("Sandbox %s is required but not available", sb.Name())).
			WithHelp("Please install the sandbox provider and try again.").
			WithAdditionalHelp("See more at: https://github.com/safedep/pmg/blob/main/docs/sandbox.md").
			Wrap(fmt.Errorf("sandbox %s is required but not available", sb.Name()))
	}

	log.Debugf("Running %s in %s sandbox with policy %s", pmName, sb.Name(), policy.Name)

	// Scrub sensitive environment variables before the child is spawned. This
	// runs after overlay and runtime overrides are merged into the policy so
	// user allowances are honored, and is platform-independent (it filters the
	// env slice regardless of the OS sandbox driver).
	scrubbedNames := scrubEnv(cmd, policy)

	if _, err := sandbox.ValidateNetworkLockdown(policy, applyConfig.rt); err != nil {
		return nil, err
	}

	result, err := sb.Execute(ctx, cmd, policy, applyConfig.rt)
	if err != nil {
		return nil, fmt.Errorf("failed to setup sandbox: %w", err)
	}

	result.SetEnvScrub(sandbox.EnvScrub{
		Names:       scrubbedNames,
		SandboxName: sb.Name(),
		PolicyName:  policy.Name,
		Process:     cmp.Or(applyConfig.processLabel, pmName),
	})

	return result, nil
}

// applyRuntimeOverrides applies --sandbox-allow overrides to the policy.
// Overrides append to allow lists and remove exact matches from corresponding deny lists
// so that deny rules don't shadow the explicit override. Only full-path exact matches are
// removed — glob and wildcard deny patterns are never modified to stay secure by default.
func applyRuntimeOverrides(policy *sandbox.SandboxPolicy, overrides []config.SandboxAllowOverride, presets sandbox.PresetRegistry) {
	for _, override := range overrides {
		switch override.Type {
		case config.SandboxAllowPreset:
			// A missing preset means fewer allowances (fail closed), so warn
			// instead of aborting the run.
			if presets == nil {
				log.Warnf("Sandbox override: preset %s ignored, no preset registry available", override.Value)
				continue
			}

			info, err := presets.Get(override.Value)
			if err != nil {
				log.Warnf("Sandbox override: preset %s could not be resolved: %v", override.Value, err)
				if _, werr := fmt.Fprintf(os.Stderr, "pmg: warning: sandbox preset %q could not be applied: %v\n", override.Value, err); werr != nil {
					log.Warnf("failed to write preset warning to stderr: %v", werr)
				}
				continue
			}

			log.Infof("Sandbox override: applying preset %s (%s)", override.Value, info.Source)
			info.Preset.ApplyToPolicy(policy)
		case config.SandboxAllowRead:
			log.Infof("Sandbox override: allowing read access to %s", override.Value)
			policy.Filesystem.AllowRead = append(policy.Filesystem.AllowRead, override.Value)
			policy.Filesystem.DenyRead = removeExactMatch(policy.Filesystem.DenyRead, override.Value)

		case config.SandboxAllowWrite:
			log.Infof("Sandbox override: allowing write access to %s", override.Value)
			policy.Filesystem.AllowWrite = append(policy.Filesystem.AllowWrite, override.Value)
			policy.Filesystem.DenyWrite = removeExactMatch(policy.Filesystem.DenyWrite, override.Value)

		case config.SandboxAllowExec:
			log.Infof("Sandbox override: allowing execution of %s", override.Value)
			policy.Process.AllowExec = append(policy.Process.AllowExec, override.Value)
			policy.Process.DenyExec = removeExactMatch(policy.Process.DenyExec, override.Value)

		case config.SandboxAllowNetConnect:
			log.Infof("Sandbox override: allowing outbound connection to %s", override.Value)
			policy.Network.Allow(override.Value)

		case config.SandboxAllowNetBind:
			log.Infof("Sandbox override: allowing network bind on %s", override.Value)
			policy.Network.AllowBind = append(policy.Network.AllowBind, override.Value)

			// Enable AllowNetworkBind so the translator emits bind rules.
			// Without this, AllowBind entries would be ignored on some platforms.
			policy.AllowNetworkBind = utils.PtrTo(true)

		case config.SandboxAllowEnv:
			// Allow-wins: appending to Allow un-scrubs the variable regardless
			// of whether it was denied by the built-in list or a profile deny
			// glob, so (unlike the filesystem cases) there is no deny list to
			// remove an exact match from.
			log.Infof("Sandbox override: allowing environment variable %s", override.Value)
			policy.Environment.Allow = append(policy.Environment.Allow, override.Value)
		}
	}
}

// scrubEnv removes sensitive environment variables from cmd.Env per the
// resolved policy's environment section and returns the sorted names of the
// variables removed. It runs after project overlay and runtime overrides are
// merged into the policy, so user allowances take effect. A nil cmd.Env would
// mean "inherit the parent environment", which would defeat scrubbing, so it is
// populated from os.Environ() first.
func scrubEnv(cmd *exec.Cmd, policy *sandbox.SandboxPolicy) []string {
	if cmd.Env == nil {
		cmd.Env = os.Environ()
	}

	result := util.ScrubEnv(cmd.Env, util.EnvScrubOptions{
		Allow: policy.Environment.Allow,
		Deny:  policy.Environment.Deny,
	})
	cmd.Env = result.Env

	slices.Sort(result.Removed)

	if len(result.Removed) > 0 {
		log.Infof("Sandbox: scrubbed %d sensitive environment variable(s) from %s: %s",
			len(result.Removed), policy.Name, strings.Join(result.Removed, ", "))
	}

	return result.Removed
}

// removeExactMatch removes the entries that name the override's path, as
// written or once ${HOME}, ${CWD} and ${TMPDIR} are expanded. Glob patterns
// and wildcards are never matched, so a broad deny stays intact while the
// user opts one exact path out.
func removeExactMatch(slice []string, value string) []string {
	result := make([]string, 0, len(slice))
	for _, entry := range slice {
		if entry == value || expandsTo(entry, value) {
			log.Infof("Sandbox override: removing conflicting deny rule for %s", value)
			continue
		}

		result = append(result, entry)
	}

	return result
}

func expandsTo(entry, value string) bool {
	expanded, err := util.ExpandVariables(entry)
	return err == nil && expanded == value
}

// applyProjectOverlay loads the per-repo overlay (when one exists) and feeds
// its entries through applyRuntimeOverrides. Returns the number of entries
// applied. A nil/missing overlay is a clean no-op. When locked, the overlay
// is ignored entirely.
func applyProjectOverlay(policy *sandbox.SandboxPolicy, overlayDir, repoRoot string, locked bool, presets sandbox.PresetRegistry) (int, error) {
	if locked {
		log.Debugf("Project overlay: skipping under global_lockdown")
		return 0, nil
	}

	overlay, _, err := sandbox.LoadOverlayForRepo(overlayDir, repoRoot)
	if err != nil {
		return 0, fmt.Errorf("project overlay: load: %w", err)
	}
	if overlay == nil {
		return 0, nil
	}
	warnIgnoredOverlayEntries(overlay.Ignored)
	if len(overlay.Allow) == 0 {
		return 0, nil
	}

	entries := overlay.ToAllowOverrides()
	applyRuntimeOverrides(policy, entries, presets)
	// The "+overlay" suffix tags audit events as overlay-sourced.
	logSandboxOverrides(policy.Name+"+overlay", entries)
	log.Infof("Project overlay: applied %d saved allowance(s) for %s", len(entries), repoRoot)
	return len(entries), nil
}

// warnIgnoredOverlayEntries names each saved entry that the load ignored.
// Without the warning a user sees fewer allowances and no reason.
func warnIgnoredOverlayEntries(ignored []sandbox.IgnoredOverlayAllow) {
	for _, entry := range ignored {
		log.Warnf("Project overlay: ignoring %s: %v", entry.String(), entry.Reason)
		if _, err := fmt.Fprintf(os.Stderr, "pmg: warning: project overlay entry %q is ignored: %v. %s\n", entry.String(), entry.Reason, sandbox.IgnoredOverlayHint); err != nil {
			log.Warnf("failed to write overlay warning to stderr: %v", err)
		}
	}
}

// logSandboxOverrides records sandbox allow overrides in the audit event log.
func logSandboxOverrides(profileName string, overrides []config.SandboxAllowOverride) {
	entries := make([]map[string]string, 0, len(overrides))
	for _, o := range overrides {
		entries = append(entries, map[string]string{
			"type":  string(o.Type),
			"value": o.Value,
		})
	}

	audit.LogSandboxOverride(profileName, entries)
}
