package proxyserver

import (
	"fmt"
	"strings"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/proxy/netpolicy"
	"github.com/safedep/pmg/sandbox"
	"github.com/safedep/pmg/sandbox/executor"
)

// NetworkOverrides are the network policy values from the command line.
// Each rule adds to the resolved profile.
type NetworkOverrides struct {
	Allow []string
	Deny  []string

	// LockedProfile is the profile a locked config names. It loads from
	// the managed locations only, and a --profile that names another one
	// may only narrow it. Empty means the config is not locked, or names
	// no profile.
	LockedProfile string
}

// NetworkState describes the daemon's network policy in the state file.
// nil when the daemon has no profile and no flag rule.
type NetworkState struct {
	// Chain is the inheritance chain of the profile, base first.
	Chain []string `json:"chain,omitempty"`
	Mode  string   `json:"mode"`

	// Denials are the destinations a deny rule matched, written at
	// shutdown for the stop report.
	Denials []netpolicy.Denial `json:"denials,omitempty"`
}

// Profile is the chain as one line, or "flags" for a policy that is only
// flag rules.
func (n *NetworkState) Profile() string {
	if len(n.Chain) == 0 {
		return "flags"
	}
	return strings.Join(n.Chain, " < ")
}

func (n *NetworkState) Enforced() bool {
	return n.Mode == config.SandboxNetworkModeEnforce
}

// DeniedCount is the number of connections the proxy refused. Under audit
// nothing was refused.
func (n *NetworkState) DeniedCount() int {
	if n == nil || !n.Enforced() {
		return 0
	}
	count := 0
	for _, d := range n.Denials {
		count += d.Count
	}
	return count
}

type networkPolicy struct {
	policy   *netpolicy.Policy
	state    *NetworkState
	warnings []string
}

// resolveNetworkPolicy loads the profile proxy.server.profile names and adds
// the flag rules. A daemon with no profile and no flag rule has no policy.
func resolveNetworkPolicy(cfg *config.RuntimeConfig, o NetworkOverrides) (*networkPolicy, error) {
	srv := cfg.Config.Proxy.Server
	if o.LockedProfile != "" && srv.Profile == "" {
		return nil, managedProfileError(fmt.Sprintf("the globally managed configuration names the profile %s, which cannot be unset", o.LockedProfile))
	}
	if srv.Profile == "" && len(o.Allow) == 0 && len(o.Deny) == 0 {
		return &networkPolicy{}, nil
	}

	rules := sandbox.NetworkPolicy{}
	var chain []string
	var warnings []string
	if srv.Profile != "" {
		profile, err := loadProfile(cfg, o.LockedProfile, srv.Profile)
		if err != nil {
			return nil, err
		}
		rules = profile.Network
		chain = profile.Lineage
		if profile.HasNonNetworkRules() {
			warnings = append(warnings, fmt.Sprintf("Profile %s has filesystem, process or environment rules. The proxy applies only its network rules.", profile.Name))
		}
	}

	for _, raw := range o.Allow {
		if err := checkFlagRule("--network-allow", raw); err != nil {
			return nil, err
		}
		rules.Allow(raw)
	}
	for _, raw := range o.Deny {
		if err := checkFlagRule("--network-deny", raw); err != nil {
			return nil, err
		}
		rules.Deny(raw)
	}

	policy, err := netpolicy.New(rules.AllowOutbound, rules.DenyOutbound)
	if err != nil {
		return nil, usefulerror.NewUsefulError().
			WithCode(errcodes.SandboxPolicyInvalid).
			WithHumanError(fmt.Sprintf("Profile %s has an invalid network rule: %v", srv.Profile, err)).
			WithHelp("Write each rule as host:port, for example registry.npmjs.org:443. `pmg sandbox profile lint` lists every invalid rule.").
			Wrap(err)
	}

	return &networkPolicy{
		policy:   policy,
		state:    &NetworkState{Chain: chain, Mode: networkMode(srv.NetworkMode)},
		warnings: warnings,
	}, nil
}

func networkMode(mode string) string {
	if mode == "" {
		return config.SandboxNetworkModeAudit
	}
	return mode
}

func checkFlagRule(flag, raw string) error {
	_, err := netpolicy.ParseRule(raw)
	if err == nil {
		return nil
	}
	err = fmt.Errorf("%s %q: %w", flag, raw, err)
	return usefulerror.NewUsefulError().
		WithCode(errcodes.InvalidArgument).
		WithHumanError(err.Error()).
		WithHelp("Write the rule as host:port, for example registry.npmjs.org:443, or *:* for every destination.").
		Wrap(err)
}

// loadProfile loads ref. A locked config's own profile loads from the
// managed locations only, because the working directory and the user
// directories are writable by the user. Another ref under lockdown loads
// as usual and must narrow the locked profile.
func loadProfile(cfg *config.RuntimeConfig, lockedRef, ref string) (*sandbox.SandboxPolicy, error) {
	if lockedRef == "" {
		return executor.LoadProfile(cfg, ref)
	}

	locked, err := executor.LoadManagedProfile(cfg, lockedRef)
	if err != nil || ref == lockedRef {
		return locked, err
	}

	child, err := executor.LoadProfile(cfg, ref)
	if err != nil {
		return nil, err
	}
	return child, refuseWideningProfile(locked, child)
}

// refuseWideningProfile fails when child allows what the locked profile
// does not, or drops a deny rule the locked profile has. A child profile
// that inherits the locked one and only adds deny rules passes.
func refuseWideningProfile(locked, child *sandbox.SandboxPolicy) error {
	var widening []string
	for _, rule := range child.Network.AllowOutbound {
		if !containsRule(locked.Network.AllowOutbound, rule) {
			widening = append(widening, "allows "+rule)
		}
	}
	for _, rule := range locked.Network.DenyOutbound {
		if !containsRule(child.Network.DenyOutbound, rule) {
			widening = append(widening, "drops the deny rule "+rule)
		}
	}
	if len(widening) == 0 {
		return nil
	}
	return managedProfileError(fmt.Sprintf("profile %s widens the globally managed profile %s: %s", child.Name, locked.Name, strings.Join(widening, ", ")))
}

func managedProfileError(msg string) error {
	return usefulerror.NewUsefulError().
		WithCode(errcodes.PermissionDenied).
		WithHumanError(msg).
		WithHelp("This machine's PMG configuration is centrally managed. A profile may add deny rules and may not add allow rules. Contact your administrator to change it.").
		Wrap(fmt.Errorf("%s", msg))
}

// containsRule compares rules as the matcher reads them, so a case or a
// trailing dot does not tell two equal rules apart.
func containsRule(rules []string, raw string) bool {
	want, err := netpolicy.ParseRule(raw)
	if err != nil {
		return false
	}
	for _, r := range rules {
		got, err := netpolicy.ParseRule(r)
		if err == nil && got.Host == want.Host && got.Port == want.Port && got.Client == want.Client {
			return true
		}
	}
	return false
}

// PreflightNetwork resolves the network policy without starting anything,
// so the parent of a daemon reports a bad profile or a widening flag at
// once, instead of as a readiness timeout.
func PreflightNetwork(cfg *config.RuntimeConfig, o NetworkOverrides) error {
	_, err := resolveNetworkPolicy(cfg, o)
	return err
}

// NetworkPolicyLine says which policy the daemon applies and how. Without
// kernel enforcement a process can go around the proxy, so the policy is
// advisory.
func NetworkPolicyLine(network *NetworkState, kernelEnforced bool) string {
	if network == nil {
		return "Network policy: none. No profile is set, so every destination is allowed.\n"
	}
	line := fmt.Sprintf("Network policy: %s, profile %s", network.Mode, network.Profile())
	if !kernelEnforced {
		line += ", enforce: off, policy advisory"
	}
	return line + "\n"
}
