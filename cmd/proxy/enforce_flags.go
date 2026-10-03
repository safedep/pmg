package proxy

import (
	"strconv"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/proxyserver"
	"github.com/spf13/cobra"
)

// The enforce policy flags of pmg proxy start. A list flag adds to the
// config's list. The scalars bind to the config fields, so the usual
// precedence holds: flag, then PMG_* variable, then file, then default.
const (
	flagEnforcePort             = "enforce-port"
	flagEnforceEligibleUser     = "enforce-eligible-user"
	flagEnforceExemptUser       = "enforce-exempt-user"
	flagEnforceExemptExecutable = "enforce-exempt-executable"
	flagEnforceSkipDestination  = "enforce-skip-destination"
	flagEnforceCgroup           = "enforce-cgroup"
	flagEnforceDenyUDP          = "enforce-deny-udp"

	// flagEnforceRunnerExecutable carries the runner globs the parent found
	// to the daemon child. It is internal and hidden, and only the child
	// honors it, so it is not a way around a locked managed config.
	flagEnforceRunnerExecutable = "enforce-runner-executable"
)

var enforceOverridesFlag proxyserver.EnforceOverrides

func addEnforceFlags(cmd *cobra.Command, ec *config.ProxyEnforceConfig) {
	fs := cmd.Flags()
	fs.IntSliceVar(&enforceOverridesFlag.Ports, flagEnforcePort, nil,
		"Destination port to route, in addition to proxy.server.enforce.ports (repeatable)")
	fs.StringArrayVar(&enforceOverridesFlag.EligibleUsers, flagEnforceEligibleUser, nil,
		"User to route, in addition to proxy.server.enforce.eligible_users (repeatable)")
	fs.StringArrayVar(&enforceOverridesFlag.ExemptUsers, flagEnforceExemptUser, nil,
		"User never routed, in addition to proxy.server.enforce.exempt_users (repeatable)")
	fs.StringArrayVar(&enforceOverridesFlag.ExemptExecutables, flagEnforceExemptExecutable, nil,
		"Absolute path or glob of a program that connects directly, in addition to proxy.server.enforce.exempt_executables (repeatable)")
	fs.StringArrayVar(&enforceOverridesFlag.SkipDestinations, flagEnforceSkipDestination, nil,
		"CIDR prefix never routed, in addition to proxy.server.enforce.skip_destinations (repeatable)")
	fs.StringVar(&ec.Cgroup, flagEnforceCgroup, ec.Cgroup,
		"cgroup v2 directory to enforce, instead of the root (proxy.server.enforce.cgroup)")
	fs.BoolVar(&ec.DenyUDP, flagEnforceDenyUDP, ec.DenyUDP,
		"Deny UDP to the enforced ports so QUIC clients fall back to TCP (proxy.server.enforce.deny_udp)")
	fs.StringArrayVar(&enforceOverridesFlag.RunnerExecutables, flagEnforceRunnerExecutable, nil,
		"Internal: runner globs the parent found, for the daemon child")
	if err := fs.MarkHidden(flagEnforceRunnerExecutable); err != nil {
		panic(err)
	}
}

// wideningFlags returns the enforce flags that loosen the policy a locked
// managed config set: more users or programs that go direct, more
// destinations the kernel skips, or UDP left open. A port or a cgroup only
// narrows or moves the scope and stays allowed under lockdown.
func wideningFlags(changed func(string) bool, denyUDP bool) []string {
	var out []string
	for _, name := range []string{flagEnforceEligibleUser, flagEnforceExemptUser, flagEnforceExemptExecutable, flagEnforceSkipDestination} {
		if changed(name) {
			out = append(out, "--"+name)
		}
	}
	if changed(flagEnforceDenyUDP) && !denyUDP {
		out = append(out, "--"+flagEnforceDenyUDP+"=false")
	}
	return out
}

// enforceFlagArgs repeats the enforce flags for the daemon child, which
// reads the config file again and adds them the same way the parent did.
func enforceFlagArgs(cmd *cobra.Command, o proxyserver.EnforceOverrides, ec config.ProxyEnforceConfig) []string {
	var args []string
	for _, port := range o.Ports {
		args = append(args, "--"+flagEnforcePort, strconv.Itoa(port))
	}
	lists := []struct {
		name   string
		values []string
	}{
		{flagEnforceEligibleUser, o.EligibleUsers},
		{flagEnforceExemptUser, o.ExemptUsers},
		{flagEnforceExemptExecutable, o.ExemptExecutables},
		{flagEnforceSkipDestination, o.SkipDestinations},
	}
	for _, l := range lists {
		for _, v := range l.values {
			args = append(args, "--"+l.name, v)
		}
	}
	for _, glob := range o.RunnerExecutables {
		args = append(args, "--"+flagEnforceRunnerExecutable, glob)
	}
	if cmd.Flags().Changed(flagEnforceCgroup) {
		args = append(args, "--"+flagEnforceCgroup, ec.Cgroup)
	}
	if cmd.Flags().Changed(flagEnforceDenyUDP) {
		args = append(args, "--"+flagEnforceDenyUDP+"="+strconv.FormatBool(ec.DenyUDP))
	}
	return args
}
