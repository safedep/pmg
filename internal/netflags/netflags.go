// Package netflags holds the network policy flags that pmg proxy start and
// pmg sandbox exec share, so both commands name, check and echo them the
// same way.
package netflags

import (
	"errors"
	"fmt"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/proxy/netpolicy"
	"github.com/spf13/pflag"
)

const (
	Mode  = "network-mode"
	Allow = "network-allow"
	Deny  = "network-deny"
)

// AddModeFlag binds --network-mode to mode. The loaded config value is the
// default, so a locked config's value stands unless the flag changes it.
// configKey names the config key in the usage line.
func AddModeFlag(fs *pflag.FlagSet, mode *string, configKey string) {
	fs.StringVar(mode, Mode, *mode,
		fmt.Sprintf("What the proxy does with a match on a deny rule: audit or enforce (%s)", configKey))
}

// AddRuleFlags adds --network-allow and --network-deny. Each rule adds to
// the resolved profile and has no config key.
func AddRuleFlags(fs *pflag.FlagSet, allow, deny *[]string) {
	fs.StringArrayVar(allow, Allow, nil, "host:port rule added to the profile's allow_outbound list (repeatable)")
	fs.StringArrayVar(deny, Deny, nil, "host:port rule added to the profile's deny_outbound list (repeatable)")
}

// Widening returns the flags that loosen the policy a locked config set:
// an allow rule, or audit over a config that says enforce. A deny rule and
// enforce over audit only narrow. mode is the value after parsing, and the
// flag's default is the config's value. An empty mode means audit.
func Widening(fs *pflag.FlagSet, mode string) []string {
	var out []string
	if fs.Changed(Allow) {
		out = append(out, "--"+Allow)
	}
	if f := fs.Lookup(Mode); f != nil && f.Changed &&
		mode != config.SandboxNetworkModeEnforce && f.DefValue == config.SandboxNetworkModeEnforce {
		out = append(out, "--"+Mode+"="+mode)
	}
	return out
}

// Args repeats the flags for a re-exec of the command.
func Args(fs *pflag.FlagSet, mode string, allow, deny []string) []string {
	var args []string
	if fs.Changed(Mode) {
		args = append(args, "--"+Mode, mode)
	}
	for _, rule := range allow {
		args = append(args, "--"+Allow, rule)
	}
	for _, rule := range deny {
		args = append(args, "--"+Deny, rule)
	}
	return args
}

// CheckRule returns a usefulerror when raw is not a rule the matcher
// reads. flag names the flag the rule came from.
func CheckRule(flag, raw string) error {
	_, err := netpolicy.ParseRule(raw)
	if err == nil {
		return nil
	}
	err = fmt.Errorf("--%s %q: %w", flag, raw, err)
	return usefulerror.NewUsefulError().
		WithCode(errcodes.InvalidArgument).
		WithHumanError(err.Error()).
		WithHelp("Write the rule as host:port, for example registry.npmjs.org:443, or *:* for every destination.").
		Wrap(err)
}

// ModeError turns an invalid --network-mode value into the error pmg
// reports for the config key.
func ModeError(err error) error {
	var modeErr *config.NetworkModeError
	if errors.As(err, &modeErr) {
		return config.NewInvalidNetworkModeError(modeErr)
	}
	return err
}
