package proxy

import (
	"path/filepath"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/proxyserver"
	"github.com/safedep/pmg/sandbox/executor"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// The network policy flags of pmg proxy start. --profile and --network-mode
// bind to the config fields. The rule flags add to the resolved profile and
// have no config key.
const (
	flagProfile      = "profile"
	flagNetworkMode  = "network-mode"
	flagNetworkAllow = "network-allow"
	flagNetworkDeny  = "network-deny"
)

var networkOverridesFlag proxyserver.NetworkOverrides

func addNetworkFlags(cmd *cobra.Command, srv *config.ProxyServerConfig) {
	fs := cmd.Flags()
	fs.StringVar(&srv.Profile, flagProfile, srv.Profile,
		"Sandbox profile whose network rules the proxy applies: a built-in name, a policy_templates name, a user profile name, or a path (proxy.server.profile)")
	fs.StringVar(&srv.NetworkMode, flagNetworkMode, srv.NetworkMode,
		"What the proxy does with a match on a deny rule: audit or enforce (proxy.server.network_mode)")
	fs.StringArrayVar(&networkOverridesFlag.Allow, flagNetworkAllow, nil,
		"host:port rule added to the profile's allow_outbound list (repeatable)")
	fs.StringArrayVar(&networkOverridesFlag.Deny, flagNetworkDeny, nil,
		"host:port rule added to the profile's deny_outbound list (repeatable)")
}

// absoluteProfileFlag makes a relative --profile path absolute, so the
// daemon child and the config loader read the file the user named in the
// working directory, and not one next to the config file. A bare name
// stays a name, so a file in the working directory cannot stand in for a
// built-in profile.
func absoluteProfileFlag(fs *pflag.FlagSet, srv *config.ProxyServerConfig) {
	if !fs.Changed(flagProfile) || !executor.IsProfilePath(srv.Profile) || filepath.IsAbs(srv.Profile) {
		return
	}
	abs, err := filepath.Abs(srv.Profile)
	if err != nil {
		log.Warnf("failed to resolve --profile %s: %v", srv.Profile, err)
		return
	}
	srv.Profile = abs
}

// wideningNetworkFlags returns the network flags that loosen the policy a
// locked managed config set: an allow rule, an empty profile over a file
// that names one, or audit over a file that says enforce. A deny rule and
// enforce over audit only narrow. A flag's default is the file's value, so
// the file's values are the defaults of --profile and --network-mode. An
// empty mode means audit.
func wideningNetworkFlags(fs *pflag.FlagSet, srv config.ProxyServerConfig) []string {
	var out []string
	if fs.Changed(flagNetworkAllow) {
		out = append(out, "--"+flagNetworkAllow)
	}
	if profile := fs.Lookup(flagProfile); profile != nil && profile.Changed && srv.Profile == "" && profile.DefValue != "" {
		out = append(out, "--"+flagProfile+"=")
	}
	if mode := fs.Lookup(flagNetworkMode); mode != nil && mode.Changed &&
		srv.NetworkMode != config.SandboxNetworkModeEnforce && mode.DefValue == config.SandboxNetworkModeEnforce {
		out = append(out, "--"+flagNetworkMode+"="+srv.NetworkMode)
	}
	return out
}

// lockedProfile returns the profile the locked config names, which is the
// default of --profile. The daemon loads it from the managed locations
// only, and checks that a --profile that names another one narrows it.
func lockedProfile(fs *pflag.FlagSet) string {
	if profile := fs.Lookup(flagProfile); profile != nil {
		return profile.DefValue
	}
	return ""
}

// networkFlagArgs repeats the network flags for the daemon child.
func networkFlagArgs(fs *pflag.FlagSet, o proxyserver.NetworkOverrides, srv config.ProxyServerConfig) []string {
	var args []string
	if fs.Changed(flagProfile) {
		args = append(args, "--"+flagProfile, srv.Profile)
	}
	if fs.Changed(flagNetworkMode) {
		args = append(args, "--"+flagNetworkMode, srv.NetworkMode)
	}
	for _, rule := range o.Allow {
		args = append(args, "--"+flagNetworkAllow, rule)
	}
	for _, rule := range o.Deny {
		args = append(args, "--"+flagNetworkDeny, rule)
	}
	return args
}
