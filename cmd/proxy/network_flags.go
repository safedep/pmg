package proxy

import (
	"path/filepath"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/netflags"
	"github.com/safedep/pmg/internal/proxyserver"
	"github.com/safedep/pmg/sandbox/executor"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// flagProfile is the network policy flag only pmg proxy start has. It
// binds to proxy.server.profile. The shared flags are in netflags.
const flagProfile = "profile"

var networkOverridesFlag proxyserver.NetworkOverrides

func addNetworkFlags(cmd *cobra.Command, srv *config.ProxyServerConfig) {
	fs := cmd.Flags()
	fs.StringVar(&srv.Profile, flagProfile, srv.Profile,
		"Sandbox profile whose network rules the proxy applies: a built-in name, a policy_templates name, a user profile name, or a path (proxy.server.profile)")
	netflags.AddModeFlag(fs, &srv.NetworkMode, "proxy.server.network_mode")
	netflags.AddRuleFlags(fs, &networkOverridesFlag.Allow, &networkOverridesFlag.Deny)
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
// locked managed config set. Next to the shared checks, an empty profile
// over a file that names one widens. Another profile is checked against
// the locked one when the daemon loads it.
func wideningNetworkFlags(fs *pflag.FlagSet, srv config.ProxyServerConfig) []string {
	out := netflags.Widening(fs, srv.NetworkMode)
	if profile := fs.Lookup(flagProfile); profile != nil && profile.Changed && srv.Profile == "" && profile.DefValue != "" {
		out = append(out, "--"+flagProfile+"=")
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
	return append(args, netflags.Args(fs, srv.NetworkMode, o.Allow, o.Deny)...)
}
