package proxy

import (
	"fmt"
	"os"
	"strings"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/internal/proxyserver"
	"github.com/safedep/pmg/internal/ui"
)

const warningMark = "⚠"

// startupMessage is what the daemon prints once it serves. In the
// foreground it reaches the terminal. Under --daemon it reaches the log
// file, where the color library prints the mark plain.
func startupMessage(state proxyserver.State) string {
	var b strings.Builder
	if state.Enforce == nil {
		fmt.Fprintf(&b, "PMG proxy running on %s\n", state.Addr)
		b.WriteString(configSourceLine(state))
		b.WriteString(networkPolicyLine(state.Network, state.Enforce != nil))
		b.WriteString("Run: export $(pmg proxy env | xargs)  # or: pmg proxy env >> \"$GITHUB_ENV\"\n")
		b.WriteString(warningLines(state.Notices()))
		return b.String()
	}

	fmt.Fprintf(&b, "PMG proxy running on %s with kernel enforcement (cgroup %s, ports %s)\n",
		state.Addr, state.Enforce.CgroupPath, state.Enforce.PortList())
	b.WriteString(configSourceLine(state))
	b.WriteString(networkPolicyLine(state.Network, state.Enforce != nil))
	if line := namespaceStatusLine(state.Enforce.Namespaces); line != "" {
		fmt.Fprintf(&b, "  %s\n", line)
	}
	b.WriteString("Every eligible process is routed through the proxy. Run: pmg proxy env >> \"$GITHUB_ENV\"  # trust variables only\n")
	b.WriteString(warningLines(state.Notices()))
	return b.String()
}

// configSourceLine names the file the daemon loaded. An older state file
// has no path, and then there is nothing to say.
func configSourceLine(state proxyserver.State) string {
	if state.ConfigPath == "" {
		return ""
	}
	return fmt.Sprintf("  config: %s (%s)\n", state.ConfigPath, state.ConfigSource)
}

// networkPolicyLine says which policy the daemon applies and how. Without
// kernel enforcement a process can go around the proxy, so the policy is
// advisory.
func networkPolicyLine(network *proxyserver.NetworkState, kernelEnforced bool) string {
	if network == nil {
		return "Network policy: none. No profile is set, so every destination is allowed.\n"
	}
	line := fmt.Sprintf("Network policy: %s, profile %s", network.Mode, network.Profile())
	if !kernelEnforced {
		line += ", enforce: off, policy advisory"
	}
	return line + "\n"
}

// namespaceStatusLine is the one status line for the redirect. An older
// state file has no block, and then there is no line.
func namespaceStatusLine(ns *proxyserver.NamespaceState) string {
	switch {
	case ns == nil:
		return ""
	case ns.Redirecting():
		return fmt.Sprintf("namespaces: redirect (%s from %s)", ns.Table.Target(), strings.Join(ns.Table.Ingress, ", "))
	case ns.Reason != "":
		return fmt.Sprintf("namespaces: ignore (%s: %s)", ns.Mode, ns.Reason)
	default:
		return "namespaces: ignore"
	}
}

// warningLines renders daemon notices, one marked line each.
func warningLines(warnings []string) string {
	var b strings.Builder
	for _, w := range warnings {
		fmt.Fprintf(&b, "%s %s\n", ui.Colors.Yellow(warningMark), w)
	}
	return b.String()
}

// certificateRejectedNotice tells the operator what a rejected handshake
// means and what to do. It goes to stderr, which is the daemon's log file,
// because the logger is off without --debug.
func certificateRejectedNotice(line string) {
	if _, err := fmt.Fprintf(os.Stderr, "%s %s. A client that fails the handshake this way does not trust the PMG CA. Pass PMG_CA_BUNDLE from `pmg proxy env` into it. See docs/persistent-proxy.md\n", ui.Colors.Yellow(warningMark), line); err != nil {
		log.Warnf("%s: the client does not trust the PMG CA", line)
	}
}
