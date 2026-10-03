package proxyserver

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os/user"
	"slices"
	"strconv"
	"sync/atomic"

	"github.com/safedep/dry/log"
	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/netenforce"
	"github.com/safedep/pmg/internal/platform"
	"github.com/safedep/pmg/proxy/certmanager"
	"github.com/safedep/pmg/truststore"
)

// EnforceState is the Enforce block of the state file: the policy as the
// kernel sees it, plus the warnings printed at start, so `pmg proxy status`
// can repeat them.
type EnforceState struct {
	netenforce.Status
	Addr6    string   `json:"addr6,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// enforcePolicy turns the config section into the kernel policy. The ports
// of every proxy.registries endpoint are added, so a private registry on a
// non-standard port is routed too. extraExempt holds the globs the parent
// computed, such as the GitHub runner binaries.
func enforcePolicy(cfg *config.RuntimeConfig, extraExempt []string) (netenforce.Policy, error) {
	ec := cfg.Config.Proxy.Server.Enforce
	p := netenforce.DefaultPolicy()
	p.DenyUDP = ec.DenyUDP
	p.CgroupPath = ec.Cgroup
	p.EligibleUsers = ec.EligibleUsers
	p.ExemptUsers = ec.ExemptUsers
	p.ExemptExecutables = append(slices.Clone(ec.ExemptExecutables), extraExempt...)

	ports := make([]uint16, 0, len(ec.Ports)+len(cfg.Config.Proxy.Registries))
	for _, port := range ec.Ports {
		if port < 1 || port > 65535 {
			return netenforce.Policy{}, fmt.Errorf("proxy.server.enforce.ports: %d is not a valid port", port)
		}
		ports = append(ports, uint16(port))
	}
	for _, reg := range cfg.Config.Proxy.Registries {
		for _, ep := range reg.Endpoints {
			port, err := endpointPort(ep.URL)
			if err != nil {
				return netenforce.Policy{}, err
			}
			ports = append(ports, port)
		}
	}
	slices.Sort(ports)
	p.Ports = slices.Compact(ports)

	for _, raw := range ec.SkipDestinations {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return netenforce.Policy{}, fmt.Errorf("proxy.server.enforce.skip_destinations: %q is not a CIDR prefix: %w", raw, err)
		}
		p.SkipDestinations = append(p.SkipDestinations, prefix)
	}

	if err := p.Validate(); err != nil {
		return netenforce.Policy{}, err
	}
	return p, nil
}

func endpointPort(raw string) (uint16, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return 0, fmt.Errorf("proxy.registries endpoint %q: %w", raw, err)
	}
	if u.Port() == "" {
		if u.Scheme == "http" {
			return 80, nil
		}
		return 443, nil
	}
	port, err := strconv.ParseUint(u.Port(), 10, 16)
	if err != nil {
		return 0, fmt.Errorf("proxy.registries endpoint %q: %w", raw, err)
	}
	return uint16(port), nil
}

// enforcePreflight fails before the proxy binds a port when the host cannot
// enforce or no client could trust the proxy. Each failure names what to
// do. The returned warnings are printed and recorded in the state file.
func enforcePreflight(cfg *config.RuntimeConfig, p netenforce.Policy) (netenforce.Enforcer, *certmanager.Certificate, []string, error) {
	enforcer, err := netenforce.New()
	if err != nil {
		return nil, nil, nil, usefulerror.NewUsefulError().
			WithCode(errcodes.UnsupportedPlatform).
			WithHumanError(fmt.Sprintf("kernel enforcement is not available on %s", platform.OSName())).
			WithMsg(err.Error()).
			WithHelp("Run `pmg proxy start --enforce` on a Linux host, or start the proxy without --enforce").
			Wrap(err)
	}

	if probe := enforcer.Probe(); !probe.Supported {
		perr := probe.Err()
		return nil, nil, nil, usefulerror.NewUsefulError().
			WithCode(errcodes.EnforceRequirements).
			WithHumanError("this host cannot enforce proxy routing").
			WithMsg(perr.Error()).
			WithHelp(enforceRequirementsHelp(probe)).
			Wrap(perr)
	}

	caCert, err := loadEnforceCA()
	if err != nil {
		return nil, nil, nil, err
	}

	return enforcer, caCert, enforceWarnings(p), nil
}

func enforceRequirementsHelp(probe netenforce.ProbeResult) string {
	help := "Enforcement needs Linux 5.15 or later with kernel BTF and cgroup v2, and CAP_BPF, CAP_NET_ADMIN and CAP_PERFMON. Run it as root: `sudo pmg proxy start --enforce`."
	for _, m := range probe.Missing {
		help += "\n  - " + m
	}
	return help
}

// loadEnforceCA reads the root-owned keypair that `sudo pmg setup cert
// install --system` wrote and confirms the certificate is in the system
// trust store. An enforcing proxy never generates an ephemeral CA: every
// redirected client would fail on it.
func loadEnforceCA() (*certmanager.Certificate, error) {
	dir := config.SystemConfigDir()
	fail := func(msg string, cause error) error {
		return usefulerror.NewUsefulError().
			WithCode(errcodes.EnforceRequiresTrustedCA).
			WithHumanError(msg).
			WithMsg(fmt.Sprintf("%s: %v", msg, cause)).
			WithHelp("Run `sudo pmg setup cert install --system` first. It writes the keypair to " + dir + " and trusts the certificate machine-wide.").
			Wrap(cause)
	}

	caCert, err := certmanager.LoadCA(dir)
	if err != nil {
		return nil, fail("enforcement needs the PMG CA keypair in "+dir, err)
	}

	_, system, err := truststore.Status(certmanager.CACommonName)
	if err != nil {
		return nil, fail("could not read the system trust store", err)
	}
	if !system {
		return nil, fail("the PMG CA is not in the system trust store", errors.New("certificate not trusted"))
	}
	return caCert, nil
}

// enforceWarnings names the gaps an operator must know about: a container
// engine on the host, whose containers live outside the enforced network
// namespace, and an eligible user who can become root through sudo.
func enforceWarnings(p netenforce.Policy) []string {
	var warnings []string
	if processRunning("dockerd") {
		warnings = append(warnings, "Docker is running. Containers have their own network namespace and are not enforced. See docs/persistent-proxy.md for the workaround.")
	}
	for _, name := range p.EligibleUsers {
		if userCanSudo(name) {
			warnings = append(warnings, fmt.Sprintf("eligible user %q is in the sudo or wheel group. `sudo` runs commands as root, which is not eligible. Leave eligible_users empty and exempt host daemons by executable instead.", name))
		}
	}
	return warnings
}

func userCanSudo(name string) bool {
	u, err := user.Lookup(name)
	if err != nil {
		return false
	}
	gids, err := u.GroupIds()
	if err != nil {
		return false
	}
	for _, groupName := range []string{"sudo", "wheel"} {
		g, err := user.LookupGroup(groupName)
		if err != nil {
			continue
		}
		if slices.Contains(gids, g.Gid) {
			return true
		}
	}
	return false
}

// ipv6LoopbackAddr returns the IPv6 loopback listen address when the host
// has one, so native IPv6 connections can be routed instead of denied.
func ipv6LoopbackAddr() string {
	l, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		return ""
	}
	if err := l.Close(); err != nil {
		log.Debugf("close IPv6 probe listener: %v", err)
	}
	return "[::1]:0"
}

// destinationResolver hands the proxy a resolver before the kernel handle
// exists. The proxy must listen before Attach knows the target address, so
// the handle arrives a moment later.
type destinationResolver struct {
	handle atomic.Pointer[netenforce.Handle]
}

func (r *destinationResolver) set(h netenforce.Handle) { r.handle.Store(&h) }

func (r *destinationResolver) OriginalDestination(client netip.AddrPort) (netip.AddrPort, bool) {
	h := r.handle.Load()
	if h == nil {
		return netip.AddrPort{}, false
	}
	return (*h).OriginalDestination(client)
}
