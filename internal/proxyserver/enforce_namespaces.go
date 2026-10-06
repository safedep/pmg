package proxyserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/safedep/dry/log"
	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/netenforce"
)

// NamespaceState is the redirect for other network namespaces as the state
// file records it: the mode the config asked for, the mode in effect, why
// they differ, and the loaded table.
type NamespaceState struct {
	Mode      string                      `json:"mode"`
	Effective string                      `json:"effective"`
	Reason    string                      `json:"reason,omitempty"`
	Table     *netenforce.NamespaceStatus `json:"table,omitempty"`
}

// NamespaceStatusLine renders the one status line for the redirect. An
// older state file has no block, and then there is no line.
func NamespaceStatusLine(ns *NamespaceState) string {
	switch {
	case ns == nil:
		return ""
	case ns.Effective == string(netenforce.NamespaceRedirect) && ns.Table != nil:
		return fmt.Sprintf("namespaces: redirect (%s from %s)", ns.Table.Target(), strings.Join(ns.Table.Ingress, ", "))
	case ns.Reason != "":
		return fmt.Sprintf("namespaces: ignore (%s: %s)", ns.Mode, ns.Reason)
	default:
		return "namespaces: ignore"
	}
}

// newNamespaceRedirector is the seam tests use to stand in a fake host.
var newNamespaceRedirector = netenforce.NewNamespaceRedirector

// NamespacesNeedEnforce fails when the config asks for redirect without
// kernel enforcement. The redirect terminates TLS with the system CA that
// only an enforcing daemon loads, so without --enforce it would be a
// silent no-op. auto means "where the host can", and without enforcement
// it cannot, so auto stays quiet.
func NamespacesNeedEnforce(cfg *config.RuntimeConfig, enforce bool) error {
	mode, err := netenforce.ParseNamespaceMode(cfg.Config.Proxy.Server.Enforce.Namespaces.Mode)
	if err != nil {
		return err
	}
	if enforce || mode != netenforce.NamespaceRedirect {
		return nil
	}
	return usefulerror.NewUsefulError().
		WithCode(errcodes.EnforceRequirements).
		WithHumanError(fmt.Sprintf("namespaces mode %s needs kernel enforcement", mode)).
		WithMsg("the namespace redirect runs only with --enforce").
		WithHelp("Start with `sudo pmg proxy start --enforce --enforce-namespaces " + string(mode) + "`, or set proxy.server.enforce.namespaces.mode to ignore.").
		Wrap(errors.New("namespaces mode without enforcement"))
}

// namespaceRedirect carries the redirect through the daemon's start and
// stop. Under redirect every failure fails the start. Under auto a failure
// before the table is loaded turns the mode into ignore with a reason.
type namespaceRedirect struct {
	mode       netenforce.NamespaceMode
	effective  netenforce.NamespaceMode
	reason     string
	policy     netenforce.NamespacePolicy
	redirector netenforce.NamespaceRedirector
	handle     netenforce.NamespaceHandle
	addressOn  bool
}

// newNamespaceRedirect reads the config block, probes the host, and decides
// the mode in effect. It changes nothing on the host.
func newNamespaceRedirect(nc config.ProxyEnforceNamespacesConfig, p netenforce.Policy) (*namespaceRedirect, error) {
	mode, err := netenforce.ParseNamespaceMode(nc.Mode)
	if err != nil {
		return nil, err
	}
	policy, err := namespacePolicy(nc, p)
	if err != nil {
		return nil, err
	}
	n := &namespaceRedirect{mode: mode, effective: mode, policy: policy}
	if mode == netenforce.NamespaceIgnore {
		return n, nil
	}

	r, err := newNamespaceRedirector()
	if err != nil {
		return n, n.degrade(err)
	}
	if probe := r.Probe(); !probe.Supported {
		return n, n.degrade(probe.Err())
	}
	n.redirector = r
	n.effective = netenforce.NamespaceRedirect
	return n, nil
}

func namespacePolicy(nc config.ProxyEnforceNamespacesConfig, p netenforce.Policy) (netenforce.NamespacePolicy, error) {
	np := netenforce.NamespacePolicy{Ingress: nc.Ingress, Ports: p.Ports, DenyUDP: p.DenyUDP}
	if len(np.Ports) == 0 {
		np.Ports = netenforce.DefaultPorts
	}
	if nc.Address != "" {
		addr, err := netip.ParseAddr(nc.Address)
		if err != nil {
			return netenforce.NamespacePolicy{}, fmt.Errorf("proxy.server.enforce.namespaces.address: %q is not an IP address: %w", nc.Address, err)
		}
		np.Address = addr
	}
	np = np.WithDefaults()
	if err := np.Validate(); err != nil {
		return netenforce.NamespacePolicy{}, err
	}
	return np, nil
}

// degrade handles a host that cannot redirect. Under redirect it is the
// start failure, with what to do. Under auto it records the reason and the
// daemon runs as ignore.
func (n *namespaceRedirect) degrade(cause error) error {
	if n.mode == netenforce.NamespaceRedirect {
		return usefulerror.NewUsefulError().
			WithCode(errcodes.EnforceRequirements).
			WithHumanError("this host cannot redirect containers through the proxy").
			WithMsg(cause.Error()).
			WithHelp("The redirect needs Linux 5.13 or later with nf_tables and conntrack, and CAP_NET_ADMIN. Set proxy.server.enforce.namespaces.mode to auto to run without it where the host cannot, or to ignore to turn it off.").
			Wrap(cause)
	}
	n.effective = netenforce.NamespaceIgnore
	n.reason = cause.Error()
	n.redirector = nil
	return nil
}

// A nil redirect is a daemon without enforcement, and every method on it
// is a no-op, so the server's stop path needs no branch.
func (n *namespaceRedirect) active() bool {
	return n != nil && n.effective == netenforce.NamespaceRedirect
}

// listenAddr is the extra address the proxy listens on, on its own port.
func (n *namespaceRedirect) listenAddr() string {
	if !n.active() {
		return ""
	}
	return net.JoinHostPort(n.policy.Address.String(), "0")
}

// prepare puts the address on lo before the proxy binds it.
func (n *namespaceRedirect) prepare() error {
	if !n.active() {
		return nil
	}
	if err := n.redirector.EnsureAddress(n.policy.Address); err != nil {
		return n.degrade(err)
	}
	n.addressOn = true
	return nil
}

// attach loads the table once the proxy listens on the address. listeners
// are the addresses the proxy bound beside its primary one.
func (n *namespaceRedirect) attach(ctx context.Context, listeners []string) error {
	if !n.active() {
		return nil
	}
	port, ok := n.listenerPort(listeners)
	if !ok {
		return n.fail(fmt.Errorf("the proxy did not bind %s", n.policy.Address))
	}
	h, err := n.redirector.Attach(ctx, port, n.policy)
	if err != nil {
		return n.fail(fmt.Errorf("load the redirect table: %w", err))
	}
	n.handle = h
	return nil
}

// fail is degrade for a failure after the address went on. The address
// comes off again, because nothing will listen for it.
func (n *namespaceRedirect) fail(cause error) error {
	if rerr := n.releaseAddress(); rerr != nil {
		log.Warnf("%v", rerr)
	}
	return n.degrade(cause)
}

func (n *namespaceRedirect) listenerPort(listeners []string) (uint16, bool) {
	for _, extra := range listeners {
		if ap, err := netip.ParseAddrPort(extra); err == nil && ap.Addr() == n.policy.Address {
			return ap.Port(), true
		}
	}
	return 0, false
}

// detach deletes the table. It runs before the listener closes, so no
// rule points at a closed port.
func (n *namespaceRedirect) detach() error {
	if n == nil || n.handle == nil {
		return nil
	}
	err := n.handle.Close()
	n.handle = nil
	return err
}

// releaseAddress takes the address off lo. It runs after the server
// drained, because a connection whose local address is gone cannot send.
func (n *namespaceRedirect) releaseAddress() error {
	if n == nil || !n.addressOn || n.redirector == nil {
		return nil
	}
	n.addressOn = false
	return n.redirector.RemoveAddress(n.policy.Address)
}

func (n *namespaceRedirect) state() *NamespaceState {
	if n == nil {
		return nil
	}
	ns := &NamespaceState{Mode: string(n.mode), Effective: string(n.effective), Reason: n.reason}
	if n.handle != nil {
		st := n.handle.Status()
		ns.Table = &st
	}
	return ns
}

// warnings names what an operator must know: redirected containers need
// the CA, a host firewall that would drop them, or the reason the redirect
// is off under auto.
func (n *namespaceRedirect) warnings() []string {
	switch {
	case n == nil:
		return nil
	case n.active():
		w := []string{fmt.Sprintf("Containers on %s are redirected through the proxy. A container that does not trust the PMG CA fails on registry hosts. Pass PMG_CA_BUNDLE from `pmg proxy env` into it. See docs/persistent-proxy.md.", strings.Join(n.policy.Ingress, ", "))}
		if fw := n.firewallWarning(); fw != "" {
			w = append(w, fw)
		}
		return w
	case n.reason != "":
		return []string{"Containers are not redirected through the proxy: " + n.reason}
	default:
		return nil
	}
}

// firewallWarning names the input chains that drop by default. The daemon
// cannot see whether a rule in them already accepts the listener, so it
// names the rule to add and lets the operator judge.
func (n *namespaceRedirect) firewallWarning() string {
	chains, err := n.redirector.InputDropChains()
	if err != nil {
		log.Warnf("%v", err)
		return ""
	}
	if len(chains) == 0 {
		return ""
	}
	names := make([]string, len(chains))
	for i, c := range chains {
		names[i] = c.String()
	}
	return fmt.Sprintf("The host firewall drops input by default in %s. A redirected container hangs until a rule accepts the listener on every ingress interface, for example `%s`. ufw keeps `ufw allow in on %s to %s`.",
		strings.Join(names, ", "), chains[0].AcceptRule(n.policy.Ingress[0], n.policy.Address), n.policy.Ingress[0], n.policy.Address)
}

// detachAll is the error-path cleanup: table and address together.
func (n *namespaceRedirect) detachAll() error {
	return errors.Join(n.detach(), n.releaseAddress())
}
