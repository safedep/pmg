package netenforce

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// NamespaceMode says what the daemon does with a socket in another network
// namespace, such as a container's.
type NamespaceMode string

const (
	// NamespaceIgnore leaves other namespaces alone.
	NamespaceIgnore NamespaceMode = "ignore"

	// NamespaceRedirect sends their traffic through the proxy from the
	// bridge, and the start fails when the host cannot.
	NamespaceRedirect NamespaceMode = "redirect"

	// NamespaceAuto redirects where the host can and ignores elsewhere.
	NamespaceAuto NamespaceMode = "auto"
)

// ParseNamespaceMode accepts the three modes. Empty means ignore.
func ParseNamespaceMode(s string) (NamespaceMode, error) {
	switch m := NamespaceMode(strings.ToLower(strings.TrimSpace(s))); m {
	case "":
		return NamespaceIgnore, nil
	case NamespaceIgnore, NamespaceRedirect, NamespaceAuto:
		return m, nil
	default:
		return "", fmt.Errorf("enforce: namespaces mode %q is not ignore, redirect or auto", s)
	}
}

// DefaultNamespaceIngress names the interfaces Docker gives its networks:
// the default bridge and every user-defined network.
var DefaultNamespaceIngress = []string{"docker0", "br-*"}

// DefaultNamespaceAddress is the listener address the daemon adds to lo.
// Link-local space is never routed, so no host on the LAN reaches it.
var DefaultNamespaceAddress = netip.MustParseAddr("169.254.200.1")

// NamespaceTable is the name of the nftables table the daemon owns.
const NamespaceTable = "pmg"

// ifnameMax is IFNAMSIZ minus the terminating NUL.
const ifnameMax = 15

// NamespacePolicy describes the redirect at the bridge.
type NamespacePolicy struct {
	// Ingress are the interfaces whose incoming traffic is redirected. A
	// trailing * matches a prefix. Empty means DefaultNamespaceIngress.
	Ingress []string

	// Address is the IPv4 address the daemon adds to lo and listens on.
	// Unset means DefaultNamespaceAddress.
	Address netip.Addr

	// Ports are the destination ports to redirect. Empty means DefaultPorts.
	Ports []uint16

	// DenyUDP rejects forwarded UDP to the ports, so QUIC falls back to TCP.
	DenyUDP bool
}

// WithDefaults fills the empty fields.
func (p NamespacePolicy) WithDefaults() NamespacePolicy {
	if len(p.Ingress) == 0 {
		p.Ingress = slices.Clone(DefaultNamespaceIngress)
	}
	if !p.Address.IsValid() {
		p.Address = DefaultNamespaceAddress
	}
	if len(p.Ports) == 0 {
		p.Ports = slices.Clone(DefaultPorts)
	}
	return p
}

// Validate rejects a policy the kernel cannot express. It judges the
// fields as they are, so the caller fills defaults first.
func (p NamespacePolicy) Validate() error {
	if len(p.Ingress) == 0 {
		return errors.New("enforce: namespaces ingress names no interface")
	}
	for _, name := range p.Ingress {
		if err := validateIfname(name); err != nil {
			return err
		}
	}
	if !p.Address.Is4() || p.Address.IsLoopback() || p.Address.IsUnspecified() || p.Address.IsMulticast() {
		return fmt.Errorf("enforce: namespaces address %q must be an IPv4 unicast address outside loopback", p.Address)
	}
	if len(p.Ports) == 0 {
		return errors.New("enforce: namespaces redirects no port")
	}
	for _, port := range p.Ports {
		if port == 0 {
			return errors.New("enforce: port 0 is not a valid destination port")
		}
	}
	return nil
}

func validateIfname(name string) error {
	if name == "" {
		return errors.New("enforce: namespaces ingress has an empty interface name")
	}
	if len(name) > ifnameMax {
		return fmt.Errorf("enforce: namespaces ingress %q is longer than %d characters", name, ifnameMax)
	}
	if i := strings.IndexByte(name, '*'); i >= 0 && i != len(name)-1 {
		return fmt.Errorf("enforce: namespaces ingress %q may end with * but not contain it", name)
	}
	if name == "*" || strings.ContainsAny(name, " /\t\n") {
		return fmt.Errorf("enforce: namespaces ingress %q is not an interface name", name)
	}
	return nil
}

// NamespaceStatus is the loaded redirect, for the state file.
type NamespaceStatus struct {
	Address string   `json:"address"`
	Port    uint16   `json:"port"`
	Ingress []string `json:"ingress"`
	Ports   []uint16 `json:"ports"`
	DenyUDP bool     `json:"deny_udp"`
}

// Target returns the listener address and port.
func (s NamespaceStatus) Target() string {
	return s.Address + ":" + strconv.Itoa(int(s.Port))
}

// NamespaceHandle is one loaded redirect table.
type NamespaceHandle interface {
	// Status describes the loaded table.
	Status() NamespaceStatus

	// Close deletes the table. The kernel does the same when the daemon's
	// netlink socket closes, so a crash never leaves rules behind.
	Close() error
}

// NamespaceRedirector loads the redirect at the bridge. The kernel side is
// nftables, and the daemon's listener on the address does the rest.
type NamespaceRedirector interface {
	// Probe reports whether this host can redirect, and what is missing.
	Probe() ProbeResult

	// EnsureAddress adds the address to lo as a /32. It is a no-op when lo
	// already has it, and an error when another interface has it.
	EnsureAddress(addr netip.Addr) error

	// RemoveAddress removes the address from lo. A missing address is not
	// an error.
	RemoveAddress(addr netip.Addr) error

	// Attach loads the table that sends the policy's ports from the ingress
	// interfaces to the address on port. The policy is complete, as
	// WithDefaults leaves it. It fails with ErrNamespaceTableOwned when
	// another daemon owns the table.
	Attach(ctx context.Context, port uint16, p NamespacePolicy) (NamespaceHandle, error)
}

// ErrNamespaceUnsupported is returned by NewNamespaceRedirector on every
// platform but Linux.
var ErrNamespaceUnsupported = errors.New("namespace redirect is only supported on Linux")

// ErrNamespaceTableOwned means another live process owns the pmg table,
// which is a second daemon.
var ErrNamespaceTableOwned = errors.New("enforce: another process owns the pmg nftables table")

// NewNamespaceRedirector returns the redirector for this platform.
func NewNamespaceRedirector() (NamespaceRedirector, error) {
	return newPlatformNamespaceRedirector()
}
