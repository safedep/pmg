//go:build !linux

package netenforce

import (
	"net"
	"net/netip"
)

func newPlatformNamespaceRedirector() (NamespaceRedirector, error) {
	return nil, ErrNamespaceUnsupported
}

// ConntrackOriginalDestination has no conntrack to ask off Linux.
func ConntrackOriginalDestination(net.Conn) (netip.AddrPort, bool) {
	return netip.AddrPort{}, false
}
