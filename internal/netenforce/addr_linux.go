//go:build linux

package netenforce

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const loopbackName = "lo"

// ensureAddress adds addr/32 to lo. lo already carrying it, for instance
// after a crash, is fine. Another interface carrying it is a conflict the
// operator resolves with the address key.
func ensureAddress(addr netip.Addr) error {
	owner, err := interfaceWithAddress(addr)
	if err != nil {
		return err
	}
	switch owner {
	case loopbackName:
		return nil
	case "":
	default:
		return fmt.Errorf("enforce: namespaces address %s is already on interface %s, set another with proxy.server.enforce.namespaces.address", addr, owner)
	}
	err = changeAddress(unix.RTM_NEWADDR, netlink.Request|netlink.Acknowledge|netlink.Create|netlink.Excl, addr)
	if err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("enforce: add %s to %s: %w", addr, loopbackName, err)
	}
	return nil
}

func removeAddress(addr netip.Addr) error {
	err := changeAddress(unix.RTM_DELADDR, netlink.Request|netlink.Acknowledge, addr)
	if err != nil && !errors.Is(err, unix.EADDRNOTAVAIL) && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("enforce: remove %s from %s: %w", addr, loopbackName, err)
	}
	return nil
}

// interfaceWithAddress returns the name of the interface that has addr, or
// "" when none does.
func interfaceWithAddress(addr netip.Addr) (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("enforce: list interfaces: %w", err)
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return "", fmt.Errorf("enforce: list addresses of %s: %w", iface.Name, err)
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if got, ok := netip.AddrFromSlice(ipn.IP); ok && got.Unmap() == addr {
				return iface.Name, nil
			}
		}
	}
	return "", nil
}

// changeAddress sends one RTM_NEWADDR or RTM_DELADDR for addr/32 on lo.
func changeAddress(msgType uint16, flags netlink.HeaderFlags, addr netip.Addr) error {
	lo, err := net.InterfaceByName(loopbackName)
	if err != nil {
		return err
	}
	conn, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	// struct ifaddrmsg: family, prefixlen, flags, scope, index.
	hdr := make([]byte, 8)
	hdr[0] = unix.AF_INET
	hdr[1] = 32
	hdr[3] = unix.RT_SCOPE_UNIVERSE
	binary.NativeEndian.PutUint32(hdr[4:], uint32(lo.Index))

	ae := netlink.NewAttributeEncoder()
	a4 := addr.As4()
	ae.Bytes(unix.IFA_LOCAL, a4[:])
	ae.Bytes(unix.IFA_ADDRESS, a4[:])
	attrs, err := ae.Encode()
	if err != nil {
		return err
	}

	_, err = conn.Execute(netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(msgType), Flags: flags},
		Data:   append(hdr, attrs...),
	})
	return err
}
