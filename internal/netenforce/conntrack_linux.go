//go:build linux

package netenforce

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"

	"github.com/safedep/dry/log"
	"golang.org/x/sys/unix"
)

// ConntrackOriginalDestination asks conntrack where a DNAT'd client wanted
// to connect. The lookup key is the socket's own four-tuple, which the
// kernel reads from the socket, so no record from the client's namespace
// is needed. A connection that was not translated reports its own local
// address, which counts as a miss.
func ConntrackOriginalDestination(c net.Conn) (netip.AddrPort, bool) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return netip.AddrPort{}, false
	}
	local, ok := tc.LocalAddr().(*net.TCPAddr)
	if !ok || !local.AddrPort().Addr().Unmap().Is4() {
		return netip.AddrPort{}, false
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		log.Debugf("enforce: conntrack lookup for %s: %v", c.RemoteAddr(), err)
		return netip.AddrPort{}, false
	}

	var orig netip.AddrPort
	var gerr error
	cerr := raw.Control(func(fd uintptr) {
		m, err := unix.GetsockoptIPv6Mreq(int(fd), unix.SOL_IP, unix.SO_ORIGINAL_DST)
		if err != nil {
			gerr = err
			return
		}
		port := binary.BigEndian.Uint16(m.Multiaddr[2:4])
		orig = netip.AddrPortFrom(netip.AddrFrom4([4]byte(m.Multiaddr[4:8])), port)
	})
	if err := errors.Join(cerr, gerr); err != nil {
		// ENOENT is a connection conntrack never saw, which is normal for a
		// client on loopback. Anything else is worth a look.
		if !errors.Is(err, unix.ENOENT) {
			log.Debugf("enforce: conntrack lookup for %s: %v", c.RemoteAddr(), err)
		}
		return netip.AddrPort{}, false
	}
	if !orig.IsValid() {
		return netip.AddrPort{}, false
	}
	if orig == netip.AddrPortFrom(local.AddrPort().Addr().Unmap(), uint16(local.Port)) {
		return netip.AddrPort{}, false
	}
	return orig, true
}
