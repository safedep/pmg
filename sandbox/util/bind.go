package util

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// BindAddress is one entry of network.allow_bind or of net-bind: the address
// that a sandboxed process may listen on. The CLI, the profile and preset
// checks and the drivers all parse an entry with ParseBindAddress, so a value
// that one of them accepts is never refused by another.
type BindAddress struct {
	Host string
	Port string
}

// ParseBindAddress parses host:port. The host is loopback (localhost,
// 127.0.0.1, [::1]) or all interfaces (0.0.0.0, [::]). The port is a number
// from 1 to 65535, or * for any port.
//
// Other hosts are refused because no driver can keep a bind to one of them.
// Seatbelt accepts only localhost or * as the host, and Landlock cannot check
// the host of a bind, so the entry would allow more than it names.
func ParseBindAddress(entry string) (BindAddress, error) {
	host, port, err := net.SplitHostPort(entry)
	if err != nil {
		return BindAddress{}, fmt.Errorf("expected host:port, with an IPv6 host in brackets (e.g., localhost:3000 or [::1]:3000), got %q", entry)
	}
	if host == "" {
		return BindAddress{}, fmt.Errorf("missing host in %q", entry)
	}
	if ContainsGlob(host) {
		return BindAddress{}, fmt.Errorf("host wildcards are not allowed in %q (specify a host, e.g., localhost:3000)", entry)
	}
	if port != "*" {
		if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
			return BindAddress{}, fmt.Errorf("port %q in %q must be a number from 1 to 65535 or *", port, entry)
		}
	}
	addr := BindAddress{Host: strings.ToLower(host), Port: port}
	if !addr.IsLoopback() && !addr.IsAllInterfaces() {
		return BindAddress{}, fmt.Errorf("host %q in %q must be loopback (localhost, 127.0.0.1, [::1]) or all interfaces (0.0.0.0, [::])", host, entry)
	}
	return addr, nil
}

// IsLoopback reports whether only the local machine can reach the address.
func (b BindAddress) IsLoopback() bool {
	switch b.Host {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

// IsAllInterfaces reports whether the address names every interface.
func (b BindAddress) IsAllInterfaces() bool {
	return b.Host == "0.0.0.0" || b.Host == "::"
}
