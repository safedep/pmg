package util

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// BindAddress is one network.allow_bind or net-bind entry. Every check and
// every driver parses an entry with ParseBindAddress.
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
	if strings.HasPrefix(entry, "[") && !strings.Contains(host, ":") {
		return BindAddress{}, fmt.Errorf("only an IPv6 host goes in brackets, got %q", entry)
	}
	if ContainsGlob(host) {
		return BindAddress{}, fmt.Errorf("host wildcards are not allowed in %q (specify a host, e.g., localhost:3000)", entry)
	}
	if port != "*" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			return BindAddress{}, fmt.Errorf("port %q in %q must be a number from 1 to 65535 or *", port, entry)
		}
		port = strconv.FormatUint(n, 10)
	}
	addr := BindAddress{Host: strings.ToLower(host), Port: port}
	if !addr.IsLoopback() && !addr.IsAllInterfaces() {
		return BindAddress{}, fmt.Errorf("host %q in %q must be loopback (localhost, 127.0.0.1, [::1]) or all interfaces (0.0.0.0, [::])", host, entry)
	}
	return addr, nil
}

// String returns the entry in its normal form, as in localhost:3000 or
// [::1]:3000.
func (b BindAddress) String() string {
	return net.JoinHostPort(b.Host, b.Port)
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
