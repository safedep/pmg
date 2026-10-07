package sandbox

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const outboundDenyAll = "*:*"

type outboundRule struct {
	host string
	port uint16
}

// OutboundMatcher decides whether a host:port destination is allowed by the
// network.allow_outbound and network.deny_outbound rules of a profile.
//
// A deny rule other than *:* wins. Then an allow rule allows. Otherwise the
// destination is denied when an allow list exists or *:* is denied. Hosts
// match as written. The matcher does not resolve DNS.
type OutboundMatcher struct {
	allow       []outboundRule
	deny        []outboundRule
	defaultDeny bool
}

func NewOutboundMatcher(n NetworkPolicy) (*OutboundMatcher, error) {
	m := &OutboundMatcher{defaultDeny: len(n.AllowOutbound) > 0}

	for _, raw := range n.DenyOutbound {
		if raw == outboundDenyAll {
			m.defaultDeny = true
			continue
		}
		rule, err := parseOutboundRule(raw)
		if err != nil {
			return nil, fmt.Errorf("network.deny_outbound: %w", err)
		}
		m.deny = append(m.deny, rule)
	}

	for _, raw := range n.AllowOutbound {
		rule, err := parseOutboundRule(raw)
		if err != nil {
			return nil, fmt.Errorf("network.allow_outbound: %w", err)
		}
		m.allow = append(m.allow, rule)
	}

	return m, nil
}

func (m *OutboundMatcher) Allows(host string, port uint16) bool {
	host = normalizeOutboundHost(host)

	for _, r := range m.deny {
		if r.matches(host, port) {
			return false
		}
	}
	for _, r := range m.allow {
		if r.matches(host, port) {
			return true
		}
	}
	return !m.defaultDeny
}

func parseOutboundRule(raw string) (outboundRule, error) {
	host, portStr, err := net.SplitHostPort(raw)
	if err != nil {
		return outboundRule{}, fmt.Errorf("rule %q is not host:port", raw)
	}

	if !validOutboundHost(host) {
		return outboundRule{}, fmt.Errorf("rule %q has an invalid host", raw)
	}
	host = normalizeOutboundHost(host)

	var port uint16
	if portStr != "*" {
		n, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil || n == 0 {
			return outboundRule{}, fmt.Errorf("rule %q has an invalid port", raw)
		}
		port = uint16(n)
	}

	return outboundRule{host: host, port: port}, nil
}

func validOutboundHost(host string) bool {
	if host == "*" {
		return true
	}
	rest, wildcard := strings.CutPrefix(host, "*.")
	rest = strings.TrimSuffix(rest, ".")
	if wildcard && strings.HasPrefix(rest, ".") {
		return false
	}
	return rest != "" && !strings.Contains(rest, "*")
}

func normalizeOutboundHost(host string) string {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap().String()
	}
	return host
}

func (r outboundRule) matches(host string, port uint16) bool {
	if r.port != 0 && r.port != port {
		return false
	}
	if r.host == "*" {
		return true
	}
	if suffix, ok := strings.CutPrefix(r.host, "*"); ok {
		return strings.HasSuffix(host, suffix)
	}
	return r.host == host
}
