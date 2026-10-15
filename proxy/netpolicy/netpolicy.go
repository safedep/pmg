// Package netpolicy decides whether a connection to a host and port is
// allowed by the network rules of a sandbox profile. The proxy and the
// sandbox linter share it, so the package depends on neither.
//
// A rule is "host:port". The grammar also has a client part,
// "<exe>=host:port", that the proxy cannot match yet, so ParseRule rejects
// it. The most specific matching rule wins. An exact host beats a wildcard, a
// longer wildcard suffix beats a shorter one, and every host rule beats "*".
// At equal host specificity an exact port beats "*". At equal specificity
// deny wins. With no matching rule the connection is allowed, so a profile
// that wants an allow list denies "*:*".
package netpolicy

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const (
	anyHost = "*"
	anyPort = 0

	// A name is at most 253 characters and a label at most 63 (RFC 1035).
	maxHostLen  = 253
	maxLabelLen = 63

	exactHostRank = 1 << 16
)

// Rule is one parsed allow or deny entry.
type Rule struct {
	// Raw is the rule as the profile wrote it.
	Raw string

	// Client is the executable the rule applies to: an absolute path or a
	// bare program name. Empty applies to every client.
	Client string

	// Host is the normalized host: lower case, no trailing dot, an IP
	// literal in canonical form, "*" or "*.suffix".
	Host string

	// Port is the port, or 0 for "*".
	Port uint16

	// Deny is true for a deny_outbound entry.
	Deny bool
}

// RuleError reports a rule that does not parse, with the list it came from.
type RuleError struct {
	List   string
	Rule   string
	Reason string
}

func (e *RuleError) Error() string {
	if e.List == "" {
		return fmt.Sprintf("rule %q %s", e.Rule, e.Reason)
	}
	return fmt.Sprintf("%s: rule %q %s", e.List, e.Rule, e.Reason)
}

// Decision is the outcome for one host and port.
type Decision struct {
	Allowed bool

	// Rule is the rule that decided, or nil when no rule matched.
	Rule *Rule
}

// Policy holds the parsed rules of one profile.
type Policy struct {
	rules []Rule
}

// ParseRule parses one rule. It does not know which list the rule came from,
// so Deny is false. The proxy has no client for a connection yet, so a rule
// with a client part is an error and not a rule that never matches.
func ParseRule(raw string) (Rule, error) {
	rule, err := parseRule(raw)
	if err != nil {
		return Rule{}, err
	}
	if rule.Client != "" {
		return Rule{}, &RuleError{Rule: raw, Reason: "names a client, which the proxy cannot match yet"}
	}
	return rule, nil
}

func parseRule(raw string) (Rule, error) {
	rule := Rule{Raw: raw}

	rest := raw
	if idx := strings.Index(rest, "="); idx >= 0 {
		client := strings.TrimSpace(rest[:idx])
		rest = rest[idx+1:]
		if client == "" {
			return Rule{}, &RuleError{Rule: raw, Reason: "has an empty client before \"=\""}
		}
		if strings.ContainsAny(client, "\t\n*") || isRelativePath(client) {
			return Rule{}, &RuleError{Rule: raw, Reason: "has an invalid client before \"=\" (use an absolute path or a bare program name)"}
		}
		rule.Client = client
	}

	host, portStr, err := net.SplitHostPort(rest)
	if err != nil {
		return Rule{}, &RuleError{Rule: raw, Reason: "is not host:port"}
	}

	normalizedHost, err := normalizeRuleHost(host)
	if err != nil {
		return Rule{}, &RuleError{Rule: raw, Reason: err.Error()}
	}
	rule.Host = normalizedHost

	if portStr == anyHost {
		rule.Port = anyPort
		return rule, nil
	}

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return Rule{}, &RuleError{Rule: raw, Reason: "has an invalid port"}
	}
	rule.Port = uint16(port)

	return rule, nil
}

// New parses the allow and deny lists of a profile. The first invalid rule
// is returned as a *RuleError that names its list.
func New(allow, deny []string) (*Policy, error) {
	policy := &Policy{rules: make([]Rule, 0, len(allow)+len(deny))}

	for _, raw := range allow {
		rule, err := parseListRule("network.allow_outbound", raw)
		if err != nil {
			return nil, err
		}
		policy.rules = append(policy.rules, rule)
	}

	for _, raw := range deny {
		rule, err := parseListRule("network.deny_outbound", raw)
		if err != nil {
			return nil, err
		}
		rule.Deny = true
		policy.rules = append(policy.rules, rule)
	}

	return policy, nil
}

func parseListRule(list, raw string) (Rule, error) {
	rule, err := ParseRule(raw)
	var ruleErr *RuleError
	if errors.As(err, &ruleErr) {
		ruleErr.List = list
		return Rule{}, ruleErr
	}
	return rule, err
}

// Rules returns the parsed rules, allow entries first, in profile order.
func (p *Policy) Rules() []Rule {
	if p == nil {
		return nil
	}
	return append([]Rule(nil), p.rules...)
}

// Decide returns the decision for a connection to host and port. A nil
// policy allows every connection.
func (p *Policy) Decide(host string, port uint16) Decision {
	if p == nil {
		return Decision{Allowed: true}
	}

	host = NormalizeHost(host)

	var best *Rule
	for i := range p.rules {
		rule := &p.rules[i]
		if !rule.matches(host, port) {
			continue
		}
		if best == nil || rule.beats(best) {
			best = rule
		}
	}

	if best == nil {
		return Decision{Allowed: true}
	}

	return Decision{Allowed: !best.Deny, Rule: best}
}

// NormalizeHost lowers the case, drops a trailing dot and brackets, and
// writes an IP literal in canonical form, so a rule and a connection
// compare as equal strings.
func NormalizeHost(host string) string {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap().String()
	}
	return host
}

func (r *Rule) matches(host string, port uint16) bool {
	if r.Port != anyPort && r.Port != port {
		return false
	}
	if r.Host == anyHost {
		return true
	}
	if suffix, ok := strings.CutPrefix(r.Host, "*."); ok {
		// A wildcard names labels, and an address has none, so "*.3.4"
		// never matches 1.2.3.4.
		if isAddress(host) {
			return false
		}
		return strings.HasSuffix(host, "."+suffix)
	}
	return r.Host == host
}

func isAddress(host string) bool {
	_, err := netip.ParseAddr(host)
	return err == nil
}

// isRelativePath reports a client with a path separator that is not an
// absolute path. The proxy has no base to resolve it against.
func isRelativePath(client string) bool {
	if !strings.ContainsAny(client, `/\`) {
		return false
	}
	if strings.HasPrefix(client, "/") {
		return false
	}
	isDrivePath := len(client) > 2 && client[1] == ':' && (client[2] == '\\' || client[2] == '/')
	return !isDrivePath
}

// beats says whether r is more specific than other, or as specific and a
// deny while other is an allow.
func (r *Rule) beats(other *Rule) bool {
	if a, b := r.hostRank(), other.hostRank(); a != b {
		return a > b
	}
	if a, b := r.portRank(), other.portRank(); a != b {
		return a > b
	}
	return r.Deny && !other.Deny
}

func (r *Rule) hostRank() int {
	switch {
	case r.Host == anyHost:
		return 0
	case strings.HasPrefix(r.Host, "*."):
		return strings.Count(r.Host, ".")
	default:
		return exactHostRank
	}
}

func (r *Rule) portRank() int {
	if r.Port == anyPort {
		return 0
	}
	return 1
}

func normalizeRuleHost(host string) (string, error) {
	if strings.TrimSpace(host) == anyHost {
		return anyHost, nil
	}
	host = NormalizeHost(host)
	if host == "" {
		return "", fmt.Errorf("has an empty host")
	}
	if host == anyHost {
		return "", fmt.Errorf("has an invalid host")
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return "", fmt.Errorf("has an invalid host")
		}
		return host, nil
	}

	name, wildcard := strings.CutPrefix(host, "*.")
	if err := validateName(name); err != nil {
		return "", err
	}
	if wildcard {
		return "*." + name, nil
	}
	return name, nil
}

func validateName(name string) error {
	if name == "" || len(name) > maxHostLen {
		return fmt.Errorf("has an invalid host")
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > maxLabelLen || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("has an invalid host")
		}
		for _, c := range label {
			if !isLabelChar(c) {
				return fmt.Errorf("has an invalid host")
			}
		}
	}
	return nil
}

func isLabelChar(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}
