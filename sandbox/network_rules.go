package sandbox

import (
	"slices"

	"github.com/safedep/dry/utils"
	"github.com/safedep/pmg/proxy/netpolicy"
)

// Compile turns the block into the policy the proxy decides with. Every
// enforcement point calls it, so the key semantics live in one place.
func (n NetworkPolicy) Compile() (*netpolicy.Policy, error) {
	var opts []netpolicy.Option
	if utils.SafelyGetValue(n.DenyIPLiterals) {
		opts = append(opts, netpolicy.DenyIPLiterals())
	}
	return netpolicy.New(n.AllowOutbound, n.DenyOutbound, opts...)
}

// Allow adds rule to the allow list and drops the equal deny rule. At equal
// specificity deny wins, so an allow that leaves the deny in place would
// not decide. Two rules are equal as the matcher reads them, so a case or
// a trailing dot does not tell them apart.
func (n *NetworkPolicy) Allow(rule string) {
	n.AllowOutbound = append(n.AllowOutbound, rule)
	n.DenyOutbound = slices.DeleteFunc(n.DenyOutbound, func(entry string) bool { return sameRule(entry, rule) })
}

// Deny adds rule to the deny list.
func (n *NetworkPolicy) Deny(rule string) {
	n.DenyOutbound = append(n.DenyOutbound, rule)
}

func sameRule(a, b string) bool {
	ra, errA := netpolicy.ParseRule(a)
	rb, errB := netpolicy.ParseRule(b)
	if errA != nil || errB != nil {
		return a == b
	}
	return ra.Host == rb.Host && ra.Port == rb.Port && ra.Client == rb.Client
}

// HasNonNetworkRules reports whether the policy carries filesystem,
// process or environment rules, which only a sandbox applies.
func (p *SandboxPolicy) HasNonNetworkRules() bool {
	fs, proc, env := p.Filesystem, p.Process, p.Environment
	return len(fs.AllowRead)+len(fs.AllowWrite)+len(fs.DenyRead)+len(fs.DenyWrite) > 0 ||
		len(proc.AllowExec)+len(proc.DenyExec) > 0 ||
		len(env.Allow)+len(env.Deny) > 0
}
