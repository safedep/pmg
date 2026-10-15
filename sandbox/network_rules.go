package sandbox

import "slices"

// Allow adds rule to the allow list and drops an equal deny rule. At equal
// specificity deny wins, so an allow that leaves the deny in place would
// not decide.
func (n *NetworkPolicy) Allow(rule string) {
	n.AllowOutbound = append(n.AllowOutbound, rule)
	n.DenyOutbound = slices.DeleteFunc(n.DenyOutbound, func(entry string) bool { return entry == rule })
}

// Deny adds rule to the deny list.
func (n *NetworkPolicy) Deny(rule string) {
	n.DenyOutbound = append(n.DenyOutbound, rule)
}

// HasNonNetworkRules reports whether the policy carries filesystem,
// process or environment rules, which only a sandbox applies.
func (p *SandboxPolicy) HasNonNetworkRules() bool {
	fs, proc, env := p.Filesystem, p.Process, p.Environment
	return len(fs.AllowRead)+len(fs.AllowWrite)+len(fs.DenyRead)+len(fs.DenyWrite) > 0 ||
		len(proc.AllowExec)+len(proc.DenyExec) > 0 ||
		len(env.Allow)+len(env.Deny) > 0
}
