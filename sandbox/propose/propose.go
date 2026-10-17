// Package propose turns the destinations a run reached into the network
// block of a sandbox profile. It is one pure function. The CLI wraps it,
// and SafeDep Cloud can run it over synced events for a team-wide baseline.
package propose

import (
	"fmt"
	"slices"
	"sort"

	"github.com/safedep/dry/utils"
	"github.com/safedep/pmg/proxy/netpolicy"
	"github.com/safedep/pmg/sandbox"
)

// CatchAllDeny is the deny rule a proposed profile ends with, so a
// destination the profile does not name is refused.
const CatchAllDeny = "*:*"

// Input is what one proposal needs.
type Input struct {
	Destinations []netpolicy.Destination

	// Parent is the resolved profile the target inherits. Its allow rules
	// cover the registry hosts, so the proposal does not repeat them. nil
	// when the target inherits nothing.
	Parent *sandbox.SandboxPolicy

	// Existing is the target profile's own network block. nil for a new
	// profile.
	Existing *sandbox.NetworkPolicy
}

// Verdict says what the proposal does with one destination.
type Verdict string

const (
	// VerdictAdd proposes an allow rule for the destination.
	VerdictAdd Verdict = "add"
	// VerdictParentAllows leaves the destination to a parent allow rule.
	VerdictParentAllows Verdict = "parent allows"
	// VerdictAlreadyAllowed leaves the destination to an existing allow rule.
	VerdictAlreadyAllowed Verdict = "already allowed"
	// VerdictKeptDenied leaves a destination a specific deny rule of the
	// target or the parent refuses, because a rule a maintainer wrote is a
	// decision.
	VerdictKeptDenied Verdict = "kept denied"
	// VerdictRefused skips a destination the run refused under enforce.
	// The program never reached it, so the run is no evidence that it
	// needs an allow rule. A probe by a compromised tool must not become
	// a rule.
	VerdictRefused Verdict = "refused"
	// VerdictInvalid skips a destination the rule parser does not read as
	// host:port. The proxy observes what a client asked for, and a client
	// can ask for a host no rule can name.
	VerdictInvalid Verdict = "not a valid rule"
)

// Row is one destination with the proposal's verdict.
type Row struct {
	netpolicy.Destination
	Verdict Verdict `json:"verdict"`
	// Rule is the allow rule the proposal adds, or the existing rule that
	// decided.
	Rule string `json:"proposed_rule,omitempty"`
}

// Result is the network block to write and how each destination fared.
type Result struct {
	// Network is the target's full network block: the existing rules first
	// in their order, then the new allow rules sorted, then the catch-all
	// deny when nothing in the chain has it.
	Network sandbox.NetworkPolicy `json:"network"`

	// Added are the allow rules the proposal adds, sorted.
	Added []string `json:"added"`

	Rows []Row `json:"destinations"`
}

// Network builds the proposal. It does not remove a rule, because one run
// does not see every path. An allow rule for every host, in the parent or
// in the target, covers nothing here: the catch-all deny the proposal adds
// beats it, so each destination still needs its own allow rule.
//
// The verdict comes from the union of the parent's and the target's rules,
// because the loader unions them and enforcement decides on that union.
func Network(in Input) (Result, error) {
	parent := sandbox.NetworkPolicy{}
	if in.Parent != nil {
		parent = in.Parent.Network
		if _, err := parent.Compile(); err != nil {
			return Result{}, fmt.Errorf("parent profile %s: %w", in.Parent.Name, err)
		}
	}
	existing := sandbox.NetworkPolicy{}
	if in.Existing != nil {
		existing = *in.Existing
		if _, err := existing.Compile(); err != nil {
			return Result{}, fmt.Errorf("target profile: %w", err)
		}
	}

	// A proposal turns on the IP literal denial, because an attacker who
	// finds a name denied connects to the address next. A target that set
	// the key keeps its value.
	denyIPLiterals := utils.PtrTo(true)
	if existing.DenyIPLiterals != nil {
		denyIPLiterals = utils.PtrTo(*existing.DenyIPLiterals)
	}

	// The verdicts come from the block the proposal writes, so an address
	// a port-wide allow covers still gets its exact rule when the key
	// denies it.
	rules, err := sandbox.NetworkPolicy{
		AllowOutbound:  union(parent.AllowOutbound, existing.AllowOutbound),
		DenyOutbound:   union(parent.DenyOutbound, existing.DenyOutbound),
		DenyIPLiterals: denyIPLiterals,
	}.Compile()
	if err != nil {
		return Result{}, fmt.Errorf("parent and target profile: %w", err)
	}

	result := Result{Network: sandbox.NetworkPolicy{
		AllowOutbound:  slices.Clone(existing.AllowOutbound),
		DenyOutbound:   slices.Clone(existing.DenyOutbound),
		AllowBind:      slices.Clone(existing.AllowBind),
		DenyIPLiterals: denyIPLiterals,
	}}

	added := map[string]bool{}
	for _, d := range in.Destinations {
		row := Row{Destination: d, Verdict: VerdictAdd, Rule: d.Address()}
		if _, err := netpolicy.ParseRule(row.Rule); err != nil {
			row.Verdict, row.Rule = VerdictInvalid, ""
			result.Rows = append(result.Rows, row)
			continue
		}
		rule := rules.Decide(d.Host, d.Port).Rule
		switch {
		case rule != nil && rule.Deny && !isCatchAll(rule) && rule.Raw != netpolicy.IPLiteralRule:
			row.Verdict, row.Rule = VerdictKeptDenied, rule.Raw
		case d.Enforced && !d.Allowed:
			row.Verdict, row.Rule = VerdictRefused, d.Rule
		case rule == nil || isCatchAll(rule) || rule.Raw == netpolicy.IPLiteralRule:
			added[row.Rule] = true
		case slices.Contains(existing.AllowOutbound, rule.Raw):
			row.Verdict, row.Rule = VerdictAlreadyAllowed, rule.Raw
		default:
			row.Verdict, row.Rule = VerdictParentAllows, rule.Raw
		}
		result.Rows = append(result.Rows, row)
	}

	for rule := range added {
		result.Added = append(result.Added, rule)
	}
	sort.Strings(result.Added)
	result.Network.AllowOutbound = append(result.Network.AllowOutbound, result.Added...)

	if !deniesCatchAll(existing.DenyOutbound) && (in.Parent == nil || !deniesCatchAll(in.Parent.Network.DenyOutbound)) {
		result.Network.DenyOutbound = append(result.Network.DenyOutbound, CatchAllDeny)
	}
	return result, nil
}

func union(a, b []string) []string {
	out := make([]string, 0, len(a)+len(b))
	for _, rule := range slices.Concat(a, b) {
		if !slices.Contains(out, rule) {
			out = append(out, rule)
		}
	}
	return out
}

func isCatchAll(rule *netpolicy.Rule) bool {
	return rule.Host == "*" && rule.Port == 0 && rule.Client == ""
}

func deniesCatchAll(deny []string) bool {
	for _, raw := range deny {
		if rule, err := netpolicy.ParseRule(raw); err == nil && isCatchAll(&rule) {
			return true
		}
	}
	return false
}
