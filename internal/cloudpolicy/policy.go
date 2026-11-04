package cloudpolicy

import (
	"sync/atomic"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	recordv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/policy/record/v1"
	"github.com/safedep/dry/policy/match"
	"github.com/safedep/pmg/config"
)

// Policy does not change after it is built, so the proxy daemon can swap in
// a new one while requests read the old one.
type Policy struct {
	index *match.Index

	// Cooldown is dependency_cooldown after the cloud layer and the flags.
	Cooldown config.DependencyCooldownConfig

	cooldownCitation *recordv1.DecisionCitation
	applied          *AppliedHeader

	now func() time.Time
}

// AppliedHeader names the cloud policy that pmg applies.
type AppliedHeader struct {
	Tenant                string
	Digest                string
	Revision              uint64
	DefaultPolicyRevision uint64
}

// Source gives the policy that applies now. An interceptor reads Current for
// each request, because the proxy daemon swaps the policy after a fetch.
type Source interface {
	Current() *Policy
}

// RuleMatch is the package rule that decided. Applied and Citation are nil
// for a local rule.
type RuleMatch struct {
	Rule     match.Rule
	Applied  *AppliedHeader
	Citation *recordv1.DecisionCitation
}

// Cloud reports whether a cloud rule decided.
func (m RuleMatch) Cloud() bool {
	return m.Rule.Origin.Kind == match.OriginCloud
}

// Block returns the block entry that matches the package, from the cloud or
// from blocked_packages.
func (p *Policy) Block(ecosystem packagev1.Ecosystem, name, version string) (RuleMatch, bool) {
	d := p.decide(ecosystem, name, version, 0, match.VerdictNone)
	if d.Effect != match.EffectBlock {
		return RuleMatch{}, false
	}
	return p.ruleMatch(d.Rule), true
}

// TrustMalware returns the cloud trust entry with scope MALWARE that waives a
// malware verdict. For a verified verdict it returns none: the verified
// malware guard of match decides that.
func (p *Policy) TrustMalware(ecosystem packagev1.Ecosystem, name, version string, verified bool) (RuleMatch, bool) {
	verdict := match.VerdictMalware
	if verified {
		verdict = match.VerdictVerifiedMalware
	}
	return p.trust(ecosystem, name, version, match.ScopeMalware, verdict)
}

// TrustCooldown returns the cloud trust entry with scope COOLDOWN that
// exempts one version from the cooldown window.
func (p *Policy) TrustCooldown(ecosystem packagev1.Ecosystem, name, version string) (RuleMatch, bool) {
	return p.trust(ecosystem, name, version, match.ScopeCooldown, match.VerdictNone)
}

func (p *Policy) trust(ecosystem packagev1.Ecosystem, name, version string, control match.Scope, verdict match.Verdict) (RuleMatch, bool) {
	d := p.decide(ecosystem, name, version, control, verdict)
	if d.Effect != match.EffectTrust {
		return RuleMatch{}, false
	}
	return p.ruleMatch(d.Rule), true
}

func (p *Policy) decide(ecosystem packagev1.Ecosystem, name, version string, control match.Scope, verdict match.Verdict) match.Decision {
	if p == nil || p.index == nil || name == "" {
		return match.Decision{}
	}
	now := time.Now()
	if p.now != nil {
		now = p.now()
	}
	return p.index.Decide(match.Query{
		Package: packageOf(ecosystem, name, version),
		Control: control,
		Verdict: verdict,
		Now:     now,
	})
}

func (p *Policy) ruleMatch(rule match.Rule) RuleMatch {
	m := RuleMatch{Rule: rule}
	if m.Cloud() && p.applied != nil {
		m.Applied = p.applied
		m.Citation = ruleCitation(p.applied, rule.ID)
	}
	return m
}

// CooldownCitation cites the policy field that set the cooldown. It is nil
// when the cooldown comes from the tool baseline.
func (p *Policy) CooldownCitation() *recordv1.DecisionCitation {
	if p == nil {
		return nil
	}
	return p.cooldownCitation
}

// Applied names the cloud policy that pmg applies, or nil.
func (p *Policy) Applied() *AppliedHeader {
	if p == nil {
		return nil
	}
	return p.applied
}

// Rules returns the rules of the index, the cloud rules and the local rules.
func (p *Policy) Rules() []match.Rule {
	if p == nil || p.index == nil {
		return nil
	}
	return p.index.Rules()
}

// FromConfig returns the policy of cfg with no cloud layer.
func FromConfig(cfg *config.RuntimeConfig) *Policy {
	index, _ := newIndex(nil, cfg.BlockedRules())
	return &Policy{index: index, Cooldown: cfg.Config.DependencyCooldown}
}

// Static is a Source that always gives one policy.
type Static struct {
	Policy *Policy
}

func (s Static) Current() *Policy { return s.Policy }

// Runtime holds the policy of this process.
type Runtime struct {
	current atomic.Pointer[Policy]
	status  atomic.Pointer[Status]

	// baseline is dependency_cooldown before the cloud layer. A reload
	// applies a new cloud layer on top of it.
	baseline config.DependencyCooldownConfig

	// LoginTenant returns the tenant of the cloud login, or "" for no login.
	// When it is nil, the runtime reads the keychain. A test sets it, so a
	// developer who ran pmg cloud login gets the same result as CI.
	LoginTenant func() string
}

var global = &Runtime{}

// Global returns the policy holder of this process.
func Global() *Runtime {
	return global
}

// Current returns the policy that applies now. Before the root command
// published a policy, it derives one from the config at each call.
func (r *Runtime) Current() *Policy {
	if p := r.current.Load(); p != nil {
		return p
	}
	return FromConfig(config.Get())
}

// Status returns the state of the cloud policy that the last load found. It
// is nil before the first load.
func (r *Runtime) Status() *Status {
	return r.status.Load()
}
