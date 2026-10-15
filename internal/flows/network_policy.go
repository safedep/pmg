package flows

import (
	"net"
	"sort"
	"strconv"
	"sync"

	"github.com/safedep/pmg/internal/audit"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/proxy"
	"github.com/safedep/pmg/proxy/interceptors"
	"github.com/safedep/pmg/sandbox"
	"github.com/safedep/pmg/sandbox/executor"
)

// networkDecisionLog writes every network policy decision to the audit log
// and keeps one line per destination for the report.
type networkDecisionLog struct {
	mu         sync.Mutex
	policyName string
	enforced   bool
	denials    map[string]*ui.NetworkDenial
}

func newNetworkDecisionLog(res *executor.Resolution) *networkDecisionLog {
	l := &networkDecisionLog{denials: map[string]*ui.NetworkDenial{}}
	if res != nil && res.Policy != nil {
		l.policyName = res.Policy.Name
	}
	return l
}

func (l *networkDecisionLog) record(d proxy.NetworkDecision) {
	entryPoint, client := interceptors.AuditClient(d.Origin)
	audit.LogNetworkPolicy(audit.NetworkDecision{
		Hostname:   d.Host,
		Port:       d.Port,
		Rule:       d.Rule,
		Enforced:   d.Enforced,
		EntryPoint: entryPoint,
		Client:     client,
	})

	l.mu.Lock()
	defer l.mu.Unlock()

	l.enforced = d.Enforced
	destination := net.JoinHostPort(d.Host, strconv.Itoa(int(d.Port)))
	if denial, ok := l.denials[destination]; ok {
		denial.Count++
		return
	}
	l.denials[destination] = &ui.NetworkDenial{
		Destination: destination,
		Rule:        d.Rule,
		Client:      clientLabel(d.Origin),
		Count:       1,
	}
}

func clientLabel(o proxy.Origin) string {
	switch {
	case o.Exe != "":
		return o.Exe
	case o.Comm != "":
		return o.Comm
	case o.Address.IsValid():
		return o.Address.String()
	}
	return ""
}

func (l *networkDecisionLog) report() *ui.NetworkPolicyReport {
	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.denials) == 0 {
		return nil
	}

	report := &ui.NetworkPolicyReport{Enforced: l.enforced}
	for _, d := range l.denials {
		report.Denials = append(report.Denials, *d)
	}
	sort.Slice(report.Denials, func(i, j int) bool {
		return report.Denials[i].Destination < report.Denials[j].Destination
	})
	return report
}

// observeViolations records the refused destinations as sandbox violations.
// An audit decision is not a violation, because nothing was refused.
func (l *networkDecisionLog) observeViolations() {
	report := l.report()
	if report == nil || !report.Enforced {
		return
	}

	violations := make([]sandbox.Violation, 0, len(report.Denials))
	for _, d := range report.Denials {
		violations = append(violations, sandbox.Violation{
			Kind:       sandbox.ViolationKindNetworkConnect,
			RawKind:    "network_policy",
			Target:     d.Destination,
			RuleTarget: d.Rule,
			Process:    d.Client,
		})
	}
	executor.ObserveNetworkDenials(l.policyName, violations)
}
