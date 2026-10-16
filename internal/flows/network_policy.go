package flows

import (
	"cmp"
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

// NetworkDecisionLog writes every network policy decision to the audit log
// and keeps one line per destination for the report. The daemon keys the
// lines by client as well, so its report names the program behind each one.
type NetworkDecisionLog struct {
	mu       sync.Mutex
	byClient bool
	enforced bool
	denials  map[string]*ui.NetworkDenial
}

func NewNetworkDecisionLog(byClient bool) *NetworkDecisionLog {
	return &NetworkDecisionLog{byClient: byClient, denials: map[string]*ui.NetworkDenial{}}
}

func (l *NetworkDecisionLog) Record(d proxy.NetworkDecision) {
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
	key := destination
	if l.byClient {
		key += "\x00" + clientLabel(d.Origin) + "\x00" + strconv.FormatUint(uint64(d.Origin.PID), 10)
	}
	if denial, ok := l.denials[key]; ok {
		denial.Count++
		return
	}
	l.denials[key] = &ui.NetworkDenial{
		Destination: destination,
		Rule:        d.Rule,
		Client:      clientLabel(d.Origin),
		PID:         int(d.Origin.PID),
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

// Report returns the denials sorted by destination, then client. nil when
// no deny rule matched.
func (l *NetworkDecisionLog) Report() *ui.NetworkPolicyReport {
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
		a, b := report.Denials[i], report.Denials[j]
		if a.Destination != b.Destination {
			return a.Destination < b.Destination
		}
		if a.Client != b.Client {
			return a.Client < b.Client
		}
		return a.PID < b.PID
	})
	return report
}

// networkDecisionLog is the one-shot proxy's log. It knows the policy and
// the package manager, so a refused destination becomes a violation.
type networkDecisionLog struct {
	*NetworkDecisionLog
	policyName     string
	packageManager string
}

func newNetworkDecisionLog(res *executor.Resolution) *networkDecisionLog {
	l := &networkDecisionLog{NetworkDecisionLog: NewNetworkDecisionLog(false)}
	if res != nil {
		l.packageManager = res.PackageManager
		if res.Policy != nil {
			l.policyName = res.Policy.Name
		}
	}
	return l
}

func (l *networkDecisionLog) record(d proxy.NetworkDecision) { l.Record(d) }

// observeViolations records the refused destinations as sandbox violations.
// An audit decision is not a violation, because nothing was refused.
func (l *networkDecisionLog) observeViolations() {
	if violations := l.violations(); len(violations) > 0 {
		executor.ObserveNetworkDenials(l.policyName, violations)
	}
}

// violations returns one violation per refused destination. A proxy-aware
// client has no process attribution, and the package manager is the only
// client of the one-shot proxy, so its name stands in.
func (l *networkDecisionLog) violations() []sandbox.Violation {
	report := l.Report()
	if report == nil || !report.Enforced {
		return nil
	}

	violations := make([]sandbox.Violation, 0, len(report.Denials))
	for _, d := range report.Denials {
		violations = append(violations, sandbox.Violation{
			Kind:       sandbox.ViolationKindNetworkConnect,
			RawKind:    string(audit.EventTypeNetworkPolicy),
			Target:     d.Destination,
			RuleTarget: d.Rule,
			RuleLabel:  ui.NetworkDenialMessage(d.Destination, d.Rule),
			Process:    cmp.Or(d.Client, l.packageManager),
		})
	}
	return violations
}
