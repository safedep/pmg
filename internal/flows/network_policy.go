package flows

import (
	"cmp"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/audit"
	"github.com/safedep/pmg/internal/eventlog"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/proxy"
	"github.com/safedep/pmg/proxy/interceptors"
	"github.com/safedep/pmg/proxy/netpolicy"
	"github.com/safedep/pmg/sandbox"
	"github.com/safedep/pmg/sandbox/executor"
)

// NetworkDecisionLog records every destination the proxy decides. A match
// on a deny rule goes to the audit log as well. The log keeps one line per
// destination for the report and the run's observation. The daemon keys
// the lines by client too, so its report names the program behind each one.
type NetworkDecisionLog struct {
	mu           sync.Mutex
	byClient     bool
	enforced     bool
	now          func() time.Time
	destinations map[string]*netpolicy.Destination
}

func NewNetworkDecisionLog(byClient bool) *NetworkDecisionLog {
	return &NetworkDecisionLog{byClient: byClient, now: time.Now, destinations: map[string]*netpolicy.Destination{}}
}

func (l *NetworkDecisionLog) Record(d proxy.NetworkDecision) {
	entryPoint, client := interceptors.AuditClient(d.Origin)
	if !d.Allowed {
		audit.LogNetworkPolicy(audit.NetworkDecision{
			Hostname:   d.Host,
			Port:       d.Port,
			Rule:       d.Rule,
			Enforced:   d.Enforced,
			EntryPoint: entryPoint,
			Client:     client,
		})
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if !d.Allowed {
		l.enforced = d.Enforced
	}
	key := net.JoinHostPort(d.Host, strconv.Itoa(int(d.Port)))
	if l.byClient {
		key += "\x00" + clientLabel(d.Origin) + "\x00" + strconv.FormatUint(uint64(d.Origin.PID), 10)
	}
	seen := l.now()
	if dest, ok := l.destinations[key]; ok {
		dest.Count++
		dest.LastSeen = seen
		dest.Allowed = d.Allowed
		dest.Rule = d.Rule
		dest.Enforced = d.Enforced
		return
	}
	l.destinations[key] = &netpolicy.Destination{
		Host:      d.Host,
		Port:      d.Port,
		Client:    clientLabel(d.Origin),
		PID:       int(d.Origin.PID),
		Count:     1,
		FirstSeen: seen,
		LastSeen:  seen,
		Allowed:   d.Allowed,
		Rule:      d.Rule,
		Enforced:  d.Enforced,
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
func (l *NetworkDecisionLog) Report() *netpolicy.Report {
	var report *netpolicy.Report
	for _, d := range l.sorted() {
		if d.Allowed {
			continue
		}
		if report == nil {
			report = &netpolicy.Report{Enforced: l.enforced}
		}
		report.Denials = append(report.Denials, netpolicy.Denial{
			Destination: d.Address(),
			Rule:        d.Rule,
			Client:      d.Client,
			PID:         d.PID,
			Count:       d.Count,
		})
	}
	return report
}

// Observation returns every destination of the run under the keys a later
// command finds it by. The table keeps one row per process for the denial
// report. The observation folds the processes of one client into one row,
// so a long run with many processes stays small.
func (l *NetworkDecisionLog) Observation(runID, repoRoot, packageManager, profile, mode string) netpolicy.Observation {
	return netpolicy.Observation{
		RunID:          runID,
		RepoRoot:       repoRoot,
		PackageManager: packageManager,
		Profile:        profile,
		Mode:           mode,
		Destinations:   netpolicy.Fold(l.sorted()),
	}
}

func (l *NetworkDecisionLog) sorted() []netpolicy.Destination {
	l.mu.Lock()
	defer l.mu.Unlock()

	out := make([]netpolicy.Destination, 0, len(l.destinations))
	for _, d := range l.destinations {
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		if a.Client != b.Client {
			return a.Client < b.Client
		}
		return a.PID < b.PID
	})
	return out
}

// NetworkOutcome is what a run's report shows about the network policy:
// the denials, and the run id and destination count that point at the
// proposal command. RunID is empty when the run has no event log.
type NetworkOutcome struct {
	Report   *netpolicy.Report
	RunID    string
	Observed int
}

// networkRun is the network side of one proxied run: the decision log and
// the run id, from the first decision to the record at the end. The
// package manager proxy and the exec proxy share it.
type networkRun struct {
	log   *networkDecisionLog
	runID string
	res   *executor.Resolution
}

func newNetworkRun(res *executor.Resolution) *networkRun {
	return &networkRun{log: newNetworkDecisionLog(res), runID: netpolicy.NewRunID(), res: res}
}

func (r *networkRun) record(d proxy.NetworkDecision) { r.log.Record(d) }

// finish records the refused destinations as violations and the run's
// observation in the event log. Call it after the proxy stopped, so a
// decision made while the child exits is in the record.
func (r *networkRun) finish() NetworkOutcome {
	r.log.observeViolations()
	observation := r.log.observation(r.runID, r.res)
	audit.LogNetworkObservation(observation)

	out := NetworkOutcome{Report: r.log.Report(), Observed: len(observation.Destinations)}
	if eventlog.Dir() != "" {
		out.RunID = r.runID
	}
	return out
}

// applyNetworkPolicy gives the proxy the network block of the resolution.
// A run with no sandbox has no policy, and the proxy then allows every
// destination and still reports each one.
func applyNetworkPolicy(cfg *proxy.ProxyConfig, res *executor.Resolution) {
	if res == nil || res.Network == nil {
		return
	}
	cfg.NetworkPolicy = res.Network
	cfg.NetworkEnforce = res.NetworkMode == config.SandboxNetworkModeEnforce
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

// observation keys the run's destinations by the repository the command
// ran in, as the overlay does, so a later proposal finds the runs of one
// repository.
func (l *networkDecisionLog) observation(runID string, res *executor.Resolution) netpolicy.Observation {
	mode := ""
	if res != nil {
		mode = res.NetworkMode
	}
	return l.Observation(runID, sandbox.RepoRootOfCwd(), l.packageManager, l.policyName, mode)
}

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
