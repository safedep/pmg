package flows

import (
	"net"
	"slices"
	"strconv"
	"sync"

	"github.com/safedep/pmg/proxy"
	"github.com/safedep/pmg/sandbox"
	"github.com/safedep/pmg/sandbox/executor"
)

// egressRecorder adapts the sandbox outbound matcher to the proxy egress
// policy. It keeps each denied destination for the end-of-run report.
type egressRecorder struct {
	matcher *sandbox.OutboundMatcher

	mu     sync.Mutex
	denied map[string]struct{}
}

func newEgressRecorder(m *sandbox.OutboundMatcher) *egressRecorder {
	return &egressRecorder{matcher: m, denied: map[string]struct{}{}}
}

func (r *egressRecorder) Allows(host string, port uint16) bool {
	if r.matcher.Allows(host, port) {
		return true
	}

	r.mu.Lock()
	r.denied[net.JoinHostPort(host, strconv.Itoa(int(port)))] = struct{}{}
	r.mu.Unlock()
	return false
}

// egressPolicyFor returns the proxy egress policy for a resolved sandbox
// policy. Both values are nil when the policy does not enforce outbound
// rules. The interface is a real nil then, so the proxy enforces nothing.
func egressPolicyFor(res *executor.Resolution) (*egressRecorder, proxy.EgressPolicy) {
	if res == nil || res.Outbound == nil {
		return nil, nil
	}

	r := newEgressRecorder(res.Outbound)
	return r, r
}

// Denied returns the denied destinations as sorted host:port values.
func (r *egressRecorder) Denied() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]string, 0, len(r.denied))
	for d := range r.denied {
		out = append(out, d)
	}
	slices.Sort(out)
	return out
}
