// Package netenforce makes the kernel route the TCP connections of eligible
// processes to the PMG proxy. It defines the contract on every platform and
// implements it on Linux with cgroup BPF programs. The package knows nothing
// about HTTP or interceptors. internal/proxyserver wires it to the proxy.
package netenforce

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// ErrUnsupported is returned by New on every platform but Linux.
var ErrUnsupported = errors.New("network enforcement is only supported on Linux")

// DefaultPorts are the destination ports enforcement routes when the policy
// names none.
var DefaultPorts = []uint16{80, 443}

// Policy describes which connections the kernel routes to the proxy. Users
// write it in terms they can know in advance: ports, users and executable
// paths. There is no pid in the policy.
type Policy struct {
	// Ports are the destination ports to route. Empty means DefaultPorts.
	Ports []uint16

	// EligibleUsers narrows enforcement to these users. Empty means every
	// user is eligible. A name or a numeric uid.
	EligibleUsers []string

	// ExemptUsers are never routed. A name or a numeric uid.
	ExemptUsers []string

	// ExemptExecutables are absolute paths or globs of programs that connect
	// directly, such as a CI runner agent. Never list an interpreter or a
	// general HTTP client.
	ExemptExecutables []string

	// SkipDestinations are added to the built-in skip list of loopback,
	// link-local and cloud metadata addresses. They never remove a built-in
	// entry.
	SkipDestinations []netip.Prefix

	// CgroupPath is the cgroup v2 directory the programs attach to. Empty
	// means the cgroup v2 root, which covers every process on the host.
	CgroupPath string

	// DenyUDP returns EPERM for UDP to a routed port from an eligible
	// process, so a QUIC client falls back to TCP. Default true.
	DenyUDP bool

	// TraceDecisions makes the kernel report every decision through a ring
	// buffer, for debug logs and tests. It costs one record per connection
	// on the host, so it is off in normal operation.
	TraceDecisions bool
}

// DefaultPolicy returns the policy the daemon uses when the config names
// nothing: default ports, every user eligible, UDP denied.
func DefaultPolicy() Policy {
	return Policy{
		Ports:   slices.Clone(DefaultPorts),
		DenyUDP: true,
	}
}

// Validate rejects a policy the kernel programs cannot express.
func (p Policy) Validate() error {
	for _, port := range p.Ports {
		if port == 0 {
			return errors.New("enforce: port 0 is not a valid destination port")
		}
	}
	for _, prefix := range p.SkipDestinations {
		if !prefix.IsValid() {
			return fmt.Errorf("enforce: skip destination %q is not a valid prefix", prefix)
		}
	}
	for _, users := range [][]string{p.EligibleUsers, p.ExemptUsers} {
		if _, err := resolveUIDs(users); err != nil {
			return err
		}
	}
	return nil
}

// Target is where the kernel sends routed connections.
type Target struct {
	// Addr is the proxy's IPv4 listener.
	Addr netip.AddrPort

	// Addr6 is the proxy's IPv6 listener on the same port. When it is not
	// valid, native IPv6 connections from eligible processes get EPERM and
	// the client falls back to IPv4.
	Addr6 netip.AddrPort
}

// Enforcer attaches the enforcement programs for a target and a policy.
type Enforcer interface {
	// Attach loads the programs, fills the maps and attaches to the cgroup.
	// It returns only when every eligible connection is routed. The programs
	// stay attached until the Handle is closed or the process exits. It
	// fails with ErrAlreadyEnforced when another daemon enforces the cgroup.
	Attach(ctx context.Context, t Target, p Policy) (Handle, error)

	// Probe reports whether this host can enforce, and what is missing.
	Probe() ProbeResult

	// Attached reports whether a pmg program is attached to the cgroup. An
	// empty path means the cgroup v2 root.
	Attached(cgroupPath string) (bool, error)
}

// ErrAlreadyEnforced means another pmg daemon has its programs on the
// cgroup. Two sets would both attach, and the first would take every
// connection while the second reports active and does nothing.
var ErrAlreadyEnforced = errors.New("enforce: another pmg daemon already enforces this cgroup")

// Origin is where a redirected client wanted to connect, and the process
// that asked. The kernel records the process at connect, so a log line can
// name the program behind a connection. A client in another network
// namespace has a destination and no process.
type Origin struct {
	Dst  netip.AddrPort
	PID  uint32
	Comm string
	Exe  string

	// ToProxy means the client connected to the proxy itself and Dst is the
	// proxy. The kernel recorded who asked and rewrote nothing.
	ToProxy bool
}

// Handle is one attached enforcement. It is the proxy's source for the
// original destination of a redirected client.
type Handle interface {
	// OriginalDestination returns where the client at the given address
	// wanted to connect, and who asked. It consumes the entry.
	OriginalDestination(client netip.AddrPort) (Origin, bool)

	// Status describes the attached enforcement for the state file.
	Status() Status

	// Close detaches the programs. Connections then go direct.
	Close() error
}

// Status is the resolved form of a policy, as the kernel sees it.
type Status struct {
	CgroupPath        string         `json:"cgroup_path"`
	Ports             []uint16       `json:"ports"`
	NetnsCookie       uint64         `json:"netns_cookie"`
	EligibleUIDs      []uint32       `json:"eligible_uids,omitempty"`
	ExemptUIDs        []uint32       `json:"exempt_uids,omitempty"`
	ExemptExecutables []ExemptedFile `json:"exempt_executables,omitempty"`
	SkipDestinations  []netip.Prefix `json:"skip_destinations"`
	DenyUDP           bool           `json:"deny_udp"`
	KernelVersion     string         `json:"kernel_version"`
	LoaderVersion     string         `json:"loader_version"`
}

// PortList renders the routed ports for a status line.
func (s Status) PortList() string {
	parts := make([]string, len(s.Ports))
	for i, p := range s.Ports {
		parts[i] = strconv.Itoa(int(p))
	}
	return strings.Join(parts, ",")
}

// ExemptedFile is one executable the kernel lets connect directly.
type ExemptedFile struct {
	Path  string `json:"path"`
	Dev   uint64 `json:"dev"`
	Inode uint64 `json:"inode"`
}

// ProbeResult says whether the host can enforce. Missing holds one line per
// requirement the host does not meet, so a preflight error can name it.
// Subject names what the host cannot do, in the error. Empty means
// "enforce".
type ProbeResult struct {
	Supported     bool
	Missing       []string
	KernelVersion string
	CgroupPath    string
	Subject       string
}

// Err turns a failed probe into one error that lists every missing
// requirement. nil when the host can do what the probe asked.
func (r ProbeResult) Err() error {
	if r.Supported {
		return nil
	}
	subject := r.Subject
	if subject == "" {
		subject = "enforce"
	}
	msg := "enforce: this host cannot " + subject
	if len(r.Missing) > 0 {
		msg += ":"
	}
	for _, m := range r.Missing {
		msg += "\n  - " + m
	}
	return errors.New(msg)
}

// New returns the enforcer for this platform. It returns ErrUnsupported on
// every platform but Linux.
func New() (Enforcer, error) {
	return newPlatformEnforcer()
}
