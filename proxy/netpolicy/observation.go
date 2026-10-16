package netpolicy

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"time"
)

// Destination is one host and port a run reached through the proxy, with
// the decision the policy made. Count is the number of decisions: one per
// tunnel for TLS, one per request for plain HTTP. A run without a policy
// allows every destination. The daemon keeps one per client as well.
type Destination struct {
	Host      string    `json:"host"`
	Port      uint16    `json:"port"`
	Client    string    `json:"client,omitempty"`
	PID       int       `json:"pid,omitempty"`
	Count     int       `json:"count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Allowed   bool      `json:"allowed"`
	Rule      string    `json:"rule,omitempty"`
	Enforced  bool      `json:"enforced,omitempty"`
}

// Address is the destination as host:port, with an IPv6 host in brackets
// so the string reads back as a rule.
func (d Destination) Address() string {
	return net.JoinHostPort(d.Host, strconv.Itoa(int(d.Port)))
}

// Observation is every destination one run reached, keyed so a later
// command can find the run and the repository it ran in. The one-shot run
// and the daemon write one at exit. `pmg sandbox profile propose` reads it.
type Observation struct {
	RunID          string        `json:"run_id"`
	RepoRoot       string        `json:"repo_root,omitempty"`
	PackageManager string        `json:"package_manager,omitempty"`
	Profile        string        `json:"profile,omitempty"`
	Mode           string        `json:"mode,omitempty"`
	Destinations   []Destination `json:"destinations"`
}

// NewRunID returns a short random id for one run. Twelve hex digits keep
// the id short enough to type from a report.
func NewRunID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%012x", time.Now().UnixNano()&0xffffffffffff)
	}
	return hex.EncodeToString(b[:])
}
