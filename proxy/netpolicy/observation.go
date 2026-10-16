package netpolicy

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
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

// Fold merges rows into one row per host, port and client, sorted. A pid
// names one process, so it does not survive the fold. The newest row
// decides a merged row's decision.
func Fold(rows []Destination) []Destination {
	merged := map[string]*Destination{}
	for _, d := range rows {
		key := d.Address() + "\x00" + d.Client
		row, ok := merged[key]
		if !ok {
			copied := d
			copied.PID = 0
			merged[key] = &copied
			continue
		}
		row.Count += d.Count
		if d.FirstSeen.Before(row.FirstSeen) {
			row.FirstSeen = d.FirstSeen
		}
		if !d.LastSeen.Before(row.LastSeen) {
			row.LastSeen = d.LastSeen
			row.Allowed, row.Rule, row.Enforced = d.Allowed, d.Rule, d.Enforced
		}
	}

	out := make([]Destination, 0, len(merged))
	for _, row := range merged {
		out = append(out, *row)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Client < b.Client
	})
	return out
}
