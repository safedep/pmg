package netpolicy

// Denial is one destination a deny rule matched, with how many connections
// it matched. The daemon keeps one per client, so the stop report names the
// program behind each one. The daemon writes it to its state file, so the
// JSON tags are an interface between a running daemon and a newer
// `pmg proxy stop`.
type Denial struct {
	Destination string `json:"destination"`
	Rule        string `json:"rule"`
	Client      string `json:"client,omitempty"`
	PID         int    `json:"pid,omitempty"`
	Count       int    `json:"count"`
}

// Report is what the network policy decided during a run.
type Report struct {
	Enforced bool
	Denials  []Denial
}
