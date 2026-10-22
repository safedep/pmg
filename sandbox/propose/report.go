package propose

import "github.com/safedep/pmg/sandbox"

// Report is the JSON form of one proposal. `pmg sandbox profile propose
// --json` prints it, and the GitHub Action job summary reads it.
type Report struct {
	RunIDs       []string              `json:"run_ids"`
	Destinations []Row                 `json:"destinations"`
	Network      sandbox.NetworkPolicy `json:"network"`
	Added        []string              `json:"added"`
	Target       string                `json:"target,omitempty"`
	// New is true when the target is a new profile file.
	New     bool   `json:"new,omitempty"`
	Content string `json:"content"`
	Written bool   `json:"written"`
}
