package sandbox

import "context"

type ProbeStatus string

const (
	ProbeStatusOK      ProbeStatus = "ok"
	ProbeStatusWarn    ProbeStatus = "warn"
	ProbeStatusFail    ProbeStatus = "fail"
	ProbeStatusSkipped ProbeStatus = "skipped"
)

// ProbeFix is a suggested remediation for a non-OK probe result.
type ProbeFix struct {
	Description string
	Command     string
	Docs        string
}

// ProbeResult is the structured outcome of a probe.
type ProbeResult struct {
	Name    string
	Status  ProbeStatus
	Summary string
	Detail  string
	Fixes   []ProbeFix
}

// Probe is the unit of work a diagnose runner executes.
type Probe interface {
	Name() string
	Run(ctx context.Context) ProbeResult
}

// Probe names. These are stable identifiers used in JSON output, the
// `--driver` filter, and by callers that want to look up a specific probe's
// result. The cmd layer maps them to friendly labels for human rendering.
const (
	ProbeSeatbeltDriver = "driver.seatbelt.available"
	ProbeBwrapDriver    = "driver.bwrap.available"
	ProbeLandlockDriver = "driver.landlock.abi"
	ProbeAppArmorUserns = "linux.apparmor.userns"
	ProbeSeatbeltCanary = "canary.seatbelt"
	ProbeBwrapCanary    = "canary.bubblewrap"
	ProbeLandlockCanary = "canary.landlock"
)

// RunProbes executes probes sequentially in input order, honoring ctx cancellation
// between probes. A cancelled context short-circuits the remaining probes
// with ProbeStatusSkipped results so the caller can render a complete table.
func RunProbes(ctx context.Context, probes []Probe) []ProbeResult {
	results := make([]ProbeResult, 0, len(probes))

	for _, p := range probes {
		if err := ctx.Err(); err != nil {
			results = append(results, ProbeResult{
				Name:    p.Name(),
				Status:  ProbeStatusSkipped,
				Summary: "skipped: " + err.Error(),
			})
			continue
		}

		results = append(results, p.Run(ctx))
	}

	return results
}
