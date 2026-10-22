package ghasummary

import (
	"fmt"
	"strings"
)

const annotationTitle = "PMG"

// Commands are the workflow commands that annotate the run: an error or a
// warning per denial and per blocked package set, a warning per new host
// when the workflow names a profile, and a notice that points at the
// proposal. Each kind stops at a fixed count, so a noisy run does not
// bury the job.
func Commands(in Input) []string {
	var out []string
	kind := "warning"
	if in.FailOnViolation {
		kind = "error"
	}
	if in.Stop.Stopped && !in.Stop.StateVerified {
		out = append(out, command(kind, "PMG could not verify the final proxy state. Treat this run as failed."))
	}
	if in.Stop.BlockedCount > 0 {
		out = append(out, command(kind, fmt.Sprintf("PMG blocked %d package(s). See the job summary.", in.Stop.BlockedCount)))
	}
	out = append(out, denialCommands(in, kind)...)
	out = append(out, newHostCommands(in)...)
	if p := in.Proposal; p != nil && len(p.Added) > 0 {
		out = append(out, command("notice", fmt.Sprintf("PMG proposes %d network rule(s) for %s. See the job summary.", len(p.Added), in.profilePath())))
	}
	return out
}

func denialCommands(in Input, kind string) []string {
	n := in.Stop.Network
	if n == nil {
		return nil
	}
	action := "would deny"
	if n.Enforced() {
		action = "denied"
	} else {
		kind = "warning"
	}
	var out []string
	for i, d := range n.Denials {
		if i == maxAnnotations {
			out = append(out, command(kind, fmt.Sprintf("PMG %s %d more connection(s). See the job summary.", action, len(n.Denials)-maxAnnotations)))
			break
		}
		msg := fmt.Sprintf("PMG %s %s by rule %s", action, d.Destination, d.Rule)
		if d.Client != "" {
			msg += " (" + d.Client + ")"
		}
		out = append(out, command(kind, msg))
	}
	return out
}

// newHostCommands warns about each host a named profile does not allow.
// Under enforce the proxy denied them, and the denial commands cover them.
func newHostCommands(in Input) []string {
	p := in.Proposal
	if p == nil || in.Profile == "" || p.New || in.enforced() {
		return nil
	}
	var out []string
	for i, rule := range p.Added {
		if i == maxAnnotations {
			out = append(out, command("warning", fmt.Sprintf("%d more destination(s) are not in %s. See the job summary.", len(p.Added)-maxAnnotations, in.Profile)))
			break
		}
		out = append(out, command("warning", fmt.Sprintf("%s is not in %s", rule, in.Profile)))
	}
	return out
}

// command formats one workflow command. The escapes keep a value from the
// network from ending the command or starting a new one.
func command(kind, msg string) string {
	return fmt.Sprintf("::%s title=%s::%s", kind, escapeProperty(annotationTitle), escapeData(msg))
}

func escapeData(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(s)
}

func escapeProperty(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C").Replace(s)
}
