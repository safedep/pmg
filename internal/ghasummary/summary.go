// Package ghasummary renders the PMG GitHub Action job summary and the
// workflow commands that annotate the run. It reads the stop report and
// the network profile proposal.
package ghasummary

import (
	"fmt"
	"strings"

	"github.com/safedep/pmg/internal/proxyserver"
	"github.com/safedep/pmg/sandbox/propose"
)

// DefaultProfilePath is where the summary tells a user to save a proposal
// when the workflow names no network profile.
const DefaultProfilePath = ".pmg/network.yml"

const (
	maxTableRows   = 100
	maxAnnotations = 10
)

// Input is what one summary needs.
type Input struct {
	Stop proxyserver.StopReport

	// Proposal is nil when the job made no proposal.
	Proposal *propose.Report

	// Profile is the network profile path the workflow names. Empty when
	// it names none.
	Profile string

	FailOnViolation bool

	// Workspace is the checkout directory. The summary shows a profile path
	// under it relative to it.
	Workspace string
}

func (in Input) profilePath() string {
	if in.Profile != "" {
		return in.Profile
	}
	return DefaultProfilePath
}

func (in Input) enforced() bool {
	return in.Stop.Network != nil && in.Stop.Network.Enforced()
}

// Markdown is the job summary.
func Markdown(in Input) string {
	var b strings.Builder
	b.WriteString("## PMG\n\n")
	b.WriteString(verdict(in))
	b.WriteString("\n\n")
	writeOverview(&b, in)
	writeDenials(&b, in)
	writeDestinations(&b, in)
	writeProposal(&b, in)
	return b.String()
}

func verdict(in Input) string {
	switch {
	case !in.Stop.Stopped:
		return "PMG was not running at the end of the job. A workflow step stopped it first, so this summary has no stop result."
	case in.Stop.Violation != "" && in.FailOnViolation:
		return "**Failed.** " + sentence(in.Stop.Violation)
	case in.Stop.Violation != "":
		return "**Passed with violations.** " + sentence(in.Stop.Violation) + " `fail-on-violation` is off, so the job does not fail."
	default:
		return "**Passed.** PMG blocked no package and denied no connection."
	}
}

func sentence(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:] + "."
}

func writeOverview(b *strings.Builder, in Input) {
	if !in.Stop.Stopped {
		return
	}
	mode, profile := "off", "none"
	if n := in.Stop.Network; n != nil {
		mode, profile = n.Mode, n.Profile()
	}
	if in.Workspace != "" {
		profile = strings.ReplaceAll(profile, strings.TrimSuffix(in.Workspace, "/")+"/", "")
	}
	b.WriteString("| Packages blocked | Network mode | Network profile | Destinations observed |\n")
	b.WriteString("|---|---|---|---|\n")
	fmt.Fprintf(b, "| %d | %s | %s | %d |\n\n", in.Stop.BlockedCount, cell(mode), code(profile), in.Stop.Observed)
}

func writeDenials(b *strings.Builder, in Input) {
	n := in.Stop.Network
	if n == nil || len(n.Denials) == 0 {
		return
	}
	if n.Enforced() {
		b.WriteString("### Denied connections\n\n")
	} else {
		b.WriteString("### Connections the profile would deny\n\n")
	}
	b.WriteString("| Destination | Rule | Program | Count |\n|---|---|---|---|\n")
	for i, d := range n.Denials {
		if i == maxTableRows {
			fmt.Fprintf(b, "\n%d more connection(s) are not shown.\n", len(n.Denials)-maxTableRows)
			break
		}
		fmt.Fprintf(b, "| %s | %s | %s | %d |\n", code(d.Destination), code(d.Rule), cell(d.Client), d.Count)
	}
	if in.Profile != "" {
		fmt.Fprintf(b, "\nTo allow a destination, add it to `network.allow_outbound` in %s.\n", code(in.Profile))
	}
	b.WriteString("\n")
}

func writeDestinations(b *strings.Builder, in Input) {
	p := in.Proposal
	if p == nil || len(p.Destinations) == 0 {
		return
	}
	b.WriteString("### Observed destinations\n\n")
	b.WriteString("| Destination | Program | Count | Proposal |\n|---|---|---|---|\n")
	for i, row := range p.Destinations {
		if i == maxTableRows {
			fmt.Fprintf(b, "\n%d more destination(s) are not shown. The proposed profile has all of them.\n", len(p.Destinations)-maxTableRows)
			break
		}
		fmt.Fprintf(b, "| %s | %s | %d | %s |\n", code(row.Address()), cell(row.Client), row.Count, rowProposal(row))
	}
	b.WriteString("\n")
}

func rowProposal(row propose.Row) string {
	switch row.Verdict {
	case propose.VerdictAdd:
		return "add " + code(row.Rule)
	case propose.VerdictParentAllows:
		return "parent rule " + code(row.Rule) + " allows it"
	case propose.VerdictAlreadyAllowed:
		return "rule " + code(row.Rule) + " allows it"
	case propose.VerdictKeptDenied:
		return "rule " + code(row.Rule) + " denies it"
	default:
		return cell(string(row.Verdict))
	}
}

func writeProposal(b *strings.Builder, in Input) {
	p := in.Proposal
	if p == nil {
		return
	}
	path := code(in.profilePath())
	b.WriteString("### Network profile\n\n")
	switch {
	case p.New:
		fmt.Fprintf(b, "PMG proposes a network profile from the %d destination(s) this job reached. ", len(p.Destinations))
		fmt.Fprintf(b, "Review each rule. Save the file as %s and commit it.", path)
		if in.Profile == "" {
			fmt.Fprintf(b, " Then set `network-profile: %s` on the PMG step.", strings.Trim(path, "`"))
		}
		b.WriteString(" Later runs report each destination the profile does not name. Set `network-mode: enforce` to refuse them.\n\n")
	case len(p.Added) == 0:
		if refused := refusedCount(p); refused > 0 {
			fmt.Fprintf(b, "%s does not allow %d destination(s) that this job tried to reach. PMG proposes no rule for them, because the job did not reach them. Add a rule by hand only when the job needs the destination.\n\n", path, refused)
			return
		}
		fmt.Fprintf(b, "%s allows every destination this job reached.\n\n", path)
		return
	default:
		fmt.Fprintf(b, "This job reached %d destination(s) that %s does not allow. Review each one before you add it:\n\n", len(p.Added), path)
		for _, rule := range p.Added {
			fmt.Fprintf(b, "- %s\n", code(rule))
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(b, "<details><summary>Proposed %s</summary>\n\n", path)
	fence := codeFence(p.Content)
	fmt.Fprintf(b, "%syaml\n%s", fence, p.Content)
	if !strings.HasSuffix(p.Content, "\n") {
		b.WriteString("\n")
	}
	fmt.Fprintf(b, "%s\n\n</details>\n\n", fence)
	b.WriteString("Add the profile to CODEOWNERS, so that a security reviewer approves each change to it.\n")
}

func refusedCount(p *propose.Report) int {
	n := 0
	for _, row := range p.Destinations {
		if row.Verdict == propose.VerdictRefused || row.Verdict == propose.VerdictKeptDenied {
			n++
		}
	}
	return n
}

// cell makes text from the network safe in a table cell. A client asks
// for the host, so a host can hold Markdown or HTML.
func cell(s string) string {
	s = strings.NewReplacer("\r", " ", "\n", " ", "|", `\|`, "<", "&lt;", ">", "&gt;", "`", "'").Replace(s)
	if s == "" {
		return "-"
	}
	return s
}

func code(s string) string {
	if s == "" {
		return "-"
	}
	return "`" + strings.NewReplacer("\r", " ", "\n", " ", "|", `\|`, "`", "'").Replace(s) + "`"
}

// codeFence is a fence longer than any backtick run in content, so the
// content cannot close the block.
func codeFence(content string) string {
	longest, run := 0, 0
	for _, r := range content {
		if r == '`' {
			run++
			longest = max(longest, run)
			continue
		}
		run = 0
	}
	return strings.Repeat("`", max(3, longest+1))
}
