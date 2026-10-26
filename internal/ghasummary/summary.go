// Package ghasummary renders the PMG GitHub Action job summary and the
// workflow commands that annotate the run. It reads the stop report and
// the network profile proposal.
package ghasummary

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/safedep/pmg/internal/proxyserver"
	"github.com/safedep/pmg/sandbox/executor"
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

// profilePath is the file a proposal goes to. A built-in profile cannot
// change, so a proposal for it is a new file.
func (in Input) profilePath() string {
	if in.profileFile() {
		return in.Profile
	}
	return DefaultProfilePath
}

func (in Input) profileFile() bool {
	return in.Profile != "" && executor.IsProfilePath(in.Profile)
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
	case !in.Stop.Stopped && in.FailOnViolation:
		return "**Failed.** No PMG proxy ran at the end of the job. A step stopped it or removed its state file, so the job has no verdict. When a step of the job stops PMG, set `auto-stop: false`."
	case !in.Stop.Stopped:
		return "No PMG proxy ran at the end of the job. A step stopped it or removed its state file, so this summary has no stop result."
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
	blocked := strconv.Itoa(in.Stop.BlockedCount)
	if !in.Stop.StateVerified {
		blocked = "unknown"
	}
	b.WriteString("| Packages blocked | Network mode | Network profile | Destinations observed |\n")
	b.WriteString("|---|---|---|---|\n")
	fmt.Fprintf(b, "| %s | %s | %s | %d |\n\n", blocked, cell(mode), code(profile), in.Stop.Observed)
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
	switch {
	case in.Profile == "":
	case in.profileFile():
		fmt.Fprintf(b, "\nTo allow a destination, add it to `network.allow_outbound` in %s.\n", code(in.Profile))
	default:
		fmt.Fprintf(b, "\n%s is a built-in profile. To allow a destination, make a profile file that inherits %s, add the destination to its `network.allow_outbound`, and set `network-profile` to the file.\n", code(in.Profile), code(in.Profile))
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
		fmt.Fprintf(b, "PMG proposes a network profile from the %d destination(s) this job reached. ", countDestinations(p.Destinations))
		fmt.Fprintf(b, "Review each rule. Save the file as %s and commit it.", path)
		if !in.profileFile() {
			fmt.Fprintf(b, " Then set `network-profile: %s` on the PMG step.", strings.Trim(path, "`"))
		}
		b.WriteString(" Later runs report each destination the profile does not name. Set `network-mode: enforce` to refuse them.\n\n")
	case len(p.Added) == 0:
		if !writeUnproposed(b, p, path) {
			fmt.Fprintf(b, "%s allows every destination this job reached.\n\n", path)
		}
		return
	default:
		writeUnproposed(b, p, path)
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
	b.WriteString("Add the profile to CODEOWNERS, so that a security reviewer approves each change to it. Set `baseline: false` on the PMG step to leave this section out.\n")
}

// writeUnproposed explains each destination that gets no proposed rule and
// no allow rule. It reports whether it wrote anything.
func writeUnproposed(b *strings.Builder, p *propose.Report, path string) bool {
	n := countVerdicts(p)
	if c := n[propose.VerdictRefused]; c > 0 {
		fmt.Fprintf(b, "%s refused %d destination(s) that this job tried to reach. PMG proposes no rule for a refused destination. Add a rule by hand only when the job needs the destination.\n\n", path, c)
	}
	if c := n[propose.VerdictKeptDenied]; c > 0 {
		fmt.Fprintf(b, "A deny rule in the profile chain of %s matches %d destination(s). PMG keeps the deny rule, because a maintainer wrote it.\n\n", path, c)
	}
	if c := n[propose.VerdictInvalid]; c > 0 {
		fmt.Fprintf(b, "PMG cannot write a rule for %d destination(s), because the name is not a valid host and port.\n\n", c)
	}
	return n[propose.VerdictRefused]+n[propose.VerdictKeptDenied]+n[propose.VerdictInvalid] > 0
}

// countVerdicts counts the destinations of each verdict. A destination
// that two programs reach has a row for each program.
func countVerdicts(p *propose.Report) map[propose.Verdict]int {
	seen := map[propose.Verdict]map[string]bool{}
	for _, row := range p.Destinations {
		if seen[row.Verdict] == nil {
			seen[row.Verdict] = map[string]bool{}
		}
		seen[row.Verdict][row.Address()] = true
	}
	n := map[propose.Verdict]int{}
	for verdict, addresses := range seen {
		n[verdict] = len(addresses)
	}
	return n
}

func countDestinations(rows []propose.Row) int {
	seen := map[string]bool{}
	for _, row := range rows {
		seen[row.Address()] = true
	}
	return len(seen)
}

// cell keeps text from the network from changing the table or adding a
// link or HTML. A client asks for the host, so a host can hold Markdown.
func cell(s string) string {
	s = strings.NewReplacer("\r", " ", "\n", " ", "|", `\|`, "<", "&lt;", ">", "&gt;", "`", "'", "[", `\[`, "]", `\]`).Replace(s)
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
