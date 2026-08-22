package main

import (
	"encoding/xml"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	acc "github.com/safedep/pmg/test/acceptance"
)

type Status string

const (
	StatusGap  Status = "gap"
	StatusPass Status = "pass"
	StatusFail Status = "fail"
	StatusSkip Status = "skip"
)

const subtestPrefix = "TestAcceptance/"

type junitReport struct {
	XMLName xml.Name     `xml:"testsuites"`
	Suites  []junitSuite `xml:"testsuite"`
}

type junitSuite struct {
	Cases []junitCase `xml:"testcase"`
}

type junitCase struct {
	Name    string   `xml:"name,attr"`
	Failure *xmlNode `xml:"failure"`
	Skipped *xmlNode `xml:"skipped"`
}

type xmlNode struct {
	Message string `xml:"message,attr"`
	Body    string `xml:",chardata"`
}

type result struct {
	status  Status
	message string
}

func parseJUnit(data []byte) (map[string]result, error) {
	var r junitReport
	if err := xml.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse junit: %w", err)
	}
	out := map[string]result{}
	for _, s := range r.Suites {
		for _, c := range s.Cases {
			if !strings.HasPrefix(c.Name, subtestPrefix) {
				continue
			}
			id := strings.TrimPrefix(c.Name, subtestPrefix)
			res := result{status: StatusPass}
			switch {
			case c.Failure != nil:
				res.status = StatusFail
				res.message = snippet(c.Failure)
			case c.Skipped != nil:
				res.status = StatusSkip
				res.message = snippet(c.Skipped)
			}
			out[id] = res
		}
	}
	return out, nil
}

// statusesFromJUnit maps each acceptance subtest id to its status. Parent
// aggregate rows (e.g. "npm/guard") are included; they are not catalog ids, so
// summarize ignores them.
func statusesFromJUnit(data []byte) (map[string]Status, error) {
	res, err := parseJUnit(data)
	if err != nil {
		return nil, err
	}
	out := make(map[string]Status, len(res))
	for id, r := range res {
		out[id] = r.status
	}
	return out, nil
}

func snippet(n *xmlNode) string {
	text := strings.TrimSpace(n.Body)
	if text == "" {
		text = strings.TrimSpace(n.Message)
	}
	if text == "" {
		return ""
	}
	line := strings.TrimSpace(strings.SplitN(text, "\n", 2)[0])
	const max = 200
	if len(line) > max {
		line = line[:max] + "…"
	}
	return line
}

type Row struct {
	G      acc.Guarantee
	Status Status
}

type Summary struct {
	Rows   []Row
	Counts map[Status]int
}

func summarize(cat *acc.Catalog, st map[string]Status) Summary {
	sum := Summary{Counts: map[Status]int{}}
	for _, id := range cat.IDs() {
		g, _ := cat.Get(id)
		s := StatusGap
		if v, ok := st[id]; ok {
			s = v
		}
		sum.Rows = append(sum.Rows, Row{G: g, Status: s})
		sum.Counts[s]++
	}
	return sum
}

func icon(s Status) string {
	switch s {
	case StatusPass:
		return "✅"
	case StatusFail:
		return "❌"
	case StatusSkip:
		return "⏭️"
	default:
		return "⚪"
	}
}

var tierOrder = []acc.Tier{acc.TierP0, acc.TierP1, acc.TierP2}

func render(w *strings.Builder, sum Summary, messages map[string]result) {
	fmt.Fprintf(w, "# PMG Acceptance Report\n\n")
	fmt.Fprintf(w, "✅ %d pass · ❌ %d fail · ⏭️ %d skip · ⚪ %d gap\n\n",
		sum.Counts[StatusPass], sum.Counts[StatusFail], sum.Counts[StatusSkip], sum.Counts[StatusGap])

	renderTierRollup(w, sum)

	bySurface := map[string][]Row{}
	surfaces := []string{}
	for _, r := range sum.Rows {
		if _, seen := bySurface[r.G.Surface]; !seen {
			surfaces = append(surfaces, r.G.Surface)
		}
		bySurface[r.G.Surface] = append(bySurface[r.G.Surface], r)
	}
	sort.Strings(surfaces)

	for _, surface := range surfaces {
		fmt.Fprintf(w, "## %s\n\n| | Tier | Guarantee | Detail |\n|---|---|---|---|\n", surface)
		rows := bySurface[surface]
		sortRowsByTier(rows)
		for _, r := range rows {
			detail := r.G.Guarantee
			if r.Status == StatusFail || r.Status == StatusSkip {
				if m, ok := messages[r.G.ID]; ok && m.message != "" {
					detail = fmt.Sprintf("%s — %s", r.G.Guarantee, m.message)
				}
			}
			fmt.Fprintf(w, "| %s | %s | `%s` | %s |\n", icon(r.Status), r.G.Tier, r.G.ID, mdCell(detail))
		}
		fmt.Fprintf(w, "\n")
	}
}

func renderTierRollup(w *strings.Builder, sum Summary) {
	perTier := map[acc.Tier]map[Status]int{}
	for _, r := range sum.Rows {
		if perTier[r.G.Tier] == nil {
			perTier[r.G.Tier] = map[Status]int{}
		}
		perTier[r.G.Tier][r.Status]++
	}

	fmt.Fprintf(w, "| Tier | ✅ | ❌ | ⏭️ | ⚪ | coverage |\n|---|---|---|---|---|---|\n")
	for _, tier := range tierOrder {
		c := perTier[tier]
		total := c[StatusPass] + c[StatusFail] + c[StatusSkip] + c[StatusGap]
		fmt.Fprintf(w, "| %s | %d | %d | %d | %d | %d/%d |\n",
			tier, c[StatusPass], c[StatusFail], c[StatusSkip], c[StatusGap], c[StatusPass], total)
	}
	fmt.Fprintf(w, "\n")
}

func sortRowsByTier(rows []Row) {
	rank := map[acc.Tier]int{acc.TierP0: 0, acc.TierP1: 1, acc.TierP2: 2}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].G.Tier != rows[j].G.Tier {
			return rank[rows[i].G.Tier] < rank[rows[j].G.Tier]
		}
		return rows[i].G.ID < rows[j].G.ID
	})
}

func mdCell(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}

func main() {
	junitPath := flag.String("junit", "", "path to gotestsum JUnit XML")
	catalogPath := flag.String("catalog", "test/acceptance/catalog.yaml", "path to catalog.yaml")
	flag.Parse()

	cat, err := acc.LoadCatalog(*catalogPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load catalog: %v\n", err)
		os.Exit(1)
	}

	results := map[string]result{}
	if *junitPath != "" {
		data, err := os.ReadFile(*junitPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read junit: %v\n", err)
		} else if results, err = parseJUnit(data); err != nil {
			fmt.Fprintf(os.Stderr, "parse junit: %v\n", err)
			results = map[string]result{}
		}
	}

	statuses := make(map[string]Status, len(results))
	for id, r := range results {
		statuses[id] = r.status
	}

	var b strings.Builder
	render(&b, summarize(cat, statuses), results)
	if _, err := fmt.Fprint(os.Stdout, b.String()); err != nil {
		fmt.Fprintf(os.Stderr, "write report: %v\n", err)
		os.Exit(1)
	}
}
