//go:build windows

package setup

import (
	"fmt"
	"strings"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/internal/alias"
	"github.com/safedep/pmg/internal/shim"
	"github.com/safedep/pmg/internal/ui"
)

// warnShadowedManagers reports the package managers a shell resolves outside
// the shim directory, and what to do about each. Windows builds PATH as the
// machine value then the user value, and a shell profile can prepend more,
// so `pmg setup install` alone cannot always win.
func warnShadowedManagers(binDir string) {
	inspection, err := shim.InspectInterception(alias.DefaultConfig().PackageManagers, []string{binDir})
	if err != nil {
		log.Warnf("failed to check which managers the shims intercept: %v", err)
		return
	}
	_, shadowed := inspection.Partition()
	if len(shadowed) == 0 {
		return
	}

	fmt.Printf("\n%s A shell resolves these managers ahead of the shims, so PMG does not intercept them:\n",
		ui.Colors.Yellow("⚠"))
	for _, line := range shadowedLines(shadowed) {
		fmt.Printf("   %s\n", line)
	}
}

// shadowedFix fills the doctor Fix column with the same lines the install
// warning prints, so the two cannot disagree.
func shadowedFix(shadowed []shim.ManagerResolution) string {
	return strings.Join(shadowedLines(shadowed), " ")
}

// shadowedLines groups the managers by the PATH half that wins. Four
// shadowed managers then read as one reason and one action, not four.
func shadowedLines(shadowed []shim.ManagerResolution) []string {
	var order []shim.PathOrigin
	groups := map[shim.PathOrigin][]shim.ManagerResolution{}
	for _, r := range shadowed {
		if _, seen := groups[r.Origin]; !seen {
			order = append(order, r.Origin)
		}
		groups[r.Origin] = append(groups[r.Origin], r)
	}

	var lines []string
	for _, origin := range order {
		group := groups[origin]
		entries := make([]string, 0, len(group))
		names := make([]string, 0, len(group))
		for _, r := range group {
			entries = append(entries, fmt.Sprintf("%s (%s)", r.Name, r.Path))
			names = append(names, r.Name)
		}
		lines = append(lines, fmt.Sprintf("%s: %s", shadowedReason(origin), strings.Join(entries, ", ")))
		lines = append(lines, shadowedAction(origin, names))
	}
	return lines
}

func shadowedReason(origin shim.PathOrigin) string {
	switch origin {
	case shim.OriginUser:
		return "On the user PATH, ahead of the shims"
	case shim.OriginProfile:
		return "Put on PATH by a shell profile, where PMG cannot reorder it"
	default:
		return "On the machine PATH, ahead of the user PATH"
	}
}

// shadowedAction names what the user can do, which depends on where the
// winning PATH entry came from. Only the user PATH is one PMG can reorder.
func shadowedAction(origin shim.PathOrigin, names []string) string {
	switch origin {
	case shim.OriginUser:
		return "Run `pmg setup install` again to move the shims ahead."
	case shim.OriginProfile:
		return fmt.Sprintf("Run %s, or drop that line from the profile.", asPmgCommands(names))
	default:
		return fmt.Sprintf("Run `pmg setup install --system` from a terminal started as administrator, or run %s.", asPmgCommands(names))
	}
}

func asPmgCommands(names []string) string {
	commands := make([]string, 0, len(names))
	for _, name := range names {
		commands = append(commands, fmt.Sprintf("`pmg %s`", name))
	}
	if len(commands) == 1 {
		return "it as " + commands[0]
	}
	return "them as " + strings.Join(commands, ", ")
}
