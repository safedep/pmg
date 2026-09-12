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

	fmt.Printf("\n%s ", ui.Colors.Yellow("⚠"))
	for _, line := range shadowedLines(shadowed) {
		fmt.Printf("%s\n", line)
	}
}

// shadowedFix fills the doctor Fix column with the same lines the install
// warning prints, so the two cannot disagree.
func shadowedFix(shadowed []shim.ManagerResolution) string {
	return strings.Join(shadowedLines(shadowed), " ")
}

// shadowedLines names the managers once, then gives one action. The path
// of each manager is in `pmg setup doctor --json` for whoever needs it.
func shadowedLines(shadowed []shim.ManagerResolution) []string {
	names := make([]string, 0, len(shadowed))
	profile := false
	for _, r := range shadowed {
		names = append(names, r.Name)
		profile = profile || r.Origin == shim.OriginProfile
	}
	lines := []string{fmt.Sprintf("PMG does not intercept %s. Another copy is ahead of the shims on PATH.", strings.Join(names, ", "))}
	if profile {
		lines = append(lines, "A shell profile puts it there. Prefix the command with `pmg`, as in `pmg npm install`, or drop that line from the profile.")
	} else {
		lines = append(lines, "Run `pmg setup install --system` from a terminal started as administrator, or prefix the command with `pmg`, as in `pmg npm install`.")
	}
	return lines
}
