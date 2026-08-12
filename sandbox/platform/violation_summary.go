package platform

import (
	"fmt"

	"github.com/safedep/pmg/sandbox"
)

// summarizeViolation renders the short label carried on
// sandbox.Violation.RuleLabel. Drivers reporting normalized kinds share it;
// Seatbelt keeps its own because it labels from raw operation strings.
func summarizeViolation(kind sandbox.ViolationKind, target string) string {
	switch kind {
	case sandbox.ViolationKindFSRead:
		return fmt.Sprintf("read access denied: %s", target)
	case sandbox.ViolationKindFSWrite:
		return fmt.Sprintf("write access denied: %s", target)
	case sandbox.ViolationKindFSDeleteOrRename:
		return fmt.Sprintf("rename or unlink denied: %s", target)
	case sandbox.ViolationKindExec:
		return fmt.Sprintf("process execution denied: %s", target)
	case sandbox.ViolationKindNetworkConnect:
		// Same posture message as the Seatbelt driver (seatbelt_diagnostics_darwin.go).
		return fmt.Sprintf("direct network access blocked by network_via_proxy_only (%s) — traffic must flow through the PMG proxy (a tool may have ignored HTTP_PROXY/HTTPS_PROXY)", target)
	default:
		if target == "" {
			return "sandbox denied an operation"
		}
		return fmt.Sprintf("sandbox denied access to %s", target)
	}
}
