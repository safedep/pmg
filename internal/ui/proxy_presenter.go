package ui

import (
	"fmt"
	"strings"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/proxy"
)

// ecosystemLabel maps the ecosystem enum to the label users know the
// registry by (npm, pypi, go, ...) instead of the raw enum name.
func ecosystemLabel(ecosystem packagev1.Ecosystem) string {
	return strings.ToLower(strings.TrimPrefix(ecosystem.String(), "ECOSYSTEM_"))
}

// ProxyPresenter composes all user-facing text authored by the proxy layer.
// Interceptors return structured decisions; any new proxy-emitted message
// belongs here, not in the proxy layer.
type ProxyPresenter struct {
	// Advisory returns the org-configured advisory message appended to
	// policy block messages. Read at render time so config changes apply
	// to subsequent blocks. nil means no advisory.
	Advisory func() string
}

// BlockMessage renders the response body for a blocked proxy request
// from the interceptor's structured block decision.
func (p ProxyPresenter) BlockMessage(reason proxy.BlockReason, blockCtx *proxy.BlockContext) string {
	if blockCtx == nil {
		return ""
	}

	ecosystem := ecosystemLabel(blockCtx.Ecosystem)

	var message string
	switch reason {
	case proxy.BlockReasonMalware, proxy.BlockReasonUserDeclined:
		prefix := MalwareBlockedHeadline
		if reason == proxy.BlockReasonUserDeclined {
			prefix = "Installation blocked by user"
		}

		message = fmt.Sprintf("%s: %s/%s@%s\n\nReason: %s",
			prefix, ecosystem, blockCtx.PackageName, blockCtx.PackageVersion, blockCtx.MalwareSummary)
		if blockCtx.MalwareReferenceURL != "" {
			message += "\n\nReference: " + blockCtx.MalwareReferenceURL
		}

	case proxy.BlockReasonConfirmationFailed:
		// Operational failure rather than a policy decision; the advisory
		// message is intentionally not appended.
		return fmt.Sprintf("Failed to get user confirmation for suspicious package %s/%s@%s",
			ecosystem, blockCtx.PackageName, blockCtx.PackageVersion)

	case proxy.BlockReasonAnalysisUnavailable:
		// The gate fails closed: the backend gave no verdict, so the package
		// is neither confirmed safe nor malicious. This is an operational
		// failure, so the advisory message is not appended.
		return fmt.Sprintf("Malware analysis unavailable for %s/%s@%s; blocking to fail closed. Retry when the analysis backend is reachable.",
			ecosystem, blockCtx.PackageName, blockCtx.PackageVersion)

	case proxy.BlockReasonDependencyCooldown:
		message = fmt.Sprintf("Package blocked by dependency cooldown: %s/%s@%s\n\nPublished %d day(s) ago; cooldown window is %d day(s) (%d remaining).",
			ecosystem, blockCtx.PackageName, blockCtx.PackageVersion,
			blockCtx.CooldownDaysAgo, blockCtx.CooldownDays, blockCtx.CooldownDaysLeft)

	default:
		return ""
	}

	if p.Advisory != nil {
		if advisory := p.Advisory(); advisory != "" {
			message += "\n\n" + advisory
		}
	}
	return message
}
