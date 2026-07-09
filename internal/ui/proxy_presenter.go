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
	case proxy.BlockReasonMalware:
		message = fmt.Sprintf("Malicious package blocked: %s/%s@%s\n\nReason: %s\n\nReference: %s",
			ecosystem, blockCtx.PackageName, blockCtx.PackageVersion,
			blockCtx.MalwareSummary, blockCtx.MalwareReferenceURL)

	case proxy.BlockReasonUserDeclined:
		message = fmt.Sprintf("Installation blocked by user: %s/%s@%s\n\nReason: %s\n\nReference: %s",
			ecosystem, blockCtx.PackageName, blockCtx.PackageVersion,
			blockCtx.MalwareSummary, blockCtx.MalwareReferenceURL)

	case proxy.BlockReasonConfirmationFailed:
		// Operational failure rather than a policy decision; the advisory
		// message is intentionally not appended.
		return fmt.Sprintf("Failed to get user confirmation for suspicious package %s/%s@%s",
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
