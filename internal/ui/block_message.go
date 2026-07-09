package ui

import (
	"fmt"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/proxy"
)

// ProxyBlockMessage renders the response body for a blocked proxy request
// from the interceptor's structured block decision. It is the single place
// where user-facing block message text is composed.
func ProxyBlockMessage(reason proxy.BlockReason, blockCtx *proxy.BlockContext) string {
	return renderProxyBlockMessage(reason, blockCtx, config.Get().Config.AdvisoryMessage)
}

func renderProxyBlockMessage(reason proxy.BlockReason, blockCtx *proxy.BlockContext, advisory string) string {
	if blockCtx == nil {
		return ""
	}

	var message string
	switch reason {
	case proxy.BlockReasonMalware:
		message = fmt.Sprintf("Malicious package blocked: %s/%s@%s\n\nReason: %s\n\nReference: %s",
			blockCtx.Ecosystem, blockCtx.PackageName, blockCtx.PackageVersion,
			blockCtx.MalwareSummary, blockCtx.MalwareReferenceURL)

	case proxy.BlockReasonUserDeclined:
		message = fmt.Sprintf("Installation blocked by user: %s/%s@%s\n\nReason: %s\n\nReference: %s",
			blockCtx.Ecosystem, blockCtx.PackageName, blockCtx.PackageVersion,
			blockCtx.MalwareSummary, blockCtx.MalwareReferenceURL)

	case proxy.BlockReasonConfirmationFailed:
		// Operational failure rather than a policy decision; the advisory
		// message is intentionally not appended.
		return fmt.Sprintf("Failed to get user confirmation for suspicious package %s/%s@%s",
			blockCtx.Ecosystem, blockCtx.PackageName, blockCtx.PackageVersion)

	case proxy.BlockReasonDependencyCooldown:
		message = fmt.Sprintf("Package blocked by dependency cooldown: %s/%s@%s\n\nPublished %d day(s) ago; cooldown window is %d day(s) (%d remaining).",
			blockCtx.Ecosystem, blockCtx.PackageName, blockCtx.PackageVersion,
			blockCtx.CooldownDaysAgo, blockCtx.CooldownDays, blockCtx.CooldownDaysLeft)

	default:
		return ""
	}

	if advisory != "" {
		message += "\n\n" + advisory
	}
	return message
}
