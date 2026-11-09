package ui

import (
	"fmt"
	"net/url"
	"strings"
	"unicode"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/api/pb"
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

	case proxy.BlockReasonDependencyCooldown:
		message = fmt.Sprintf("Package blocked by dependency cooldown: %s/%s@%s\n\nPublished %d day(s) ago; cooldown window is %d day(s) (%d remaining).",
			ecosystem, blockCtx.PackageName, blockCtx.PackageVersion,
			blockCtx.CooldownDaysAgo, blockCtx.CooldownDays, blockCtx.CooldownDaysLeft)
		if line := CooldownPolicyLine(blockCtx.CooldownDays, blockCtx.CooldownPolicyRevision); line != "" {
			message += "\n\n" + line
		}

	case proxy.BlockReasonNetworkPolicy:
		message = NetworkDenialMessage(blockCtx.Destination, blockCtx.Rule)

	case proxy.BlockReasonPolicyRule:
		message = PolicyRuleBlockMessage(blockCtx)
		if message == "" {
			return ""
		}

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

// CooldownPolicyLine names the cloud policy that set a cooldown, so a
// developer knows that the tenant policy and not the local config blocked the
// package. It is empty when the local config set the cooldown (revision 0).
func CooldownPolicyLine(days int, revision uint64) string {
	if revision == 0 {
		return ""
	}
	return fmt.Sprintf("The policy of your tenant (revision %d) sets a cooldown of %s", revision, pluralizeDays(days))
}

// NetworkDenialMessage is the one sentence for a connection the network
// policy refused. The proxy sends it to the client and the violation
// record carries it as the rule label.
func NetworkDenialMessage(destination, rule string) string {
	return fmt.Sprintf("Connection to %s denied by the network policy (rule %s)", destination, rule)
}

// policyRuleIndent aligns the lines after the first with the text after
// "pmg: ".
const policyRuleIndent = "     "

// PolicyRuleBlockMessage is the message for a package that a block entry of
// the cloud policy or of blocked_packages blocked. It names the rule, so a
// developer can ask for an exception.
func PolicyRuleBlockMessage(blockCtx *proxy.BlockContext) string {
	if blockCtx == nil || blockCtx.PolicyRule == nil {
		return ""
	}
	rule := blockCtx.PolicyRule
	pkg := packagePurl(blockCtx)
	ruleID := removeControlChars(rule.RuleID)

	details := []string{"rule " + ruleID}
	var lines []string
	if rule.Cloud {
		lines = append(lines, fmt.Sprintf("pmg: blocked %s by the policy of your tenant", pkg))
		details = append(details,
			fmt.Sprintf("policy revision %d", rule.Revision),
			fmt.Sprintf("default policy revision %d", rule.DefaultPolicyRevision))
	} else {
		lines = append(lines, fmt.Sprintf("pmg: blocked %s by blocked_packages in %s", pkg, removeControlChars(rule.File)))
	}
	if reason := removeControlChars(rule.Reason); reason != "" {
		details = append(details, reason)
	}
	lines = append(lines, policyRuleIndent+strings.Join(details, " · "))

	if rule.Cloud {
		lines = append(lines,
			policyRuleIndent+"To ask for an exception, send the rule id and the reason to your security admin.",
			policyRuleIndent+"They can run: safedep policy rule show "+ruleID)
	} else {
		lines = append(lines, policyRuleIndent+"The owner of that file can change the list")
	}
	return strings.Join(lines, "\n")
}

// packagePurl names the blocked package as a PURL, the form of the rule
// selectors. An admin writes a selector in the decoded form, for example
// pkg:npm/@types/ms, so the message decodes the wire form for display only.
func packagePurl(blockCtx *proxy.BlockContext) string {
	purl, err := pb.Purl(&packagev1.PackageVersion{
		Package: &packagev1.Package{Ecosystem: blockCtx.Ecosystem, Name: blockCtx.PackageName},
		Version: blockCtx.PackageVersion,
	})
	if err != nil {
		purl = fmt.Sprintf("%s/%s@%s", ecosystemLabel(blockCtx.Ecosystem), blockCtx.PackageName, blockCtx.PackageVersion)
	} else if decoded, decodeErr := url.PathUnescape(purl); decodeErr == nil {
		purl = decoded
	}
	return removeControlChars(purl)
}

// removeControlChars removes control characters from text that an admin or
// a config file wrote, so the text cannot move the cursor or change the
// terminal.
func removeControlChars(text string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, text)
}
