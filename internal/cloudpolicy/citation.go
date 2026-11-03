package cloudpolicy

import (
	recordv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/policy/record/v1"
	"github.com/safedep/dry/policy/project"
)

// ruleCitation cites a cloud package rule. The layer and the override stay
// unset, because the resolved policy does not say which override a rule
// attaches to. The server finds them from the rule id.
func ruleCitation(applied *AppliedHeader, ruleID string) *recordv1.DecisionCitation {
	return recordv1.DecisionCitation_builder{
		Revision:              applied.Revision,
		DefaultPolicyRevision: applied.DefaultPolicyRevision,
		Digest:                applied.Digest,
		RuleId:                ruleID,
	}.Build()
}

// fieldCitation cites a field of the policy, with the layer and the override
// that set it.
func fieldCitation(applied *AppliedHeader, path string, proj *project.Projection) *recordv1.DecisionCitation {
	source := proj.Sources[project.SourceKey{Path: path}]
	return recordv1.DecisionCitation_builder{
		Revision:              applied.Revision,
		DefaultPolicyRevision: applied.DefaultPolicyRevision,
		Digest:                applied.Digest,
		Path:                  path,
		Layer:                 source.Layer,
		OverrideId:            source.OverrideID,
	}.Build()
}
