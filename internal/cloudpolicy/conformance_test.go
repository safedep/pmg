package cloudpolicy

import (
	"testing"
	"time"

	specv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/policy/spec/v1"
	"github.com/safedep/dry/api/pb"
	"github.com/safedep/dry/policy/conformance"
	"github.com/safedep/dry/policy/project"
)

// TestPolicyConformance runs the shared corpus through the projection and
// the package rule index of pmg, with the identity that the interceptors
// use for a request.
func TestPolicyConformance(t *testing.T) {
	kind := specv1.SubjectKind_SUBJECT_KIND_ENDPOINT
	conformance.Run(t, kind, func(raw []byte, q conformance.Query) (conformance.Decision, error) {
		proj, err := project.Decode(raw, conformance.Expect(kind))
		if err != nil {
			return conformance.Decision{}, err
		}
		index, _ := newIndex(proj.Rules, nil)
		p := &Policy{index: index}

		ecosystem, err := pb.EcosystemFromName(q.Package.Ecosystem)
		if err != nil {
			return conformance.Decision{}, err
		}
		p.now = func() time.Time { return q.Now }
		d := p.decide(ecosystem, q.Package.Name, q.Package.Version, q.Control, q.Verdict)
		return conformance.Decision{Effect: d.Effect, RuleID: d.Rule.ID}, nil
	})
}
