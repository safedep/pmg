// Package cloudpolicytest writes a policy cache for tests. It commits the
// cache through a configsync.Fetcher with a stub transport, so a test uses
// the cache layout of configsync and never writes the files itself.
package cloudpolicytest

import (
	"context"
	"fmt"
	"time"

	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
	corev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/policy/core/v1"
	packageadmissionv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/policy/packageadmission/v1"
	recordv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/policy/record/v1"
	specv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/policy/spec/v1"
	policyv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/controltower/policy/v1"
	"github.com/safedep/dry/cloud/configsync"
	"github.com/safedep/dry/cloud/endpointsync"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Policy returns a resolved policy with the package rules and no header.
func Policy(rules ...*corev1.PackageRule) *specv1.ResolvedPolicy {
	return specv1.ResolvedPolicy_builder{
		Spec: specv1.PolicySpec_builder{
			Core: corev1.Core_builder{PackageRules: rules}.Build(),
		}.Build(),
	}.Build()
}

// WithCooldown sets the dependency cooldown of policy, as the base layer of
// the tenant sets it.
func WithCooldown(policy *specv1.ResolvedPolicy, minAge time.Duration) *specv1.ResolvedPolicy {
	policy.GetSpec().SetPackageAdmission(packageadmissionv1.PackageAdmission_builder{
		Cooldown: packageadmissionv1.Cooldown_builder{MinAge: durationpb.New(minAge)}.Build(),
	}.Build())
	policy.SetFieldSources(append(policy.GetFieldSources(), specv1.FieldSource_builder{
		Path:  "package_admission.cooldown.min_age",
		Layer: recordv1.Layer_LAYER_BASE,
	}.Build()))
	return policy
}

// Block returns a block entry. vers can be empty.
func Block(id, purl, vers, reason string) *corev1.PackageRule {
	return corev1.PackageRule_builder{
		RuleId:   id,
		Selector: selector(purl, vers),
		Effect:   corev1.Effect_EFFECT_BLOCK,
		Reason:   reason,
	}.Build()
}

// Trust returns a trust entry that expires at expires.
func Trust(id, purl, vers string, expires time.Time, scopes ...corev1.TrustScope) *corev1.PackageRule {
	return corev1.PackageRule_builder{
		RuleId:    id,
		Selector:  selector(purl, vers),
		Effect:    corev1.Effect_EFFECT_TRUST,
		Scopes:    scopes,
		Reason:    "reviewed",
		ExpiresAt: timestamppb.New(expires),
	}.Build()
}

// WithVulnerabilities sets the vulnerabilities that a trust entry with the
// scope TRUST_SCOPE_NAMED_VULNERABILITY waives. The contract drops such an
// entry when it has no ids.
func WithVulnerabilities(rule *corev1.PackageRule, ids ...string) *corev1.PackageRule {
	var waived []*corev1.WaivedVulnerability
	for _, id := range ids {
		waived = append(waived, corev1.WaivedVulnerability_builder{Id: id}.Build())
	}
	rule.SetVulnerabilities(waived)
	return rule
}

func selector(purl, vers string) *corev1.PackageSelector {
	b := corev1.PackageSelector_builder{Purl: purl}
	if vers != "" {
		b.Vers = &vers
	}
	return b.Build()
}

// Header is the header of a policy for an endpoint.
type Header struct {
	Tenant                string
	MachineID             string
	Revision              uint64
	DefaultPolicyRevision uint64
}

// Marshal sets the header of policy and returns its bytes on the wire.
func Marshal(policy *specv1.ResolvedPolicy, header Header) ([]byte, error) {
	policy = proto.CloneOf(policy)
	policy.SetHeader(specv1.ResolvedPolicyHeader_builder{
		Tenant: header.Tenant,
		Subject: specv1.Subject_builder{
			Kind: specv1.SubjectKind_SUBJECT_KIND_ENDPOINT,
			Id:   "ep_test",
		}.Build(),
		Revision:              header.Revision,
		DefaultPolicyRevision: header.DefaultPolicyRevision,
		IssuedAt:              timestamppb.Now(),
		MachineId:             header.MachineID,
	}.Build())
	return proto.Marshal(policy)
}

// Commit writes raw as the current policy of the cache in dir, for tenant,
// at revision. It accepts the bytes as they are, so a test can also write a
// policy that the loader of pmg rejects.
func Commit(dir, tenant string, raw []byte, revision uint64) error {
	store, err := configsync.NewStore(dir, configsync.WithTenant(tenant))
	if err != nil {
		return err
	}
	fetcher, err := configsync.NewFetcher(store, reply{raw: raw, revision: revision})
	if err != nil {
		return err
	}
	_, err = fetcher.Fetch(context.Background(), configsync.FetchRequest{
		Endpoint: controltowerv1.EndpointIdentity_builder{Identifier: "test", MachineId: "test"}.Build(),
		Labels:   endpointsync.ReportedLabels(),
		ToolName: "pmg",
		Validate: func([]byte) (configsync.Accepted, error) { return configsync.Accepted{}, nil },
	})
	if err != nil {
		return fmt.Errorf("commit the policy cache: %w", err)
	}
	return nil
}

// Write sets the header of policy and commits it as the cache in dir.
func Write(dir string, policy *specv1.ResolvedPolicy, header Header) error {
	raw, err := Marshal(policy, header)
	if err != nil {
		return err
	}
	return Commit(dir, header.Tenant, raw, header.Revision)
}

// MachineID returns the machine id that pmg sends with the endpoint id
// endpointID, so a test can write a header that the loader accepts.
func MachineID(endpointID string) (string, error) {
	identity, err := endpointsync.NewEndpointIdentityResolver(endpointsync.WithEndpointID(endpointID)).Resolve()
	if err != nil {
		return "", err
	}
	return identity.GetMachineId(), nil
}

// reply is a transport that always sends one policy.
type reply struct {
	raw      []byte
	revision uint64
}

func (r reply) GetResolvedPolicy(context.Context, *policyv1.GetResolvedPolicyRequest) (*policyv1.GetResolvedPolicyResponse, error) {
	return policyv1.GetResolvedPolicyResponse_builder{
		Status:         policyv1.ResolvedPolicyStatus_RESOLVED_POLICY_STATUS_MODIFIED,
		ResolvedPolicy: r.raw,
		Digest:         configsync.Digest(r.raw),
		Revision:       r.revision,
	}.Build(), nil
}
