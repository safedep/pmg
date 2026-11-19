package proxy

import (
	"net/http"
	"net/url"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
)

// ResponseAction determines how the proxy should handle a request
type ResponseAction int

const (
	// ActionAllow forwards the request unchanged
	ActionAllow ResponseAction = iota

	// ActionBlock blocks the request with an error response
	ActionBlock

	// ActionModifyRequest modifies the request before forwarding
	ActionModifyRequest

	// ActionModifyResponse modifies the response after receiving
	ActionModifyResponse
)

// RequestContext provides request information to interceptors
// This is passed to ShouldIntercept and HandleRequest methods
type RequestContext struct {
	URL     *url.URL
	Method  string
	Headers http.Header

	// Body is not currently used by the interceptors, but it is here for future use
	Body []byte

	Hostname  string
	Port      string
	RequestID string
	StartTime time.Time

	Origin Origin

	// Interceptor can store custom data
	Data map[string]interface{}
}

// BlockReason identifies why an interceptor blocked a request
type BlockReason int

const (
	BlockReasonNone BlockReason = iota
	BlockReasonMalware
	BlockReasonUserDeclined
	BlockReasonConfirmationFailed
	BlockReasonDependencyCooldown
	BlockReasonNetworkPolicy
	BlockReasonPolicyRule
)

// blockReasonNames are the names of the reasons in JSON. A stored reason
// keeps its meaning when a new reason changes the order of the constants.
var blockReasonNames = map[BlockReason]string{
	BlockReasonNone:               "none",
	BlockReasonMalware:            "malware",
	BlockReasonUserDeclined:       "user_declined",
	BlockReasonConfirmationFailed: "confirmation_failed",
	BlockReasonDependencyCooldown: "dependency_cooldown",
	BlockReasonNetworkPolicy:      "network_policy",
	BlockReasonPolicyRule:         "policy_rule",
}

// MarshalText writes a reason with no name as "none". It never fails, because
// a failed write of the final daemon state would hide the blocks from
// `pmg proxy stop --fail-on-violation`.
func (r BlockReason) MarshalText() ([]byte, error) {
	name, ok := blockReasonNames[r]
	if !ok {
		name = blockReasonNames[BlockReasonNone]
	}
	return []byte(name), nil
}

// UnmarshalText reads an unknown name as BlockReasonNone, so a state file
// from a newer daemon stays readable.
func (r *BlockReason) UnmarshalText(text []byte) error {
	for reason, name := range blockReasonNames {
		if name == string(text) {
			*r = reason
			return nil
		}
	}
	*r = BlockReasonNone
	return nil
}

// BlockContext carries the structured facts of a block decision so a
// presentation layer can render the user-facing message. Interceptors
// populate it instead of composing message text themselves.
type BlockContext struct {
	Ecosystem      packagev1.Ecosystem `json:"ecosystem,omitempty"`
	PackageName    string              `json:"package_name,omitempty"`
	PackageVersion string              `json:"package_version,omitempty"`

	// For BlockReasonMalware and BlockReasonUserDeclined
	MalwareSummary      string `json:"malware_summary,omitempty"`
	MalwareReferenceURL string `json:"malware_reference_url,omitempty"`

	// For BlockReasonDependencyCooldown
	CooldownDays     int `json:"cooldown_days,omitempty"`
	CooldownDaysAgo  int `json:"cooldown_days_ago,omitempty"`
	CooldownDaysLeft int `json:"cooldown_days_left,omitempty"`
	// CooldownPolicyRevision is the revision of the cloud policy of the
	// tenant that set the cooldown. It is 0 when the local config set it.
	CooldownPolicyRevision uint64 `json:"cooldown_policy_revision,omitempty"`

	// For BlockReasonNetworkPolicy: the denied host:port and the rule.
	Destination string `json:"destination,omitempty"`
	Rule        string `json:"rule,omitempty"`

	// For BlockReasonPolicyRule: the block entry that matched.
	PolicyRule *PolicyRuleBlock `json:"policy_rule,omitempty"`
}

// PolicyRuleBlock is a block entry of the cloud policy of the tenant or of
// blocked_packages that blocked a request.
type PolicyRuleBlock struct {
	RuleID string `json:"rule_id,omitempty"`
	Reason string `json:"reason,omitempty"`

	// Cloud is true for a rule of the tenant policy. Revision and
	// DefaultPolicyRevision name that policy.
	Cloud                 bool   `json:"cloud,omitempty"`
	Revision              uint64 `json:"revision,omitempty"`
	DefaultPolicyRevision uint64 `json:"default_policy_revision,omitempty"`

	// File is the config file of a rule of blocked_packages.
	File string `json:"file,omitempty"`
}

// InterceptorResponse defines how the proxy should handle the request
type InterceptorResponse struct {
	// Action to take
	Action ResponseAction

	// For Action = Block: why and what was blocked. The proxy renders the
	// response body from these via ProxyConfig.BlockMessageRenderer.
	BlockReason  BlockReason
	BlockContext *BlockContext

	// BlockMessage overrides the rendered message when non-empty
	BlockMessage string
	BlockCode    int

	// For Action = ModifyRequest: modified headers/body
	ModifiedHeaders http.Header

	// ModifiedBody is not currently used by the interceptors, but it is here for future use
	ModifiedBody []byte

	// For Action = ModifyResponse: response modification function
	ResponseModifier ResponseModifierFunc
}

// ResponseModifierFunc modifies HTTP response
// It receives the status code, headers, and body, and returns modified versions
type ResponseModifierFunc func(statusCode int, headers http.Header, body []byte) (int, http.Header, []byte, error)

// Interceptor processes HTTP/HTTPS requests and can modify or block them
type Interceptor interface {
	// Name returns the interceptor name for logging
	Name() string

	// ShouldIntercept determines if this interceptor handles the given request
	ShouldIntercept(ctx *RequestContext) bool

	// HandleRequest processes the request and returns response action
	// Called for each request matching ShouldIntercept
	HandleRequest(ctx *RequestContext) (*InterceptorResponse, error)
}

// MITMDecider is optional; implement to control whether CONNECT requests are MITM’d.
type MITMDecider interface {
	ShouldMITM(ctx *RequestContext) bool
}
