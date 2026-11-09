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

// BlockContext carries the structured facts of a block decision so a
// presentation layer can render the user-facing message. Interceptors
// populate it instead of composing message text themselves.
type BlockContext struct {
	Ecosystem      packagev1.Ecosystem
	PackageName    string
	PackageVersion string

	// For BlockReasonMalware and BlockReasonUserDeclined
	MalwareSummary      string
	MalwareReferenceURL string

	// For BlockReasonDependencyCooldown
	CooldownDays     int
	CooldownDaysAgo  int
	CooldownDaysLeft int
	// CooldownPolicyRevision is the revision of the cloud policy of the
	// tenant that set the cooldown. It is 0 when the local config set it.
	CooldownPolicyRevision uint64

	// For BlockReasonNetworkPolicy: the denied host:port and the rule.
	Destination string
	Rule        string

	// For BlockReasonPolicyRule: the block entry that matched.
	PolicyRule *PolicyRuleBlock
}

// PolicyRuleBlock is a block entry of the cloud policy of the tenant or of
// blocked_packages that blocked a request.
type PolicyRuleBlock struct {
	RuleID string
	Reason string

	// Cloud is true for a rule of the tenant policy. Revision and
	// DefaultPolicyRevision name that policy.
	Cloud                 bool
	Revision              uint64
	DefaultPolicyRevision uint64

	// File is the config file of a rule of blocked_packages.
	File string
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
