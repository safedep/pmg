package proxy

import (
	"net/http"
	"net/url"
	"time"
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
	RequestID string
	StartTime time.Time

	// Interceptor can store custom data
	Data map[string]interface{}
}

// InterceptorResponse defines how the proxy should handle the request
type InterceptorResponse struct {
	// Action to take
	Action ResponseAction

	// For Action = Block: error message to return
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
