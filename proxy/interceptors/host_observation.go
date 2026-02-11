package interceptors

import (
	"github.com/safedep/pmg/internal/eventlog"
	"github.com/safedep/pmg/proxy"
)

// HostObservationInterceptor logs unknown outbound hosts observed by proxy mode.
// It is passive telemetry only and never blocks or mutates requests.
type HostObservationInterceptor struct{}

var _ proxy.Interceptor = (*HostObservationInterceptor)(nil)

func NewHostObservationInterceptor() *HostObservationInterceptor {
	return &HostObservationInterceptor{}
}

func (i *HostObservationInterceptor) Name() string {
	return "host-observation-interceptor"
}

// ShouldIntercept is always true so we can observe all proxied traffic.
func (i *HostObservationInterceptor) ShouldIntercept(_ *proxy.RequestContext) bool {
	return true
}

// ShouldMITM is false because this interceptor is telemetry-only.
func (i *HostObservationInterceptor) ShouldMITM(_ *proxy.RequestContext) bool {
	return false
}

func (i *HostObservationInterceptor) HandleRequest(ctx *proxy.RequestContext) (*proxy.InterceptorResponse, error) {
	if ctx == nil || ctx.Hostname == "" {
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	if i.isKnownRegistryHost(ctx.Hostname) {
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	eventlog.LogProxyHostObserved(ctx.Hostname, ctx.Method, "host_observation_interceptor", map[string]interface{}{
		"request_id": ctx.RequestID,
	})

	return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
}

func (i *HostObservationInterceptor) isKnownRegistryHost(hostname string) bool {
	return npmRegistryDomains.ContainsHostname(hostname) || pypiRegistryDomains.ContainsHostname(hostname)
}
