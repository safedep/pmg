package interceptors

import (
	"github.com/safedep/pmg/internal/audit"
	"github.com/safedep/pmg/proxy"
)

// AuditLoggerInterceptor logs unknown outbound hosts observed by proxy mode.
// It is passive telemetry only and never blocks or mutates requests.
type AuditLoggerInterceptor struct{}

var _ proxy.Interceptor = (*AuditLoggerInterceptor)(nil)
var _ proxy.MITMDecider = (*AuditLoggerInterceptor)(nil)

func NewAuditLoggerInterceptor() *AuditLoggerInterceptor {
	return &AuditLoggerInterceptor{}
}

func (i *AuditLoggerInterceptor) Name() string {
	return "audit-logger-interceptor"
}

// ShouldIntercept is always true so we can observe all proxied traffic.
func (i *AuditLoggerInterceptor) ShouldIntercept(_ *proxy.RequestContext) bool {
	return true
}

// ShouldMITM is false because this interceptor is telemetry-only.
func (i *AuditLoggerInterceptor) ShouldMITM(_ *proxy.RequestContext) bool {
	return false
}

func (i *AuditLoggerInterceptor) HandleRequest(ctx *proxy.RequestContext) (*proxy.InterceptorResponse, error) {
	if ctx == nil || ctx.Hostname == "" {
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	if i.isKnownRegistryHost(ctx.Hostname) {
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	audit.LogProxyHostObserved(ctx.Hostname, ctx.Method, "audit_logger_interceptor", map[string]interface{}{
		"request_id": ctx.RequestID,
	})

	return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
}

// wellKnownGoHosts are the default Go module-proxy and checksum-database
// hosts. Custom GOPROXY hosts are dynamic (known only to the Go interceptor's
// per-run config) and intentionally still surface here as observed hosts.
var wellKnownGoHosts = map[string]bool{
	"proxy.golang.org": true,
	"sum.golang.org":   true,
}

func (i *AuditLoggerInterceptor) isKnownRegistryHost(hostname string) bool {
	return npmRegistryDomains.ContainsHostname(hostname) ||
		pypiRegistryDomains.ContainsHostname(hostname) ||
		wellKnownGoHosts[hostname]
}
