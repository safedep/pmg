package interceptors

import (
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/audit"
	"github.com/safedep/pmg/internal/registryurl"
	"github.com/safedep/pmg/proxy"
)

type AuditLoggerInterceptor struct {
	customRegistryOrigins map[string]struct{}
}

var _ proxy.Interceptor = (*AuditLoggerInterceptor)(nil)
var _ proxy.MITMDecider = (*AuditLoggerInterceptor)(nil)

// NewAuditLoggerInterceptor takes the user-configured registries and
// scopes suppression to their configured origins (an endpoint on :8443
// must not hide observations on :443). Built-in suppression stays
// hostname-only.
func NewAuditLoggerInterceptor(registries []config.ProxyRegistryConfig) *AuditLoggerInterceptor {
	set := make(map[string]struct{})
	for _, origin := range customRegistryOrigins(registries) {
		set[origin] = struct{}{}
	}
	return &AuditLoggerInterceptor{customRegistryOrigins: set}
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

	if i.IsKnownRegistryHost(ctx.Hostname, ctx.Port) {
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

// IsKnownRegistryHost reports whether host observations should be suppressed.
// Custom origins are scoped to host:effectivePort; a CONNECT names the port
// in the authority, so the check is exact. Built-in suppression is
// hostname-only.
func (i *AuditLoggerInterceptor) IsKnownRegistryHost(hostname, port string) bool {
	hostname = normalizeHostnameWithOptionalPort(hostname)
	effectivePort, ok := registryurl.EffectivePort("https", port)
	if ok {
		if _, exists := i.customRegistryOrigins[registryOrigin(hostname, effectivePort)]; exists {
			return true
		}
	}
	return npmRegistryDomains.ContainsHostname(hostname) ||
		pypiRegistryDomains.ContainsHostname(hostname) ||
		wellKnownGoHosts[hostname]
}
