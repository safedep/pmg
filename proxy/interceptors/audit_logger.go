package interceptors

import (
	"github.com/safedep/pmg/internal/audit"
	"github.com/safedep/pmg/proxy"
)

type AuditLoggerInterceptor struct {
	registries *RegistryCatalog
}

var _ proxy.Interceptor = (*AuditLoggerInterceptor)(nil)
var _ proxy.MITMDecider = (*AuditLoggerInterceptor)(nil)

func NewAuditLoggerInterceptor(registries *RegistryCatalog) *AuditLoggerInterceptor {
	if registries == nil {
		registries = newBuiltInRegistryCatalog()
	}
	return &AuditLoggerInterceptor{registries: registries}
}

func (i *AuditLoggerInterceptor) Name() string {
	return "audit-logger-interceptor"
}

func (i *AuditLoggerInterceptor) ShouldIntercept(_ *proxy.RequestContext) bool {
	return true
}

func (i *AuditLoggerInterceptor) ShouldMITM(_ *proxy.RequestContext) bool {
	return false
}

func (i *AuditLoggerInterceptor) HandleRequest(ctx *proxy.RequestContext) (*proxy.InterceptorResponse, error) {
	if ctx == nil || ctx.Hostname == "" || i.isKnownRegistryRequest(ctx) {
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
	}

	audit.LogProxyHostObserved(ctx.Hostname, ctx.Method, "audit_logger_interceptor", map[string]interface{}{
		"request_id": ctx.RequestID,
	})
	return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
}

func (i *AuditLoggerInterceptor) isKnownRegistryRequest(ctx *proxy.RequestContext) bool {
	return i != nil && i.registries != nil && i.registries.IsKnownRegistryRequest(ctx)
}

var wellKnownGoHosts = map[string]bool{
	"proxy.golang.org": true,
	"sum.golang.org":   true,
}
