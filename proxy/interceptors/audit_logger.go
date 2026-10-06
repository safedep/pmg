package interceptors

import (
	"strconv"

	"github.com/safedep/dry/log"
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

	audit.LogProxyHostObserved(hostObservation(ctx), "audit_logger_interceptor", map[string]interface{}{
		"request_id": ctx.RequestID,
	})
	return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
}

func hostObservation(ctx *proxy.RequestContext) audit.HostObservation {
	obs := audit.HostObservation{
		Hostname:   ctx.Hostname,
		Method:     ctx.Method,
		Port:       observedPort(ctx),
		EntryPoint: audit.ProxyEntryPoint(ctx.Origin.EntryPoint),
		Client:     audit.ProxyClient{PID: ctx.Origin.PID, Comm: ctx.Origin.Comm, Exe: ctx.Origin.Exe},
	}
	if ctx.Origin.Address.IsValid() {
		obs.Client.Address = ctx.Origin.Address.String()
	}
	return obs
}

// observedPort is the port the client asked for. A URL without one means
// the scheme's default. A port outside the range is unknown, so the event
// leaves it out rather than record a wrong one.
func observedPort(ctx *proxy.RequestContext) uint16 {
	if ctx.Port == "" {
		if ctx.URL != nil && ctx.URL.Scheme == "http" {
			return 80
		}
		return 443
	}
	p, err := strconv.ParseUint(ctx.Port, 10, 16)
	if err != nil {
		log.Warnf("audit: port %q of %s is not a port: %v", ctx.Port, ctx.Hostname, err)
		return 0
	}
	return uint16(p)
}

func (i *AuditLoggerInterceptor) isKnownRegistryRequest(ctx *proxy.RequestContext) bool {
	return i != nil && i.registries != nil && i.registries.IsKnownRegistryRequest(ctx)
}

var wellKnownGoHosts = map[string]bool{
	"proxy.golang.org": true,
	"sum.golang.org":   true,
}
