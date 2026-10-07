package proxy

import (
	"net"
	"net/http"
	"strconv"

	"github.com/elazarl/goproxy"
	"github.com/safedep/dry/log"
)

// EgressPolicy decides whether the proxy may forward to host:port.
type EgressPolicy interface {
	Allows(host string, port uint16) bool
}

// configureEgress registers the egress checks. It must run before the MITM
// and interceptor handlers are registered, because goproxy stops at the first
// handler that returns a decision.
//
// The checks use the destination the client asked for, not the dialed
// address. With an upstream corporate proxy the dialed address is that proxy.
func (ps *proxyServer) configureEgress() {
	ps.proxy.OnRequest().HandleConnect(goproxy.FuncHttpsHandler(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		hostname, port, err := net.SplitHostPort(host)
		if err == nil && ps.egressAllows(hostname, port) {
			return nil, host
		}

		// goproxy writes ctx.Resp to the client when a CONNECT is rejected.
		ctx.Resp = ps.egressDenied(ctx.Req, host)
		return goproxy.RejectConnect, host
	}))

	// Inside a MITM tunnel goproxy builds req.URL from the inner Host
	// header, so this check also covers a request that names another host.
	ps.proxy.OnRequest().DoFunc(func(req *http.Request, _ *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		port := req.URL.Port()
		if port == "" {
			port = defaultPortForScheme(req.URL.Scheme)
		}
		if ps.egressAllows(req.URL.Hostname(), port) {
			return req, nil
		}
		return req, ps.egressDenied(req, net.JoinHostPort(req.URL.Hostname(), port))
	})
}

func (ps *proxyServer) egressAllows(host, port string) bool {
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || host == "" {
		return false
	}
	return ps.config.Egress.Allows(host, uint16(p))
}

func (ps *proxyServer) egressDenied(req *http.Request, destination string) *http.Response {
	log.Warnf("Proxy denied the connection to %s by the sandbox outbound rules", destination)

	message := "Blocked by sandbox outbound rules: " + destination
	if ps.config.BlockMessageRenderer != nil {
		if m := ps.config.BlockMessageRenderer(BlockReasonEgressDenied, &BlockContext{Destination: destination}); m != "" {
			message = m
		}
	}
	return blockResponse(req, http.StatusForbidden, message)
}

func defaultPortForScheme(scheme string) string {
	if scheme == "http" {
		return "80"
	}
	return "443"
}

// blockResponse builds the response the proxy sends for a blocked request.
func blockResponse(req *http.Request, statusCode int, message string) *http.Response {
	r := goproxy.NewResponse(req, goproxy.ContentTypeText, statusCode, message)

	// goproxy v1.8.x writes the response via (*http.Response).Write for MITM traffic.
	// Ensure the protocol version is valid (defaults to HTTP/0.0 otherwise).
	// Ref: https://github.com/elazarl/goproxy/issues/745
	if req.ProtoMajor > 0 {
		r.Proto = req.Proto
		r.ProtoMajor = req.ProtoMajor
		r.ProtoMinor = req.ProtoMinor
	} else {
		r.Proto = "HTTP/1.1"
		r.ProtoMajor = 1
		r.ProtoMinor = 1
	}
	r.Close = true
	r.Header.Set("Connection", "close")
	r.Header.Set("Proxy-Connection", "close")

	return r
}
