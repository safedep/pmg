package proxy

import (
	"net"
	"net/http"
	"strconv"

	"github.com/elazarl/goproxy"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/proxy/netpolicy"
)

// NetworkDecision is one connection the proxy decided. Allowed is true
// when no deny rule matched, or when the proxy has no policy. Rule is the
// deny rule that matched. Enforced says whether the proxy refused the
// connection. Under audit the connection went through and the decision is
// the record.
type NetworkDecision struct {
	Host     string
	Port     uint16
	Allowed  bool
	Rule     string
	Enforced bool
	Origin   Origin
}

// connectDefaultPort is the port goproxy appends to a CONNECT target that
// names none, in its ConnectAccept path.
const connectDefaultPort = 80

// mitmSession is what the CONNECT handler leaves in goproxy's user data for
// the requests inside a terminated tunnel.
type mitmSession struct {
	origin Origin
	target string
}

// configureNetworkPolicy registers the policy checks. They run before the
// MITM and interceptor handlers, because goproxy stops at the first handler
// that returns a decision.
func (ps *proxyServer) configureNetworkPolicy() {
	ps.proxy.OnRequest().HandleConnect(goproxy.FuncHttpsHandler(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		// goproxy dials port 80 for a CONNECT target without a port, so the
		// decision is made on that port and not on 443. A port-specific deny
		// then covers what is dialed.
		hostname, port := splitTarget(host, connectDefaultPort)
		decision, refused := ps.decideNetwork(hostname, port, originFromContext(ctx.Req.Context()))
		if refused {
			// goproxy writes ctx.Resp to the client when a CONNECT is rejected.
			ctx.Resp = ps.networkDeniedResponse(ctx.Req, host, decision.Rule)
			return goproxy.RejectConnect, host
		}
		return nil, host
	}))

	// A request inside a terminated tunnel carries its own Host header, so
	// a client that tunnels to an allowed host and names another one is
	// decided again here.
	ps.proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		hostname := req.URL.Hostname()
		port := requestPort(req)
		if ps.insideDecidedTunnel(req, ctx, hostname, port) {
			return req, nil
		}

		decision, refused := ps.decideNetwork(hostname, port, originOfRequest(req, ctx.UserData))
		if refused {
			return req, ps.networkDeniedResponse(req, hostPort(hostname, port), decision.Rule)
		}
		return req, nil
	})
}

// decideNetwork runs the policy on one destination and reports whether the
// proxy must refuse the connection. Every destination is reported to the
// observer, so a run can propose a policy from what it reached. Without a
// policy every destination is allowed.
func (ps *proxyServer) decideNetwork(host string, port uint16, orig Origin) (NetworkDecision, bool) {
	// The record names the host as the transport dials it, so a report
	// and an event show the destination and not its spelling.
	host = netpolicy.NormalizeHost(host)
	decision := NetworkDecision{Host: host, Port: port, Allowed: true, Origin: orig}
	if ps.config.NetworkPolicy != nil {
		if d := ps.config.NetworkPolicy.Decide(host, port); !d.Allowed {
			decision.Allowed = false
			decision.Rule = d.Rule.Raw
			decision.Enforced = ps.config.NetworkEnforce
		}
	}
	if ps.config.OnNetworkDecision != nil {
		ps.config.OnNetworkDecision(decision)
	}
	if decision.Allowed {
		return decision, false
	}

	if decision.Enforced {
		log.Warnf("network policy denied %s by rule %q (%s)", hostPort(host, port), decision.Rule, orig)
	} else {
		log.Infof("network policy would deny %s by rule %q (%s)", hostPort(host, port), decision.Rule, orig)
	}
	return decision, decision.Enforced
}

// insideDecidedTunnel reports whether the request names the destination its
// tunnel was decided on, so one connection gets one decision.
func (ps *proxyServer) insideDecidedTunnel(req *http.Request, ctx *goproxy.ProxyCtx, host string, port uint16) bool {
	target := normalizedTarget(host, port)
	if s, ok := ctx.UserData.(mitmSession); ok {
		return s.target == target
	}
	if req.TLS != nil {
		tunnelPort := uint16(443)
		if orig := originFromContext(req.Context()); orig.IsValid() {
			tunnelPort = orig.Dst.Port()
		}
		return target == normalizedTarget(req.TLS.ServerName, tunnelPort)
	}
	return false
}

func (ps *proxyServer) networkDeniedResponse(req *http.Request, destination, rule string) *http.Response {
	message := "Connection to " + destination + " denied by the network policy"
	if ps.config.BlockMessageRenderer != nil {
		if m := ps.config.BlockMessageRenderer(BlockReasonNetworkPolicy, &BlockContext{Destination: destination, Rule: rule}); m != "" {
			message = m
		}
	}
	return blockResponse(req, http.StatusForbidden, message)
}

func splitTarget(hostport string, defaultPort uint16) (string, uint16) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport, defaultPort
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return host, defaultPort
	}
	return host, uint16(port)
}

func requestPort(req *http.Request) uint16 {
	if port, err := strconv.ParseUint(req.URL.Port(), 10, 16); err == nil {
		return uint16(port)
	}
	if req.URL.Scheme == "http" {
		return 80
	}
	return 443
}

func hostPort(host string, port uint16) string {
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

func normalizedTarget(host string, port uint16) string {
	return hostPort(netpolicy.NormalizeHost(host), port)
}

// blockResponse builds the response the proxy sends for a blocked request.
func blockResponse(req *http.Request, statusCode int, message string) *http.Response {
	r := goproxy.NewResponse(req, goproxy.ContentTypeText, statusCode, message)
	r.Close = true
	r.Header.Set("Connection", "close")
	r.Header.Set("Proxy-Connection", "close")

	return r
}
