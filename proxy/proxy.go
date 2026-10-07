package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/proxy/certmanager"
)

// defaultServerReadWriteTimeout is the default timeout for the http.Server's
// ReadTimeout and WriteTimeout. These deadlines persist on hijacked CONNECT
// tunnel connections, so this must be large enough for a full bulk install.
const defaultServerReadWriteTimeout = 30 * time.Minute

// defaultUpstreamRetries is the number of times an idempotent upstream
// request is retried when the round-trip fails before any response is
// received. Registries fronted by CDNs (e.g. Cloudflare for
// registry.npmjs.org) intermittently reset connections under the connection
// burst of a large "npm install". Retrying transparently here prevents a
// single transient reset from tearing down the whole keep-alive MITM tunnel
// (which surfaces to the client as a "socket hang up"/ECONNRESET).
const defaultUpstreamRetries = 2

// ProxyServer manages the proxy lifecycle
type ProxyServer interface {
	// Start begins listening on the configured address
	Start() error

	// Stop gracefully shuts down the proxy
	Stop(ctx context.Context) error

	// Address returns the listening address (useful when using port 0)
	Address() string

	// AdditionalAddresses returns the addresses of the listeners that
	// AdditionalListenAddrs opened, in order. An address the server could
	// not bind is absent.
	AdditionalAddresses() []string

	// AddInterceptor registers an interceptor
	AddInterceptor(interceptor Interceptor) error

	// RemoveInterceptor removes an interceptor by name
	RemoveInterceptor(name string)
}

// ProxyConfig holds configuration for the proxy server
type ProxyConfig struct {
	// Network configuration
	ListenAddr string

	// TLS configuration
	CertManager certmanager.CertificateManager

	// Interceptors
	Interceptors []Interceptor

	// BlockMessageRenderer composes the response body for blocked requests
	// from the interceptor's structured block decision. nil falls back to
	// the generic block message.
	BlockMessageRenderer func(BlockReason, *BlockContext) string

	// Other configuration
	EnableMITM     bool
	RequestTimeout time.Duration
	ConnectTimeout time.Duration

	// ServerReadWriteTimeout is the timeout applied to the http.Server's
	// ReadTimeout and WriteTimeout. These deadlines are set on the raw TCP
	// connection and persist after Hijack(), which means they become the
	// hard wall-clock limit for CONNECT tunnels (used for non-MITM traffic
	// like private registries). A bulk "npm install" can easily run for
	// 15-30 minutes, so this must be significantly larger than
	// RequestTimeout (which governs individual upstream round-trips for
	// MITM'd connections).
	//
	// If zero, defaults to 30 minutes.
	ServerReadWriteTimeout time.Duration

	// UpstreamRetries bounds retries of idempotent upstream requests on
	// transient round-trip failures. Zero disables retries.
	UpstreamRetries int

	// UpstreamDialContext, when set, replaces the default dialer for all upstream
	// connections — both MITM'd round-trips and the CONNECT tunnels used for
	// non-MITM hosts. Tests use it to redirect every hostname to a mock server so
	// no path reaches the network; production leaves it nil.
	UpstreamDialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	// UpstreamTLSClientConfig, when set, overrides the TLS config used for
	// upstream connections (e.g. to trust a mock registry's certificate). nil
	// keeps the production default.
	UpstreamTLSClientConfig *tls.Config

	// Transparent accepts clients that the kernel redirected to the listener
	// and that do not speak the proxy protocol. The listener sniffs each
	// connection: TLS to a registry host is terminated with CertManager, other
	// TLS is spliced to its destination, and origin-form HTTP is served as a
	// proxy request. Proxy-aware clients are unaffected. Off by default.
	Transparent bool

	// OriginalDestination recovers where a redirected client wanted to go.
	// The enforcement layer provides it. nil means the listener falls back to
	// the SNI or the Host header.
	OriginalDestination OriginalDestinationResolver

	// AdditionalListenAddrs are served by the same server as ListenAddr. A
	// port of 0 means the port ListenAddr got. The enforcing daemon uses it
	// for an IPv6 loopback listener on the same port. A bind failure here
	// is logged and skipped, so the primary listener still serves.
	AdditionalListenAddrs []string

	// OnCertificateRejected receives http.Server's log line when a client
	// aborts the TLS handshake because it does not trust the proxy
	// certificate, at most once a minute. The caller owns the words the
	// operator reads. nil means the log.
	OnCertificateRejected func(line string)

	// RedirectOnlyAddrs are the IP addresses among AdditionalListenAddrs
	// that serve redirected clients only. A connection to one of them
	// without an original destination was made on purpose, and is refused,
	// so a container cannot use the listener as a proxy with the host's
	// reachability.
	RedirectOnlyAddrs []string

	// Egress, when set, decides which destinations the proxy may forward to.
	// The proxy checks every CONNECT and every request. It cannot be used
	// with Transparent, because the splice path does not run the check.
	Egress EgressPolicy
}

// DefaultProxyConfig returns a configuration with sensible defaults
func DefaultProxyConfig() *ProxyConfig {
	return &ProxyConfig{
		ListenAddr:             "127.0.0.1:0",
		EnableMITM:             true,
		ConnectTimeout:         30 * time.Second,
		RequestTimeout:         5 * time.Minute,
		ServerReadWriteTimeout: defaultServerReadWriteTimeout,
		UpstreamRetries:        defaultUpstreamRetries,
		Interceptors:           []Interceptor{},
	}
}

type proxyServer struct {
	config       *ProxyConfig
	proxy        *goproxy.ProxyHttpServer
	server       *http.Server
	roundTripper goproxy.RoundTripper

	listener            net.Listener
	additionalListeners []net.Listener
	ownAddrs            []netip.AddrPort
	redirectOnly        map[netip.Addr]struct{}
	interceptors        map[string]Interceptor
	mu                  sync.RWMutex
}

var errDialSelf = errors.New("the proxy refuses to connect to its own listener")

// collectOwnAddrs lists every address a client can reach this proxy on. A
// listener on an unspecified address answers on every interface, so each
// interface address counts for its port.
func (ps *proxyServer) collectOwnAddrs() []netip.AddrPort {
	var own []netip.AddrPort
	for _, l := range append([]net.Listener{ps.listener}, ps.additionalListeners...) {
		if tcp, ok := l.Addr().(*net.TCPAddr); ok {
			own = append(own, ps.collectOwnAddrsFor(tcp.AddrPort())...)
		}
	}
	return own
}

// collectOwnAddrsFor lists the addresses that reach one listener. A dial to
// an unspecified address reaches a local listener on Linux, so those always
// count. A listener on an unspecified address answers on every interface.
func (ps *proxyServer) collectOwnAddrsFor(listen netip.AddrPort) []netip.AddrPort {
	port := listen.Port()
	addr := listen.Addr().Unmap()
	own := []netip.AddrPort{
		netip.AddrPortFrom(netip.IPv4Unspecified(), port),
		netip.AddrPortFrom(netip.IPv6Unspecified(), port),
	}
	if !addr.IsUnspecified() {
		return append(own, netip.AddrPortFrom(addr, port))
	}
	ifaddrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Warnf("Could not list interface addresses: %v", err)
		return own
	}
	for _, a := range ifaddrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(ipnet.IP); ok {
				own = append(own, netip.AddrPortFrom(ip.Unmap(), port))
			}
		}
	}
	return own
}

// isRedirectOnly reports whether the connection arrived on a listener that
// serves redirected clients only.
func (ps *proxyServer) isRedirectOnly(c net.Conn) bool {
	local, ok := c.LocalAddr().(*net.TCPAddr)
	if !ok {
		return false
	}
	_, only := ps.redirectOnly[local.AddrPort().Addr().Unmap()]
	return only
}

func (ps *proxyServer) isOwnAddress(addr netip.AddrPort) bool {
	return slices.Contains(ps.ownAddrs, netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port()))
}

// refuseOwnAddress is the dialer control for upstream connections. A
// request that names the proxy's own address, directly or through a name
// that resolves to it, would make the proxy forward to itself without
// limit. The dialer sees the resolved address, so a name cannot hide it.
func (ps *proxyServer) refuseOwnAddress(_, address string, _ syscall.RawConn) error {
	addr, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil
	}
	if ps.isOwnAddress(addr) {
		return errDialSelf
	}
	return nil
}

var _ ProxyServer = &proxyServer{}

// goproxyLoggerWrapper implements the goproxy.Logger interface and bridges to the dry/log package
type goproxyLoggerWrapper struct{}

func (l *goproxyLoggerWrapper) Printf(format string, v ...interface{}) {
	log.Debugf("[GOPROXY] "+format, v...)
}

// NewProxyServer creates a new proxy server with the given configuration
// using the goproxy library as the underlying proxy implementation
func NewProxyServer(config *ProxyConfig) (ProxyServer, error) {
	if config == nil {
		config = DefaultProxyConfig()
	}

	if config.EnableMITM && config.CertManager == nil {
		return nil, fmt.Errorf("cert manager is required when MITM is enabled")
	}

	if config.ListenAddr == "" {
		config.ListenAddr = "127.0.0.1:0"
	}

	ps := &proxyServer{
		config:       config,
		interceptors: make(map[string]Interceptor),
	}

	proxy := goproxy.NewProxyHttpServer()
	proxy.Logger = &goproxyLoggerWrapper{}
	proxy.Tr = newUpstreamTransport(config, ps.refuseOwnAddress)

	// goproxy emits several log lines per request when Verbose is set. During a
	// large install (5000+ packages) that is a substantial amount of per-request
	// formatting and allocation on the hot path, even though dry/log discards
	// the lines below the debug level. Only enable goproxy's verbose logging
	// when PMG itself is running at debug level so the cost is paid only when
	// the output is actually wanted.
	proxy.Verbose = strings.EqualFold(os.Getenv("APP_LOG_LEVEL"), "debug")

	proxy.ConnectDial = newConnectDial(proxy.Tr, config.ConnectTimeout)
	ps.proxy = proxy

	ps.roundTripper = goproxy.RoundTripperFunc(func(req *http.Request, _ *goproxy.ProxyCtx) (*http.Response, error) {
		return ps.upstreamRoundTrip(req)
	})

	for _, interceptor := range config.Interceptors {
		if err := ps.AddInterceptor(interceptor); err != nil {
			return nil, fmt.Errorf("failed to add interceptor %s: %w", interceptor.Name(), err)
		}
	}

	if config.Egress != nil {
		if config.Transparent {
			return nil, fmt.Errorf("egress policy cannot be used with the transparent listener")
		}
		ps.configureEgress()
	}

	if config.EnableMITM {
		ps.configureMITM()
	}

	ps.registerHandlers()
	proxy.NonproxyHandler = http.HandlerFunc(ps.serveTransparentRequest)

	return ps, nil
}

func proxyWithLoopbackBypass(req *http.Request) (*url.URL, error) {
	host := req.URL.Hostname()
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return nil, nil
	}

	return http.ProxyFromEnvironment(req)
}

// newUpstreamTransport builds the upstream transport. control runs on every
// dial with the resolved address, so the proxy never connects to itself.
func newUpstreamTransport(config *ProxyConfig, control func(network, address string, c syscall.RawConn) error) *http.Transport {
	dialer := &net.Dialer{
		Timeout: config.ConnectTimeout,
		Control: control,
	}

	dialContext := dialer.DialContext
	if config.UpstreamDialContext != nil {
		dialContext = config.UpstreamDialContext
	}

	tlsClientConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false,
	}
	if config.UpstreamTLSClientConfig != nil {
		tlsClientConfig = config.UpstreamTLSClientConfig
	}

	// Proxy honours the environment (HTTP_PROXY, HTTPS_PROXY, NO_PROXY) so
	// that PMG works in enterprise environments that require a corporate
	// upstream proxy to reach the internet. Loopback addresses are always
	// bypassed to avoid routing localhost traffic through an external proxy,
	// which would fail because the proxy can't reach the user's localhost.
	//
	// ForceAttemptHTTP2 is required because Go's http.Transport silently
	// disables HTTP/2 when a custom TLSClientConfig or DialContext is set.
	// Without it, every proxied request opens a separate HTTP/1.1 TCP+TLS
	// connection to the upstream registry. During npm install of large
	// projects (1000+ packages), this creates a burst of concurrent
	// connections that triggers rate-limiting (RST) from CDNs like
	// Cloudflare (which fronts registry.npmjs.org). HTTP/2 multiplexing
	// allows hundreds of requests to share a few TCP connections.
	//
	// MaxConnsPerHost caps concurrent connections per upstream host to
	// prevent overwhelming registries even if HTTP/2 is not negotiated.
	// MaxIdleConnsPerHost is raised from the default of 2 to improve
	// connection reuse.
	return &http.Transport{
		Proxy:                 proxyWithLoopbackBypass,
		DialContext:           dialContext,
		ForceAttemptHTTP2:     true,
		MaxConnsPerHost:       100,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   50,
		IdleConnTimeout:       120 * time.Second,
		TLSHandshakeTimeout:   config.ConnectTimeout,
		ResponseHeaderTimeout: config.RequestTimeout,
		TLSClientConfig:       tlsClientConfig,
	}
}

func (ps *proxyServer) Start() error {
	redirectOnly := make(map[netip.Addr]struct{}, len(ps.config.RedirectOnlyAddrs))
	for _, raw := range ps.config.RedirectOnlyAddrs {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			return fmt.Errorf("redirect-only address %q: %w", raw, err)
		}
		redirectOnly[addr.Unmap()] = struct{}{}
	}

	listener, err := net.Listen("tcp", ps.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to start listener: %w", err)
	}

	ps.listener = listener
	ps.additionalListeners = ps.listenAdditional(listener.Addr().(*net.TCPAddr).Port)
	ps.ownAddrs = ps.collectOwnAddrs()
	ps.redirectOnly = redirectOnly

	serverTimeout := ps.config.ServerReadWriteTimeout
	if serverTimeout == 0 {
		serverTimeout = defaultServerReadWriteTimeout
	}

	ps.server = &http.Server{
		Handler:      ps.proxy,
		ReadTimeout:  serverTimeout,
		WriteTimeout: serverTimeout,
		ConnContext:  transparentConnContext,
		ErrorLog:     newServerLog(ps.config.OnCertificateRejected),
	}

	log.Debugf("Proxy server listening on %s", ps.Address())

	for _, l := range append([]net.Listener{listener}, ps.additionalListeners...) {
		ps.serve(l)
	}

	return nil
}

func (ps *proxyServer) serve(l net.Listener) {
	if ps.config.Transparent {
		l = newTransparentListener(l, ps)
	}
	go func() {
		if err := ps.server.Serve(l); err != nil && err != http.ErrServerClosed {
			log.Errorf("Proxy server error on %s: %v", l.Addr(), err)
		}
	}()
}

// listenAdditional binds the extra addresses. A port of 0 takes the primary
// port, so every listener of one proxy answers on the same port.
func (ps *proxyServer) listenAdditional(primaryPort int) []net.Listener {
	var listeners []net.Listener
	for _, addr := range ps.config.AdditionalListenAddrs {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			log.Warnf("Skipping additional listen address %q: %v", addr, err)
			continue
		}
		if port == "0" {
			port = strconv.Itoa(primaryPort)
		}
		l, err := net.Listen("tcp", net.JoinHostPort(host, port))
		if err != nil {
			log.Warnf("Skipping additional listen address %q: %v", addr, err)
			continue
		}
		listeners = append(listeners, l)
	}
	return listeners
}

func (ps *proxyServer) Stop(ctx context.Context) error {
	if ps.server == nil {
		return nil
	}

	log.Debugf("Shutting down proxy server...")

	if err := ps.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("failed to shutdown proxy server: %w", err)
	}

	return nil
}

func (ps *proxyServer) Address() string {
	if ps.listener == nil {
		return ""
	}

	return ps.listener.Addr().String()
}

func (ps *proxyServer) AdditionalAddresses() []string {
	addrs := make([]string, 0, len(ps.additionalListeners))
	for _, l := range ps.additionalListeners {
		addrs = append(addrs, l.Addr().String())
	}
	return addrs
}

func (ps *proxyServer) AddInterceptor(interceptor Interceptor) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if _, ok := ps.interceptors[interceptor.Name()]; ok {
		return fmt.Errorf("interceptor %s already registered", interceptor.Name())
	}

	ps.interceptors[interceptor.Name()] = interceptor
	log.Debugf("Registered interceptor: %s", interceptor.Name())

	return nil
}

func (ps *proxyServer) RemoveInterceptor(name string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	delete(ps.interceptors, name)
	log.Debugf("Removed interceptor: %s", name)
}

func (ps *proxyServer) configureMITM() {
	// Configure selective MITM based on interceptors
	ps.proxy.OnRequest().HandleConnect(goproxy.FuncHttpsHandler(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		orig := originFromContext(ctx.Req.Context())
		ctx.UserData = orig
		if ps.shouldMITM(host, "CONNECT", orig) {
			mitmAction := &goproxy.ConnectAction{
				Action: goproxy.ConnectMitm,
				TLSConfig: func(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error) {
					hostname, _, err := net.SplitHostPort(host)
					if err != nil {
						hostname = host
					}

					return ps.config.CertManager.GetTLSConfig(hostname)
				},
			}

			return mitmAction, host
		}

		return goproxy.OkConnect, host
	}))
}

// shouldMITM asks the interceptors whether a tunnel to host:port must be
// terminated. Interceptors that observe but never MITM, such as telemetry,
// see the tunnel through HandleRequest, with the origin of the connection.
// The CONNECT handler and the transparent listener share this decision, so
// a redirected client and a proxy-aware client get the same answer for the
// same host.
func (ps *proxyServer) shouldMITM(host, via string, orig Origin) bool {
	reqCtx, err := newRequestContextFromURL(host, "CONNECT")
	if err != nil {
		log.Errorf("Failed to parse %s request for %s: %v", via, host, err)
		return false
	}
	reqCtx.Origin = orig

	ps.mu.RLock()
	defer ps.mu.RUnlock()

	shouldMITM := false
	for _, interceptor := range ps.interceptors {
		if !interceptor.ShouldIntercept(reqCtx) {
			continue
		}

		mitm := true
		if decider, ok := interceptor.(MITMDecider); ok {
			mitm = decider.ShouldMITM(reqCtx)
		}

		if !mitm {
			if _, err := interceptor.HandleRequest(reqCtx); err != nil {
				log.Errorf("[%s] Interceptor %s error on %s: %v", reqCtx.RequestID, interceptor.Name(), via, err)
			}
			continue
		}

		shouldMITM = true
		log.Debugf("[%s] Interceptor %s will handle %s", reqCtx.RequestID, interceptor.Name(), host)
	}

	if !shouldMITM {
		log.Debugf("[%s] Tunneling %s (no interceptor)", reqCtx.RequestID, host)
	}
	return shouldMITM
}

// upstreamRoundTrip executes the upstream round-trip with bounded retries for
// idempotent requests. goproxy tears down the entire client MITM tunnel when a
// single round-trip returns an error (see handleHttps in goproxy), so a lone
// transient upstream reset would otherwise drop a pooled keep-alive connection
// and surface as a "socket hang up"/ECONNRESET to the package manager. Retrying
// here absorbs those transient failures and keeps the tunnel alive.
//
// Only requests that can be safely replayed are retried: idempotent methods
// with no request body, and only while the client request context is live.
func (ps *proxyServer) upstreamRoundTrip(req *http.Request) (*http.Response, error) {
	maxRetries := ps.config.UpstreamRetries
	if maxRetries < 0 {
		maxRetries = 0
	}

	var resp *http.Response
	var err error

	for attempt := 0; ; attempt++ {
		resp, err = ps.proxy.Tr.RoundTrip(req)
		if err == nil {
			return resp, nil
		}

		if attempt >= maxRetries || !isReplayableRequest(req) || req.Context().Err() != nil {
			return resp, err
		}

		// Linear backoff capped at 500ms to avoid adding meaningful latency
		// while still spacing out retries against a struggling upstream.
		backoff := time.Duration(attempt+1) * 50 * time.Millisecond
		if backoff > 500*time.Millisecond {
			backoff = 500 * time.Millisecond
		}

		log.Debugf("Retrying upstream %s %s after transient error (attempt %d/%d): %v",
			req.Method, req.URL.Host, attempt+1, maxRetries, err)

		select {
		case <-time.After(backoff):
		case <-req.Context().Done():
			return resp, err
		}
	}
}

// isReplayableRequest reports whether a request can be safely retried after an
// upstream failure. Only idempotent methods without a body qualify, which
// covers registry metadata reads and tarball downloads.
func isReplayableRequest(req *http.Request) bool {
	switch req.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
	default:
		return false
	}

	return req.Body == nil || req.Body == http.NoBody
}

func (ps *proxyServer) registerHandlers() {
	ps.proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		ctx.RoundTripper = ps.roundTripper

		reqCtx, err := newRequestContext(req)
		if err != nil {
			log.Errorf("Failed to create request context: %v", err)
			return req, nil
		}
		reqCtx.Origin = originOfRequest(req, ctx.UserData)

		log.Debugf("[%s] %s %s", reqCtx.RequestID, req.Method, req.URL.String())

		ps.mu.RLock()
		defer ps.mu.RUnlock()

		for _, interceptor := range ps.interceptors {
			if !interceptor.ShouldIntercept(reqCtx) {
				continue
			}

			resp, err := interceptor.HandleRequest(reqCtx)
			if err != nil {
				log.Errorf("[%s] Interceptor %s error: %v", reqCtx.RequestID, interceptor.Name(), err)
				continue
			}

			if resp == nil {
				continue
			}

			switch resp.Action {
			case ActionBlock:
				statusCode := resp.BlockCode
				if statusCode == 0 {
					statusCode = http.StatusForbidden
				}

				message := resp.BlockMessage
				if message == "" && ps.config.BlockMessageRenderer != nil {
					message = ps.config.BlockMessageRenderer(resp.BlockReason, resp.BlockContext)
				}
				if message == "" {
					message = "Blocked by proxy interceptor"
				}

				log.Debugf("[%s] Blocked by %s: %s", reqCtx.RequestID, interceptor.Name(), req.URL.String())
				return req, blockResponse(req, statusCode, message)

			case ActionModifyRequest:
				if resp.ModifiedHeaders != nil {
					req.Header = resp.ModifiedHeaders
				}

				log.Debugf("[%s] Request modified by %s", reqCtx.RequestID, interceptor.Name())

			case ActionModifyResponse:
				ctx.UserData = resp.ResponseModifier
				log.Debugf("[%s] Response modifier registered by %s", reqCtx.RequestID, interceptor.Name())
			}
		}

		return req, nil
	})

	ps.proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if resp == nil {
			return resp
		}

		// When the upstream transport negotiates HTTP/2, responses arrive with
		// Proto "HTTP/2.0" and ProtoMajor 2. goproxy writes MITM responses via
		// resp.Write(), which serialises the status line verbatim. An HTTP/1.1
		// client (pip, npm, etc.) rejects the "HTTP/2.0 200 OK" status line and
		// resets the connection. Normalise to HTTP/1.1 so the response is valid
		// for the downstream MITM connection.
		if resp.ProtoMajor != 1 {
			resp.Proto = "HTTP/1.1"
			resp.ProtoMajor = 1
			resp.ProtoMinor = 1
		}

		reqCtx, err := newRequestContext(ctx.Req)
		if err != nil {
			log.Errorf("Failed to create request context: %v", err)
			return resp
		}

		log.Debugf("[%s] Response received for %s", reqCtx.RequestID, ctx.Req.URL.String())

		modifier, ok := ctx.UserData.(ResponseModifierFunc)
		if !ok || modifier == nil {
			return resp
		}

		body, err := io.ReadAll(resp.Body)
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Warnf("[%s] Failed to close response body: %v", reqCtx.RequestID, closeErr)
		}
		if err != nil {
			log.Errorf("[%s] Failed to read response body for modifier: %v", reqCtx.RequestID, err)
			errMsg := []byte("PMG: failed to read response from upstream registry")
			resp.StatusCode = http.StatusServiceUnavailable
			resp.Status = ""
			resp.Body = io.NopCloser(bytes.NewReader(errMsg))
			resp.ContentLength = int64(len(errMsg))
			return resp
		}

		newStatusCode, newHeaders, newBody, err := modifier(resp.StatusCode, resp.Header, body)
		if err != nil {
			log.Errorf("[%s] Response modifier error: %v", reqCtx.RequestID, err)
			resp.Body = io.NopCloser(bytes.NewReader(body))
			resp.ContentLength = int64(len(body))
			return resp
		}

		resp.StatusCode = newStatusCode
		resp.Status = ""
		resp.Header = newHeaders
		resp.Body = io.NopCloser(bytes.NewReader(newBody))
		resp.ContentLength = int64(len(newBody))

		return resp
	})
}
