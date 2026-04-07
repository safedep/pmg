package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/proxy/certmanager"
)

// defaultServerReadWriteTimeout is the default timeout for the http.Server's
// ReadTimeout and WriteTimeout. These deadlines persist on hijacked CONNECT
// tunnel connections, so this must be large enough for a full bulk install.
const defaultServerReadWriteTimeout = 30 * time.Minute

// ProxyServer manages the proxy lifecycle
type ProxyServer interface {
	// Start begins listening on the configured address
	Start() error

	// Stop gracefully shuts down the proxy
	Stop(ctx context.Context) error

	// Address returns the listening address (useful when using port 0)
	Address() string

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
}

// DefaultProxyConfig returns a configuration with sensible defaults
func DefaultProxyConfig() *ProxyConfig {
	return &ProxyConfig{
		ListenAddr:             "127.0.0.1:0",
		EnableMITM:             true,
		ConnectTimeout:         30 * time.Second,
		RequestTimeout:         5 * time.Minute,
		ServerReadWriteTimeout: defaultServerReadWriteTimeout,
		Interceptors:           []Interceptor{},
	}
}

type proxyServer struct {
	config *ProxyConfig
	proxy  *goproxy.ProxyHttpServer
	server *http.Server

	listener     net.Listener
	interceptors map[string]Interceptor
	mu           sync.RWMutex
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

	proxy := goproxy.NewProxyHttpServer()
	proxy.Logger = &goproxyLoggerWrapper{}
	proxy.Tr = newUpstreamTransport(config)

	// Set verbose to true for verbose logging.
	// Logging is handled by our own logger which has log level controls.
	proxy.Verbose = true

	// Configure connection timeout for upstream connections during CONNECT requests
	proxy.ConnectDial = func(network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{
			Timeout: config.ConnectTimeout,
		}

		return dialer.Dial(network, addr)
	}

	ps := &proxyServer{
		config:       config,
		proxy:        proxy,
		interceptors: make(map[string]Interceptor),
	}

	for _, interceptor := range config.Interceptors {
		if err := ps.AddInterceptor(interceptor); err != nil {
			return nil, fmt.Errorf("failed to add interceptor %s: %w", interceptor.Name(), err)
		}
	}

	if config.EnableMITM {
		ps.configureMITM()
	}

	ps.registerHandlers()

	return ps, nil
}

func proxyWithLoopbackBypass(req *http.Request) (*url.URL, error) {
	host := req.URL.Hostname()
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return nil, nil
	}

	return http.ProxyFromEnvironment(req)
}

func newUpstreamTransport(config *ProxyConfig) *http.Transport {
	dialer := &net.Dialer{
		Timeout: config.ConnectTimeout,
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
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxConnsPerHost:       100,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   50,
		IdleConnTimeout:       120 * time.Second,
		TLSHandshakeTimeout:   config.ConnectTimeout,
		ResponseHeaderTimeout: config.RequestTimeout,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: false,
		},
	}
}

func (ps *proxyServer) Start() error {
	listener, err := net.Listen("tcp", ps.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to start listener: %w", err)
	}

	ps.listener = listener

	serverTimeout := ps.config.ServerReadWriteTimeout
	if serverTimeout == 0 {
		serverTimeout = defaultServerReadWriteTimeout
	}

	ps.server = &http.Server{
		Handler:      ps.proxy,
		ReadTimeout:  serverTimeout,
		WriteTimeout: serverTimeout,
	}

	log.Debugf("Proxy server listening on %s", ps.Address())

	go func() {
		if err := ps.server.Serve(ps.listener); err != nil && err != http.ErrServerClosed {
			log.Errorf("Proxy server error: %v", err)
		}
	}()

	return nil
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

// normalizeRequestURL fixes malformed URLs produced by goproxy's MITM URL reconstruction.
//
// When a client (e.g., npm) sends absolute-form Request-URIs inside a CONNECT tunnel
// (e.g., "POST http://registry.npmjs.org:443/-/npm/v1/security/advisories/bulk"),
// goproxy's MITM code checks if req.URL starts with "scheme://" and, if not, naively
// prepends "scheme://connectHost" to the full URI. Since the client's URI starts with
// "http://" but the MITM scheme is "https", the check fails and goproxy produces:
//
//	https://registry.npmjs.org:443http://registry.npmjs.org:443/-/npm/v1/security/advisories/bulk
//
// This function detects the embedded absolute URI and extracts it, preserving the
// correct scheme from the MITM connection.
func normalizeRequestURL(req *http.Request) {
	if req == nil || req.URL == nil {
		return
	}

	host := req.URL.Host
	if host == "" {
		return
	}

	// The goproxy bug produces a Host field like "registry.npmjs.org:443http:"
	// where the embedded scheme leaks into the authority. A valid host:port
	// never contains "http:" or "https:", so this check is precise and avoids
	// false positives from query parameters or path segments.
	var embeddedScheme string
	var schemeIdx int
	if idx := strings.Index(host, "http:"); idx > 0 {
		embeddedScheme = "http"
		schemeIdx = idx
	} else if idx := strings.Index(host, "https:"); idx > 0 {
		embeddedScheme = "https"
		schemeIdx = idx
	}

	if embeddedScheme == "" {
		return
	}

	// Extract the real host (everything before the embedded scheme)
	realHost := host[:schemeIdx]

	// Reconstruct the embedded URL from the scheme found in the host
	// plus the path portion that Go's URL parser placed after the authority.
	// The full original URL looks like: scheme://realHost + embeddedScheme://embeddedHost/path
	// Go parsed the authority as "realHost + embeddedScheme:" and the path as
	// "//embeddedHost/path", so we combine them back.
	embeddedURL := embeddedScheme + ":" + req.URL.Path
	if req.URL.RawQuery != "" {
		embeddedURL += "?" + req.URL.RawQuery
	}
	if req.URL.Fragment != "" {
		embeddedURL += "#" + req.URL.Fragment
	}

	parsed, err := url.Parse(embeddedURL)
	if err != nil {
		return
	}

	// If the embedded URL parsed to a valid host, use it. Otherwise fall back
	// to the real host we extracted from the authority.
	if parsed.Host == "" {
		parsed.Host = realHost
	}

	// Preserve the MITM scheme (e.g. https) rather than the client's scheme
	parsed.Scheme = req.URL.Scheme
	req.URL = parsed
}

func (ps *proxyServer) configureMITM() {
	// Configure selective MITM based on interceptors
	ps.proxy.OnRequest().HandleConnect(goproxy.FuncHttpsHandler(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		reqCtx, err := newRequestContextFromURL(host, "CONNECT")
		if err != nil {
			log.Errorf("Failed to parse CONNECT request for %s: %v", host, err)
			return goproxy.OkConnect, host
		}

		ps.mu.RLock()
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
				// Allow non-MITM interceptors (e.g., telemetry) to observe CONNECT traffic.
				if _, err := interceptor.HandleRequest(reqCtx); err != nil {
					log.Errorf("[%s] Interceptor %s error on CONNECT: %v", reqCtx.RequestID, interceptor.Name(), err)
				}
				continue
			}

			shouldMITM = true
			log.Debugf("[%s] Interceptor %s will handle %s", reqCtx.RequestID, interceptor.Name(), host)
		}
		ps.mu.RUnlock()

		if shouldMITM {
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

		// Tunnel without interception
		log.Debugf("[%s] Tunneling %s (no interceptor)", reqCtx.RequestID, host)
		return goproxy.OkConnect, host
	}))
}

func (ps *proxyServer) registerHandlers() {
	ps.proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		// Fix malformed URLs produced by goproxy's MITM URL reconstruction.
		// When a client sends absolute-form Request-URIs (e.g., http://host:port/path)
		// inside a CONNECT tunnel, goproxy naively prepends scheme://connectHost to the
		// full URI, producing malformed URLs like https://host:443http://host:443/path.
		// We detect and fix this before processing.
		normalizeRequestURL(req)

		reqCtx, err := newRequestContext(req)
		if err != nil {
			log.Errorf("Failed to create request context: %v", err)
			return req, nil
		}

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
				if message == "" {
					message = "Blocked by proxy interceptor"
				}

				log.Debugf("[%s] Blocked by %s: %s", reqCtx.RequestID, interceptor.Name(), req.URL.String())
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

				return req, r

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
			resp.Body = io.NopCloser(bytes.NewReader(body))
			resp.ContentLength = int64(len(body))
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
