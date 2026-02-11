package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/proxy/certmanager"
)

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
}

// DefaultProxyConfig returns a configuration with sensible defaults
func DefaultProxyConfig() *ProxyConfig {
	return &ProxyConfig{
		ListenAddr:     "127.0.0.1:0",
		EnableMITM:     true,
		ConnectTimeout: 30 * time.Second,
		RequestTimeout: 5 * time.Minute,
		Interceptors:   []Interceptor{},
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

func (ps *proxyServer) Start() error {
	listener, err := net.Listen("tcp", ps.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to start listener: %w", err)
	}

	ps.listener = listener

	ps.server = &http.Server{
		Handler:      ps.proxy,
		ReadTimeout:  ps.config.RequestTimeout,
		WriteTimeout: ps.config.RequestTimeout,
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
			if interceptor.ShouldIntercept(reqCtx) {

				shouldMITM = true
				log.Debugf("[%s] Interceptor %s will handle %s", reqCtx.RequestID, interceptor.Name(), host)
				break
			}
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
		reqCtx, err := newRequestContext(ctx.Req)
		if err != nil {
			log.Errorf("Failed to create request context: %v", err)
			return resp
		}

		log.Debugf("[%s] Response received for %s", reqCtx.RequestID, ctx.Req.URL.String())

		if resp == nil {
			return resp
		}

		modifier, ok := ctx.UserData.(ResponseModifierFunc)
		if !ok || modifier == nil {
			return resp
		}

		// TODO: Implement response body modification
		// This requires buffering the response body, modifying it, and creating a new response
		// For now, lets skip it

		return resp
	})
}
